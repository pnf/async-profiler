/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <fstream>  // MS: for atomic output file
#include <dlfcn.h> // MS
#include <sys/mman.h> // MS
#include <sys/stat.h>  // MS
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h> // MS
#include <sys/param.h>
#include "profiler.h"
#include <cmath>
#include "perfEvents.h"
#include "ctimer.h"
#include "allocTracer.h"
#include "mallocTracer.h"
#include "lockTracer.h"
#include "wallClock.h"
#include "j9ObjectSampler.h"
#include "j9StackTraces.h"
#include "j9WallClock.h"
#include "instrument.h"
#include "itimer.h"
#include "dwarf.h"
#include "flameGraph.h"
#include "flightRecorder.h"
#include "fdtransferClient.h"
#include "frameName.h"
#include "javaApi.h"
#include "os.h"
#include "safeAccess.h"
#include "stackFrame.h"
#include "stackWalker.h"
#include "symbols.h"
#include "tsc.h"
#include "vmStructs.h"

// MS: thread-local storage for await data.
static pthread_key_t local_await_data_key;
static void __attribute__((constructor)) createAwaitDataKey(void) {
    pthread_key_create(&local_await_data_key, NULL);
}

// The instance is deliberately not deleted, since profiler structures
// can be still accessed concurrently during VM termination
Profiler* const Profiler::_instance = new Profiler();

static SigAction orig_trapHandler = NULL;
static SigAction orig_segvHandler = NULL;

static Engine noop_engine;
static PerfEvents perf_events;
static AllocTracer alloc_tracer;
static MallocTracer malloc_tracer;
static LockTracer lock_tracer;
static ObjectSampler object_sampler;
static J9ObjectSampler j9_object_sampler;
static WallClock wall_clock;
static J9WallClock j9_wall_clock;
static CTimer ctimer;
static ITimer itimer;
static Instrument instrument;

static ProfilingWindow profiling_window;


// The same constants are used in JfrSync
enum EventMask {
    EM_CPU   = 1,
    EM_ALLOC = 2,
    EM_LOCK  = 4,
    EM_WALL  = 8,
    EM_NATIVEMEM = 16,
};


struct MethodSample {
    u64 samples;
    u64 counter;

    void add(u64 add_samples, u64 add_counter) {
        samples += add_samples;
        counter += add_counter;
    }
};

typedef std::pair<std::string, MethodSample> NamedMethodSample;

static bool sortByCounter(const NamedMethodSample& a, const NamedMethodSample& b) {
    return a.second.counter > b.second.counter;
}


static inline int hasNativeStack(EventType event_type) {
    const int events_with_native_stack =
        (1 << PERF_SAMPLE)       |
        (1 << EXECUTION_SAMPLE)  |
        (1 << WALL_CLOCK_SAMPLE) |
        (1 << MALLOC_SAMPLE)     |
        // (1 << ALLOC_SAMPLE)      | // MS
        (1 << ALLOC_OUTSIDE_TLAB) |
        (1 << JEMALLOC_SAMPLE) |
        (1 << JEMALLOC_LIVE)
        ;
    return (1 << event_type) & events_with_native_stack;
}

static inline bool isVTableStub(const char* name) {
    return name[0] && strcmp(name + 1, "table stub") == 0;
}

static inline int makeFrame(ASGCT_CallFrame* frames, jint type, jmethodID id) {
    frames[0].bci = type;
    frames[0].method_id = id;
    return 1;
}

static inline int makeFrame(ASGCT_CallFrame* frames, jint type, uintptr_t id) {
    return makeFrame(frames, type, (jmethodID)id);
}

static inline int makeFrame(ASGCT_CallFrame* frames, jint type, const char* id) {
    return makeFrame(frames, type, (jmethodID)id);
}

// MS: Recursive stack trace building
FrameIterator::FrameIterator(std::vector<CallTraceSample*> &samples, bool savedAwaitStacks) : awaitTraces() {
    if (savedAwaitStacks)
        for(std::vector<CallTraceSample*>::const_iterator it = samples.begin(); it != samples.end(); ++it){
            auto trace = (*it)->acquireTrace();
            if (trace)
                addAwaitTrace(trace);
        }
}

FrameIterator::FrameIterator(std::vector<CallTraceSample> &samples, bool savedAwaitStacks) : awaitTraces() {
    if (savedAwaitStacks)
        for(std::vector<CallTraceSample>::const_iterator it = samples.begin(); it != samples.end(); ++it){
            auto trace = ((CallTraceSample*) &(*it))->acquireTrace();
            if (trace)
                addAwaitTrace(trace);
        }
}

FrameIterator::FrameIterator(std::map<long long unsigned int, CallTraceSample> &samples, bool savedAwaitStacks) : awaitTraces() {
    if(savedAwaitStacks)
        for (std::map<u64, CallTraceSample>::const_iterator it = samples.begin(); it != samples.end(); ++it)
            addAwaitTrace(it->second.trace);
}

void FrameIterator::set(CallTrace* trace_, bool reversed, int ignore_last) {
    traceStack[0] = trace_;
    depth = 0;
    i = reversed ? trace_->num_frames - 1 - ignore_last: 0;
}

int FrameIterator::setAndCount(CallTrace* trace_, bool reversed, int ignore_last) {
    traceStack[0] = trace_;
    int n = i = depth = 0;
    if(!hasAwaits) n = trace_->num_frames;
    else { while(next() != NULL) n++; depth = 0; }
    i = reversed ? trace_->num_frames - 1 - ignore_last: 0;
    return n;
}

#define COMMA ,
static ASGCT_CallFrame MISSING = {BCI_AWAIT_S, LP64_ONLY(0 COMMA) (jmethodID) "[missing]"};

ASGCT_CallFrame* FrameIterator::prev() {
    if(!hasAwaits) return i >= 0 ? traceStack[0]->frames + i-- : NULL;
    if(i >= 0) {
        if (traceStack[depth]->frames[i].bci == BCI_AWAIT_INSERTION) {
            CallTrace *atrace = awaitTraces[traceStack[depth]->frames[i--].method_id];
            if (depth >= MAX_DEPTH - 1) return prev();
            if (atrace == NULL) return &MISSING;
            positionStack[depth] = i;
            i = atrace->num_frames - 1;
            traceStack[++depth] = atrace;
            return prev();
        } else if(traceStack[depth]->frames[i].bci == BCI_AWAIT_MARKER) {
            i--; return prev();
        } else
            return traceStack[depth]->frames + i--;
    } else if(depth > 0) {
      depth--;
      i = positionStack[depth];
      return prev();
    }
    else return NULL;
}

ASGCT_CallFrame *FrameIterator::next() {
    if(!hasAwaits) return i < traceStack[0]->num_frames ? traceStack[0]->frames + i++ : NULL;
    if(i < traceStack[depth]->num_frames) {
      if(traceStack[depth]->frames[i].bci == BCI_AWAIT_INSERTION) {
        CallTrace *atrace = awaitTraces[traceStack[depth]->frames[i++].method_id];
        if (depth >= MAX_DEPTH - 1) return next();
        if (atrace == NULL) return &MISSING;
        positionStack[depth] = i;
        i = 0;
        traceStack[++depth] = atrace;
        return next();
      } else if(traceStack[depth]->frames[i].bci == BCI_AWAIT_MARKER) {
          i++; return next();
      } else
         return traceStack[depth]->frames + i++;
    }
    else if(depth > 0) {
      depth--;
      i = positionStack[depth];
      return next();
    }
    else return NULL;
}

// MS: shared memory context
volatile static long *externalContext = NULL;
void Profiler::setExternalContext(long ctx, const char *shmpath) {
    if (shmpath) {
        if (ctx) {
            // Setting a context value for the child process to read.  There will be a different shm path for each child.
            std::string sp(shmpath);
            MutexLocker locker(_contexts_lock);
            // Get pointer to shared memory
            long *childContext = _contexts[sp];
            if (!childContext) {
                // Not mapped yet.
                int fd = shm_open(shmpath, O_CREAT | O_RDWR, 0600);
                if (fd < 0) {
                    auto err = errno;
                    Log::error("shm_open failed for %s %d", shmpath, err);
                    return;
                }
                // can return non-zero even when it succeeded;  if a real error, then mmap will fail
                ftruncate(fd, sizeof(long));
                childContext = (long *) mmap(NULL, sizeof(long), PROT_READ | PROT_WRITE,
                                             MAP_SHARED, fd, 0);  // returns -1 on failure
                if (childContext && (long) childContext != -1)
                    _contexts[sp] = childContext;
                else {
                    childContext = NULL;
                    auto err = errno;
                    Log::error("mmap failed for %s %d", shmpath, err);
                }
                close(fd);
            }
            // Set the context.
            if (childContext && ((long) childContext) != -1)
                *childContext = ctx;
        } else {
            // Get a pointer to the shared memory that will be written by our one and only parent.
            int fd = shm_open(shmpath, O_RDONLY, 0400);
            if (fd < 0) {
                auto err = errno;
                Log::error("shm_open failed for %s %d", shmpath, err);
                return;
            }
            externalContext = (long*) mmap(NULL, sizeof(externalContext), PROT_READ,
                 MAP_SHARED, fd, 0);
            if (externalContext && ((long) externalContext) != -1)
                Log::info("Shared context set %d %p %ld", fd, externalContext, externalContext ? *externalContext : 0);
            else {
                auto err = errno;
                Log::error("mmap failed for %s %d", shmpath, err);
                externalContext = NULL;
            }
            close(fd);
        }
    }
}

// MS statics
static volatile bool awaitEnabled = false;
static volatile jmethodID runContinuationId = NULL; // VirtualThread.runContinuation method id
static volatile u64 mount_ids = 1;

AwaitData* Profiler::virtualMount(JNIEnv* env, jthread vthread) {
    jlong vtid = VMThread::javaThreadId(env, vthread);
    auto vad = getVTAwaitData(vtid, AWAIT_MAP_ACTION_FIND_CREATE);
    if (!vad) return nullptr;
    // Make sure our reference to the thread is still correct
    jthread vtref = vad->weak_thread_ref;
    if (vtref &&
        !env->IsSameObject(vtref, vthread)) {
        env->DeleteWeakGlobalRef(vtref);
        vtref = nullptr;
    }
    if (!vtref)
        vad->weak_thread_ref = env->NewWeakGlobalRef(vthread);
    // Snap the stack, if this thread was transitively sampled
    recordThread(env, vad, 0, "from_mount", false);
    atomicInc(stats._vtMounts);
    // And mark the thread as unsampled
    vad->flags &= ~(AD_STACK_SAVED + AD_STACK_SAMPLED);
    __atomic_store_n(&vad->java_stack_hash, 0, __ATOMIC_RELEASE);
    // Return the await data address to be stored platform thread-locally
    return vad;
}

// MS virtual mount/unmount callbacks
static void JNICALL virtualMountCallback(jvmtiEnv *jvmti, ...) {
    // Get OS thread-local region in which we'll stash the currently mounted virtual thread
    AwaitData *tlad = Profiler::instance()->threadLocalAwaitData(true);
    if (!tlad) return;
    assert(!tlad->mounted_await_data);  // we should not currently be mounted
    va_list ap;
    va_start(ap, jvmti);
    JNIEnv *env = va_arg(ap, JNIEnv*);
    jthread vthread = va_arg(ap, jthread);
    JavaAPI::callThreadStringCallback(env, vthread, "mount");
    // Attach the virtual thread await data to the physical thread
    tlad->mounted_await_data = Profiler::instance()->virtualMount(env, vthread);
}

static void JNICALL virtualUnMountCallback(jvmtiEnv *jvmti, ...) {
    AwaitData *tlad = Profiler::instance()->threadLocalAwaitData(true);
    if (!tlad) return;
    tlad->mounted_await_data = nullptr;
    va_list ap;
    va_start(ap, jvmti);
    JNIEnv *env = va_arg(ap, JNIEnv*);
    jthread thread = va_arg(ap, jthread);
    if (thread)
        JavaAPI::callThreadStringCallback(env, thread, "unmount");
}

// Gets pointer to the OS-thread-local await data block, calloc-ing it if necessary.
AwaitData* Profiler::threadLocalAwaitData(bool may_init) {
    AwaitData *ad = (AwaitData *) pthread_getspecific(local_await_data_key);
    if (ad) return ad;
    else if (!may_init) return NULL;
    else {
        lockAll();
        ad = (AwaitData *) calloc(1, sizeof(AwaitData));
        pthread_setspecific(local_await_data_key, ad);
        unlockAll();
        return ad;
    }
}

// MS: get pointer to an await data block, which _may_ be the OS-thread-local block, unless a virtual thread is mounted,
// in which case it will be that of the virtual thread.
AwaitData *Profiler::awaitData(bool may_init, bool mayBeVirtual) {
    if (!awaitEnabled) return NULL;
    AwaitData *tlad = threadLocalAwaitData(may_init);
    if (!tlad) return NULL;
    if (_vtSlots && mayBeVirtual) {
        return tlad->mounted_await_data;
    }
    return tlad;
}

jthread Profiler::cleanupAwaitData(AwaitData *ad) {
        // we no longer occupy this AwaitData slot; someone else might want it, so don't deallocate
    auto thread_ref = ad->weak_thread_ref;
    ad->weak_thread_ref = nullptr;
    __atomic_store_n(&ad->thread_id, 0, __ATOMIC_RELEASE);
    atomicInc(stats._vtMapEntries, -1);
    return thread_ref;
}


AwaitData *Profiler::getVTAwaitData(long vtid, AwaitMapAction action, JNIEnv* jni) {
    if (!_vtSlots || vtid == 0) return nullptr;
    // Assumption is that thread ids are allocated sequentially and end relatively quickly, so the live
    // population is small compared to the table size and clustered in a portion of the table.
    AwaitData* ad = _vtAwaitData + ((vtid * _vtBucketSize) & (_vtSlots - 1));
    SpinLockScope lock(ad->lock);
    if (lock.contended()) atomicInc(stats._vtMapContended);

    AwaitData* adEmpty = nullptr;
    int i;
    // look for entry in consecutive slots
    int depth = __atomic_load_n(&ad->depth, __ATOMIC_ACQUIRE);
    for (i=0; i <= depth; i++) {
        const long id = __atomic_load_n(&ad[i].thread_id,__ATOMIC_ACQUIRE);
        if (id == vtid) {
            atomicInc(stats._vtMapHits);
            if (action == AWAIT_MAP_ACTION_REMOVE) {
                auto tr = cleanupAwaitData(ad+i);
                if (tr) {
                    lock.release();
                    jni->DeleteWeakGlobalRef(tr);
                }
                return nullptr;
            }
            return ad + i;
        }
        if (id == 0 && !adEmpty)
            adEmpty = ad + i;  // deletion occurred here
    }

    if (action != AWAIT_MAP_ACTION_REMOVE) {
        if (adEmpty) {
            __atomic_store_n(&adEmpty->thread_id, vtid, __ATOMIC_RELEASE);
            atomicInc(stats._vtMapEntries);
            atomicInc(stats._vtMapInsertions);
            return adEmpty;
        }
        // try to put entry in next consecutive slot
        if (i < _vtBucketSize) {
            __atomic_store_n(&ad->depth , i,__ATOMIC_RELEASE);
            __atomic_store_n(&ad[i].thread_id, vtid, __ATOMIC_RELEASE);
            atomicInc(stats._vtMapEntries);
            atomicInc(stats._vtMapDepthInsertions);
            return ad + i;
        }
    }

    // checked all slots; traverse linked list
    ad =  ad + _vtBucketSize - 1;
    AwaitData* adl;
    while ((adl = __atomic_load_n(&ad->next_await_data, __ATOMIC_ACQUIRE))) {
        long id = __atomic_load_n(&adl->thread_id, __ATOMIC_ACQUIRE);
        if (id == vtid) {
            if (action == AWAIT_MAP_ACTION_REMOVE) {
                auto tr = cleanupAwaitData(adl);
                if (tr) {
                    lock.release();
                    jni->DeleteWeakGlobalRef(tr);
                }
                return nullptr;
            }
            return adl;
        }
        if (id == 0 && !adEmpty)
            adEmpty = adl; // deletion occurred here
        ad = adl;
    }

    if (action == AWAIT_MAP_ACTION_REMOVE)
        return nullptr;

    // If we found a deletion, fill it
    if (adEmpty) {
        atomicInc(stats._vtMapEntries);
        atomicInc(stats._vtMapInsertions);
        __atomic_store_n(&adEmpty->thread_id, vtid, __ATOMIC_RELEASE);
        return adEmpty;
    }

    if (action == AWAIT_MAP_ACTION_FIND_OR_CLAIM) {
        atomicInc(stats._vtMapMisses);
        return nullptr;
    }

    atomicInc(stats._vtMapLinks);
    atomicInc(stats._vtMapEntries);

    adl = (AwaitData *) calloc(1, sizeof(AwaitData));
    __atomic_store_n(&ad->next_await_data, adl,__ATOMIC_RELEASE);
    __atomic_store_n(&adl->thread_id,vtid, __ATOMIC_RELEASE);
    return adl;
}

// MS: Set up static data for managing await stacks.  If slots>0, then also initialize virtual thread-local storage.nitialize non-TL await data.
int Profiler::initAwaitData(int slots) {
    MutexLocker ml(_state_lock);
    lockAll();
    awaitEnabled = true;
    if (!runContinuationId && slots) {

        if (_dq == nullptr) {
            const size_t BLOCK_SIZE = moodycamel::ConcurrentQueueDefaultTraits::BLOCK_SIZE;
            const u32 length = 50;
            // Computing the "size" to give us an effective queue length is a bit complicatedd;
            // see https://github.com/cameron314/concurrentqueue
            size_t SZ = (std::ceil(length / BLOCK_SIZE) + 1) * CONCURRENCY_LEVEL * BLOCK_SIZE;
            _dq = new moodycamel::BlockingConcurrentQueue<Deferred>(SZ);
            _ct = new moodycamel::ConsumerToken(*_dq);
            // Pre-allocate the producer tokens
            for (int i=0; i<CONCURRENCY_LEVEL; i++)
                _pts[i] = new moodycamel::ProducerToken(*_dq);
        }

        jvmtiEnv *jvmti = VM::jvmti();
        JNIEnv *env = VM::jni();
        jclass vtClass = env->FindClass("java/lang/VirtualThread");
        runContinuationId = env->GetMethodID(vtClass, "runContinuation", "()V");
        // Set mount/unmount callbacks
        // Find the VT mount/unmount callbacks and activate them.
        jint nExtensions;
        jvmtiExtensionEventInfo *extensions;
        jvmti->GetExtensionEvents(&nExtensions, &extensions);
        int idMount = 0, idUnmount = 0;
        for (int i = 0; i < nExtensions; i++) {
            auto e = extensions[i];
            if (strstr(e.id, "VirtualThreadMount"))
                idMount = e.extension_event_index;
            else if (strstr(e.id, "VirtualThreadUnmount"))
                idUnmount = e.extension_event_index;
        }
        if (idMount && idUnmount) {
            jvmti->SetExtensionEventCallback(idMount, virtualMountCallback);
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, (jvmtiEvent) idMount, NULL);
            jvmti->SetExtensionEventCallback(idUnmount, virtualUnMountCallback);
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, (jvmtiEvent) idUnmount, NULL);
            Log::info("Set virtual thread mount (%d), unmount (%d) events callbacks", idMount, idUnmount);
        } else {
            Log::error("Unable to find virtual mount events");
        }
    }
    // Allocate per-VT storage
    if (_vtAwaitData) {
        free((void*) _vtAwaitData);
    }
    if (slots > 0) {
        int s = 1;
        while (s < slots) s <<= 1;
        _vtSlots = s;
        _vtAwaitData = (AwaitData *) calloc(s, sizeof(AwaitData));
        _vtBucketSize = 4;
    }
    else _vtSlots = 0;

    unlockAll();
    return MAX_AWAIT_STACKS;
}

long Profiler::saveAwaitFrames(AwaitFrameType ft, long *elems, int n) {
    if(n == 0) return 0;
    int tid = OS::threadId();
    u32 lock_index = tryLock();
    if (lock_index > CONCURRENCY_LEVEL) return 0;
    ASGCT_CallFrame *frames = _calltrace_buffer[lock_index]->_asgct_frames;
    if (frames == NULL) {
        _locks[lock_index].unlock();
        return 0;
    }
    if(n > _max_stack_depth)
        n = _max_stack_depth;
    switch(ft) {
        case AW_METHOD:  // frames will be jmethodIDs
            for(int i=1; i<n; i++) {
                frames[i].bci = FrameType::encode(FRAME_AWAIT_J, frames[i].bci);
                frames[i].method_id = (jmethodID) elems[i];
            }
            break;
        case AW_STRING:  // frames are just strings
            for(int i=1; i<n; i++) {
                frames[i].bci = BCI_AWAIT_S;
                frames[i].method_id = (jmethodID) elems[i];
            }
            break;
        default:
            _locks[lock_index].unlock();
            return -1;
    }
    _savedAwaitStacks = true;
    frames[0].method_id = (jmethodID) elems[0];
    frames[0].bci = BCI_AWAIT_MARKER;
    u32 ret = _call_trace_storage->put(n, frames, 1, nullptr);
    _locks[lock_index].unlock();
    return ret;
}

// Avoid syscall when possible
static inline int fastThreadId() {
    VMThread* vm_thread;
    if (VMStructs::hasNativeThreadId() && (vm_thread = VMThread::current()) != NULL) {
        int thread_id = vm_thread->osThreadId();
        if (thread_id > 0) {
            return thread_id;
        }
    }
    return OS::threadId();
}


void Profiler::addJavaMethod(const void* address, int length, jmethodID method) {
    CodeHeap::updateBounds(address, (const char*)address + length);
}

void Profiler::addRuntimeStub(const void* address, int length, const char* name) {
    _stubs_lock.lock();
    _runtime_stubs.add(address, length, name, true);
    _stubs_lock.unlock();

    if (strcmp(name, "call_stub") == 0) {
        _call_stub_begin = address;
        _call_stub_end = (const char*)address + length;
    }

    CodeHeap::updateBounds(address, (const char*)address + length);
}

void Profiler::onThreadStart(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    if (_thread_filter.enabled()) {
        _thread_filter.remove(OS::threadId());
    }
    updateThreadName(jvmti, jni, thread);
}

void Profiler::onVirtualThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    if (_vtSlots) {
        atomicInc(stats._vtEnds);
        jlong vtid = VMThread::javaThreadId(jni, thread);
        getVTAwaitData(vtid, AWAIT_MAP_ACTION_REMOVE, jni);
    }
}

void Profiler::onThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    if (_thread_filter.enabled()) {
        _thread_filter.remove(OS::threadId());
    }
    updateThreadName(jvmti, jni, thread);
}

void Profiler::onGarbageCollectionFinish() {
    // Called during GC pause, do not use JNI
    atomicInc(_gc_id);
}

const char* Profiler::asgctError(int code) {
    switch (code) {
        case ticks_no_Java_frame:
        case ticks_unknown_not_Java:
            // Not in Java context at all; this is not an error
            return NULL;
        case ticks_thread_exit:
            // The last Java frame has been popped off, only native frames left
            return NULL;
        case ticks_GC_active:
            return "GC_active";
        case ticks_unknown_Java:
            return "unknown_Java";
        case ticks_not_walkable_Java:
            return "not_walkable_Java";
        case ticks_not_walkable_not_Java:
            return "not_walkable_not_Java";
        case ticks_deopt:
            return "deoptimization";
        case ticks_safepoint:
            return "safepoint";
        case ticks_skipped:
            return "skipped";
        case java_skipped:  // MS
            return "java_skipped";
        case ticks_unknown_state:
            // Zing sometimes returns it
            return "unknown_state";
        default:
            // Should not happen
            return "unexpected_state";
    }
}

inline u32 Profiler::getLockIndex(int tid) {
    u32 lock_index = tid;
    lock_index ^= lock_index >> 8;
    lock_index ^= lock_index >> 4;
    return lock_index % CONCURRENCY_LEVEL;
}

void Profiler::updateSymbols(bool kernel_symbols) {
    Symbols::parseLibraries(&_native_libs, kernel_symbols);
}

void Profiler::mangle(const char* name, char* buf, size_t size) {
    char* buf_end = buf + size;
    strcpy(buf, "_ZN");
    buf += 3;

    const char* c;
    while ((c = strstr(name, "::")) != NULL && buf + (c - name) + 4 < buf_end) {
        buf += snprintf(buf, buf_end - buf, "%d", (int)(c - name));
        memcpy(buf, name, c - name);
        buf += c - name;
        name = c + 2;
    }

    if (buf < buf_end) {
        snprintf(buf, buf_end - buf, "%d%sE*", (int)strlen(name), name);
    }
    buf_end[-1] = 0;
}

const void* Profiler::resolveSymbol(const char* name) {
    char mangled_name[256];
    if (strstr(name, "::") != NULL) {
        mangle(name, mangled_name, sizeof(mangled_name));
        name = mangled_name;
    }

    size_t len = strlen(name);
    int native_lib_count = _native_libs.count();
    if (len > 0 && name[len - 1] == '*') {
        for (int i = 0; i < native_lib_count; i++) {
            const void* address = _native_libs[i]->findSymbolByPrefix(name, len - 1);
            if (address != NULL) {
                return address;
            }
        }
    } else {
        for (int i = 0; i < native_lib_count; i++) {
            const void* address = _native_libs[i]->findSymbol(name);
            if (address != NULL) {
                return address;
            }
        }
    }

    return NULL;
}

// For BCI_NATIVE_FRAME, library index is encoded ahead of the symbol name
const char* Profiler::getLibraryName(const char* native_symbol) {
    short lib_index = NativeFunc::libIndex(native_symbol);
    if (lib_index >= 0 && lib_index < _native_libs.count()) {
        const char* s = _native_libs[lib_index]->name();
        if (s != NULL) {
            const char* p = strrchr(s, '/');
            return p != NULL ? p + 1 : s;
        }
    }
    return NULL;
}

CodeCache* Profiler::findJvmLibrary(const char* lib_name) {
    return VM::isOpenJ9() ? findLibraryByName(lib_name) : VMStructs::libjvm();
}

CodeCache* Profiler::findLibraryByName(const char* lib_name) {
    const size_t lib_name_len = strlen(lib_name);
    const int native_lib_count = _native_libs.count();
    for (int i = 0; i < native_lib_count; i++) {
        const char* s = _native_libs[i]->name();
        if (s != NULL) {
            const char* p = strrchr(s, '/');
            if (p != NULL && strncmp(p + 1, lib_name, lib_name_len) == 0) {
                return _native_libs[i];
            }
        }
    }
    return NULL;
}

CodeCache* Profiler::findLibraryByAddress(const void* address) {
    const int native_lib_count = _native_libs.count();
    for (int i = 0; i < native_lib_count; i++) {
        if (_native_libs[i]->contains(address)) {
            return _native_libs[i];
        }
    }
    return NULL;
}

const char* Profiler::findNativeMethod(const void* address) {
    CodeCache* lib = findLibraryByAddress(address);
    return lib == NULL ? NULL : lib->binarySearch(address);
}

CodeBlob* Profiler::findRuntimeStub(const void* address) {
    return _runtime_stubs.findBlobByAddress(address);
}

bool Profiler::isAddressInCode(const void* pc) {
    if (CodeHeap::contains(pc)) {
        return CodeHeap::findNMethod(pc) != NULL && !(pc >= _call_stub_begin && pc < _call_stub_end);
    } else {
        return findLibraryByAddress(pc) != NULL;
    }
}

jmethodID Profiler::getCurrentCompileTask() {
    VMThread* vm_thread = VMThread::current();
    if (vm_thread != NULL) {
        VMMethod* method = vm_thread->compiledMethod();
        if (method != NULL) {
            return method->id();
        }
    }
    return NULL;
}

int Profiler::getNativeTrace(void* ucontext, ASGCT_CallFrame* frames, EventType event_type, int tid, StackContext* java_ctx,
                             const char** unsafe) { // MS
    const void* callchain[MAX_NATIVE_FRAMES];
    int native_frames;

    // Use PerfEvents stack walker for execution samples, or basic stack walker for other events
    if (event_type == PERF_SAMPLE) {
        native_frames = PerfEvents::walk(tid, ucontext, callchain, MAX_NATIVE_FRAMES, java_ctx);
    } else if (_cstack == CSTACK_DWARF || _cstack == CSTACK_DWARF_VM) {
        native_frames = StackWalker::walkDwarf(ucontext, callchain, MAX_NATIVE_FRAMES, java_ctx);
    } else if (_cstack >= CSTACK_VM) {
        return 0;
    }
    else {
        native_frames = StackWalker::walkFP(ucontext, callchain, MAX_NATIVE_FRAMES, java_ctx);
    }

    return convertNativeTrace(native_frames, callchain, frames, event_type,
                              unsafe); // MS
}

int Profiler::convertNativeTrace(int native_frames, const void** callchain, ASGCT_CallFrame* frames, EventType event_type,
                                 const char** unsafe) { // MS
    int depth = 0;
    jmethodID prev_method = NULL;

    for (int i = 0; i < native_frames; i++) {
        const char* current_method_name = findNativeMethod(callchain[i]);
        char mark;
        if (current_method_name != NULL && (mark = NativeFunc::mark(current_method_name)) != 0) {
            if (mark == MARK_VM_RUNTIME && event_type >= ALLOC_SAMPLE) {
                // Skip all internal frames above VM runtime entry for allocation samples
                depth = 0;
                continue;
            } else if (mark == MARK_ASYNC_PROFILER && event_type == MALLOC_SAMPLE) {
                // Skip all internal frames above the *_hook functions. Include the hook function itself.
                depth = 0;
            } else if (unsafe != NULL && mark == MARK_UNSAFE) {  // MS
                *unsafe = current_method_name;
            } else if (mark == MARK_INTERPRETER) {
                // This is C++ interpreter frame, this and later frames should be reported
                // as Java frames returned by AGCT. Terminate the scan here.
                return depth;
            } else if (mark == MARK_COMPILER_ENTRY && _features.comp_task) {
                // Insert current compile task as a pseudo Java frame
                jmethodID compile_task = getCurrentCompileTask();
                if (compile_task != NULL) {
                    frames[depth].bci = 0;
                    frames[depth].method_id = compile_task;
                    depth++;
                }
            }
        }

        jmethodID current_method = (jmethodID)current_method_name;
        if (current_method == prev_method && _cstack == CSTACK_LBR) {
            // Skip duplicates in LBR stack, where branch_stack[N].from == branch_stack[N+1].to
            prev_method = NULL;
        } else {
            frames[depth].bci = BCI_NATIVE_FRAME;
            frames[depth].method_id = prev_method = current_method;
            depth++;
        }
    }

    return depth;
}

int Profiler::getJavaTraceAsync(void* ucontext, ASGCT_CallFrame* frames, int max_depth, StackContext* java_ctx) {
    // Workaround for JDK-8132510: it's not safe to call GetEnv() inside a signal handler
    // since JDK 9, so we do it only for threads already registered in ThreadLocalStorage
    VMThread* vm_thread = VMThread::current();
    if (vm_thread == NULL) {
        return 0;
    }

    JNIEnv* jni = VM::jni();
    if (jni == NULL) {
        // Not a Java thread
        return 0;
    }

    StackFrame frame(ucontext);
    uintptr_t saved_pc, saved_sp, saved_fp;
    if (ucontext != NULL) {
        saved_pc = frame.pc();
        saved_sp = frame.sp();
        saved_fp = frame.fp();
    }

    if (_features.unwind_native && vm_thread->inJava()) {
        if (saved_pc >= (uintptr_t)_call_stub_begin && saved_pc < (uintptr_t)_call_stub_end) {
            // call_stub is unsafe to walk
            frames->bci = BCI_ERROR;
            frames->method_id = (jmethodID)"call_stub";
            return 1;
        }
        if (DWARF_SUPPORTED && java_ctx->sp != 0) {
            // If a thread is in Java state, unwind manually to the last known Java frame,
            // since JVM does not always correctly unwind native frames
            frame.restore((uintptr_t)java_ctx->pc, java_ctx->sp, java_ctx->fp);
        }
    }

    JitWriteProtection jit(false);
    ASGCT_CallTrace trace = {jni, 0, frames};
    VM::_asyncGetCallTrace(&trace, max_depth, ucontext);

    if (trace.num_frames > 0) {
        frame.restore(saved_pc, saved_sp, saved_fp);
        return trace.num_frames;
    }

    if ((trace.num_frames == ticks_unknown_Java || trace.num_frames == ticks_not_walkable_Java) && _features.unknown_java && ucontext != NULL) {
        CodeBlob* stub = NULL;
        _stubs_lock.lockShared();
        if (_runtime_stubs.contains((const void*)frame.pc())) {
            stub = findRuntimeStub((const void*)frame.pc());
        }
        _stubs_lock.unlockShared();

        if (stub != NULL) {
            if (_cstack != CSTACK_NO) {
                if (_features.vtable_target && isVTableStub(stub->_name)) {
                    uintptr_t receiver = frame.jarg0();
                    if (receiver != 0) {
                        VMSymbol* symbol = VMKlass::fromOop(receiver)->name();
                        u32 class_id = classMap()->lookup(symbol->body(), symbol->length());
                        max_depth -= makeFrame(trace.frames++, BCI_ALLOC, class_id);
                    }
                }
                max_depth -= makeFrame(trace.frames++, BCI_NATIVE_FRAME, stub->_name);
            }
            if (_features.unwind_stub && frame.unwindStub((instruction_t*)stub->_start, stub->_name)
                    && isAddressInCode((const void*)frame.pc())) {
                java_ctx->pc = (const void*)frame.pc();
                VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
            }
        } else if (VMStructs::hasMethodStructs()) {
            NMethod* nmethod = CodeHeap::findNMethod((const void*)frame.pc());
            if (nmethod != NULL && nmethod->isNMethod() && nmethod->isAlive()) {
                VMMethod* method = nmethod->method();
                if (method != NULL) {
                    jmethodID method_id = method->id();
                    if (method_id != NULL) {
                        max_depth -= makeFrame(trace.frames++, 0, method_id);
                    }
                    if (_features.unwind_comp && frame.unwindCompiled(nmethod)
                            && isAddressInCode((const void*)frame.pc())) {
                        VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
                    }
                    if (_features.probe_sp && trace.num_frames < 0) {
                        if (method_id != NULL) {
                            trace.frames--;
                        }
                        for (int i = 0; trace.num_frames < 0 && i < PROBE_SP_LIMIT; i++) {
                            frame.sp() += sizeof(void*);
                            VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
                        }
                    }
                }
            } else if (nmethod != NULL) {
                if (_cstack != CSTACK_NO) {
                    max_depth -= makeFrame(trace.frames++, BCI_NATIVE_FRAME, nmethod->name());
                }
                if (_features.unwind_stub && frame.unwindStub(NULL, nmethod->name())
                        && isAddressInCode((const void*)frame.pc())) {
                    VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
                }
            }
        }
    } else if (trace.num_frames == ticks_unknown_not_Java && _features.java_anchor) {
        JavaFrameAnchor* anchor = vm_thread->anchor();
        uintptr_t sp = anchor->lastJavaSP();
        const void* pc = anchor->lastJavaPC();
        if (sp != 0 && pc == NULL) {
            // We have the last Java frame anchor, but it is not marked as walkable.
            // Make it walkable here
            pc = ((const void**)sp)[-1];
            anchor->setLastJavaPC(pc);

            NMethod* m = CodeHeap::findNMethod(pc);
            if (m != NULL) {
                // AGCT fails if the last Java frame is a Runtime Stub with an invalid _frame_complete_offset.
                // In this case we patch _frame_complete_offset manually
                if (!m->isNMethod() && m->frameSize() > 0 && m->frameCompleteOffset() == -1) {
                    m->setFrameCompleteOffset(0);
                }
                VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
            } else if (findLibraryByAddress(pc) != NULL) {
                VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
            }

            anchor->setLastJavaPC(NULL);
        }
    } else if (trace.num_frames == ticks_not_walkable_not_Java && _features.java_anchor) {
        JavaFrameAnchor* anchor = vm_thread->anchor();
        uintptr_t sp = anchor->lastJavaSP();
        const void* pc = anchor->lastJavaPC();
        if (sp != 0 && pc != NULL) {
            // Similar to the above: last Java frame is set,
            // but points to a Runtime Stub with an invalid _frame_complete_offset
            NMethod* m = CodeHeap::findNMethod(pc);
            if (m != NULL && !m->isNMethod() && m->frameSize() > 0 && m->frameCompleteOffset() == -1) {
                m->setFrameCompleteOffset(0);
                VM::_asyncGetCallTrace(&trace, max_depth, ucontext);
            }
        }
    } else if (trace.num_frames == ticks_GC_active && _features.gc_traces) {
        if (vm_thread->anchor()->lastJavaSP() == 0) {
            // Do not add 'GC_active' for threads with no Java frames, e.g. Compiler threads
            frame.restore(saved_pc, saved_sp, saved_fp);
            return 0;
        }
    }

    frame.restore(saved_pc, saved_sp, saved_fp);

    if (trace.num_frames > 0) {
        return trace.num_frames + (trace.frames - frames);
    }

    const char* err_string = asgctError(trace.num_frames);
    if (err_string == NULL) {
        // No Java stack, because thread is not in Java context
        return 0;
    }

    atomicInc(_failures[-trace.num_frames]);
    trace.frames->bci = BCI_ERROR;
    trace.frames->method_id = (jmethodID)err_string;
    return trace.frames - frames + 1;
}

int Profiler::getJavaTraceJvmti(jthread othread, // MS
                                jvmtiFrameInfo* jvmti_frames, ASGCT_CallFrame* frames, int start_depth, int max_depth) {
    int num_frames = 0;
    if (VM::jvmti()->GetStackTrace(othread, start_depth, max_depth, jvmti_frames, &num_frames) == 0 && num_frames > 0) {
        // Convert to AsyncGetCallTrace format.
        // Note: jvmti_frames and frames may overlap.
        for (int i = 0; i < num_frames; i++) {
            jint bci = jvmti_frames[i].location;
            frames[i].method_id = jvmti_frames[i].method;
            frames[i].bci = bci;
            LP64_ONLY(frames[i].padding = 0;)
        }
    }
    return num_frames;
}

void Profiler::fillFrameTypes(ASGCT_CallFrame* frames, int num_frames, NMethod* nmethod) {
    if (nmethod->isNMethod() && nmethod->isAlive()) {
        VMMethod* method = nmethod->method();
        if (method == NULL) {
            return;
        }

        jmethodID current_method_id = method->id();
        if (current_method_id == NULL) {
            return;
        }

        // If the top frame is a runtime stub, skip it
        if (num_frames > 0 && frames[0].bci == BCI_NATIVE_FRAME) {
            frames++;
            num_frames--;
        }

        // Mark current_method as COMPILED and frames above current_method as INLINED
        for (int i = 0; i < num_frames; i++) {
            if (frames[i].method_id == NULL || frames[i].bci <= BCI_NATIVE_FRAME) {
                break;
            }
            if (frames[i].method_id == current_method_id) {
                int level = nmethod->level();
                frames[i].bci = FrameType::encode(level >= 1 && level <= 3 ? FRAME_C1_COMPILED : FRAME_JIT_COMPILED, frames[i].bci);
                for (int j = 0; j < i; j++) {
                    frames[j].bci = FrameType::encode(FRAME_INLINED, frames[j].bci);
                }
                break;
            }
        }
    } else if (nmethod->isInterpreter()) {
        // Mark the first Java frame as INTERPRETED
        for (int i = 0; i < num_frames; i++) {
            if (frames[i].bci > BCI_NATIVE_FRAME) {
                frames[i].bci = FrameType::encode(FRAME_INTERPRETED, frames[i].bci);
                break;
            }
        }
    }
}

// MS: Record a custom event from arbitrary C code
extern "C"
u64 async_profiler_record_custom(int offset, double value, u64 counter) {
    return Profiler::instance()->recordCustom(offset, value, NULL, counter);
}

// MS
static const char** customEventNames = new const char*[100];
void Profiler::addCustomEventType(int offset, const char *name) {
    MutexLocker ml(_state_lock);
    customEventNames[offset] = name;
}

// MS
u64 Profiler::recordCustom(int offset, double value, const char* info, u64 counter) {
    {
        MutexLocker ml(_state_lock);
        if (_state != RUNNING) return 0;
    }
    CustomEvent e;
    e.offset = offset;
    e.value = value;
    e.info = info ? info : customEventNames[offset];
    return recordSample(NULL, counter, CUSTOM, &e);
}

// MS: Abort a sample, unlocking if necessary and recording failure.
int Profiler::bail(int tid, EventType event_type, int lock_index) {
    atomicInc(_failures[-ticks_skipped]);

    if (event_type == PERF_SAMPLE) {
        // Need to reset PerfEvents ring buffer, even though we discard the collected trace
        PerfEvents::resetBuffer(tid);
    }

    if (lock_index >= 0)
        _locks[lock_index].unlock();

    return 0;
}

// MS: Run in another thread at a safepoint to record full stacks
// If this method is never run, we will not handle virtual thread continuations specially
void Profiler::processDeferred(JNIEnv *env, int n, long ms) {
    if (!_dq) return;

    static Mutex singleThreaded;
    static Deferred d;

    MutexLocker ml(singleThreaded);

    _recording_deferred = true;
    // Pull deferred stacks off queue and pass to recordSampled to capture full java stack
    while (n-- && _dq->wait_dequeue_timed(*_ct, d, std::chrono::milliseconds(ms))) {
        MutexLocker ml(_state_lock);
        if (_state != RUNNING) continue;
        if (d.event_type == PURE_DEFERRAL)
            d.registration.run(0, 0);
        else {
            // at this point, the field is a weak ref, copied from await data; the local ref will be zero if
            // the thread was collected, and if not, it will prevent collection
            jthread thread = env->NewLocalRef(d.sampled_thread_ref);
            JavaAPI::callThreadStringCallback(env, thread, "deferred");
            d.sampled_thread_ref = thread;
            d.jniEnv = env;
            u64 tag = 0; // necessary
            recordSample(nullptr, d.counter, d.event_type, &d.event, d.needsTag ? &tag : nullptr, &d);
            if (thread)
                VM::jni()->DeleteLocalRef(thread);
        }
    }
}
static const u64 DEFERRED_POS_MASK = (1 << 10) - 1;
static const u64 LONG_PHI = 0x9E3779B97F4A7C15L;
volatile static u64 deferral_epoch = 1;
static u16 mix(jmethodID id) {
    // Mix in deferral epoch, to randomize collisions
    u64 h = ((u64) id + deferral_epoch) * LONG_PHI;
    h ^= h >> 32;
    return (u16) (h & DEFERRED_POS_MASK);
}

// Enqueue a registered closure for deterministic execution on the deferral queue, if one exists.
// Used for a deallocation whose corresponding allocation might have been deferred, to ensure that
// they're processed in the right order.
void Profiler::enqueueDeferred(Registration &registration) {
    AwaitData *tlad;
    if (!_recording_deferred || ((tlad = threadLocalAwaitData(false)) == nullptr))
        return registration.run(0, 0);
    AwaitData *pad = tlad->mounted_await_data ? tlad->mounted_await_data->parentAwaitData() : nullptr;
    if (pad) pad->sample();
    Deferred d = {};
    d.registration = registration;
    d.event_type = PURE_DEFERRAL;
    u32 lock_index = tryLock();
    if (lock_index > CONCURRENCY_LEVEL)
        return;

    if (_dq->try_enqueue(*_pts[lock_index], d)) atomicInc(stats._enqueued);
    else atomicInc(stats._enqueueFail);
    _locks[lock_index].unlock();
}

// Called from recordSample if we're on a virtual thread, with a registered closure over the
// frames we were able to capture.
bool Profiler::enqueueDeferred(u64 counter, EventType event_type, Event *event, bool needsTag,
                               ASGCT_CallFrame *frames, int num_frames, int first_java_frame,
                               AwaitData *tlad, AwaitData *ad, bool isContinuation,
                               Registration *registrationp, producer_token_t* pt
) {
    // Notify runChain that we were sampled now, as deferral may well occur after runChain
    __atomic_store_n(&ad->sampledIndicator, ad->expectedIndicator, __ATOMIC_RELEASE);
    // And notify the parent thread if there is one.
    AwaitData *pad = ad->parentAwaitData();
    if (pad) pad->sample();

    Deferred d;
    int j;
    d.num_frames = num_frames;
    for (j = 0; j < num_frames && num_frames < (DEFAULT_JSTACKDEPTH - 2); j++)
        d.frames[j] = frames[j];
    j += makeFrame(d.frames + j, BCI_CUSTOM, "deferred");
    d.frames[j] = {0, 0, 0}; // null terminate
    d.sampled_thread_ref = isContinuation && ad ? ad->weak_thread_ref : nullptr;
    d.counter = counter;
    d.event = *event;
    d.event_type = event_type;
    d.await_data = *(AwaitData *) ad; // full state of await data is _copied_
    d.await_data.debugInfo = "deferred";
    d.first_java_frame = first_java_frame;
    if (registrationp)
        d.registration = *registrationp;
    d.needsTag = needsTag;
    d.isContinuation = isContinuation;
    // Contents of d will be *copied* onto the queue.
    bool ret = _dq->try_enqueue(*pt, d);
    if (ret) atomicInc(stats._enqueued);
    else atomicInc(stats._enqueueFail);
    return ret;
}

#define MAX_THREAD_HOPS 50

u32 Profiler::tryLock() {
        u32 lock_index = getLockIndex(fastThreadId());
    if (!_locks[lock_index].tryLock() &&
        !_locks[lock_index = (lock_index + 1) % CONCURRENCY_LEVEL].tryLock() &&
        !_locks[lock_index = (lock_index + 2) % CONCURRENCY_LEVEL].tryLock()) {
        return  CONCURRENCY_LEVEL+1;
    }
    return lock_index;
}

// Make sure all sampled threads are recorded
u32 Profiler::recordThreads(JNIEnv *env) {
    if (_vtSlots > 0) {
        u32 lock_index = tryLock();
        if (lock_index > CONCURRENCY_LEVEL)
            return 0;
        u32 ret = 0;
        for (int i=0; i<_vtSlots; i++) {
            AwaitData* ad = &_vtAwaitData[i];
            if ((ad->flags & (AD_STACK_SAMPLED | AD_STACK_SAVED)) == AD_STACK_SAMPLED) {
                if (recordThread(env, ad, 0, "dump", false, nullptr, lock_index)) ret++;
            }
            if ((i % _vtBucketSize) == _vtBucketSize - 1) {
                ad = __atomic_load_n(&ad->next_await_data, __ATOMIC_ACQUIRE);
                while (ad) {
                    if ((ad->flags & (AD_STACK_SAMPLED | AD_STACK_SAVED)) == AD_STACK_SAMPLED) {
                        if (recordThread(env, ad, 0, "dump", false, nullptr, lock_index)) ret++;
                    }
                    ad = __atomic_load_n(&ad->next_await_data, __ATOMIC_ACQUIRE);
                }
            }
        }
        _locks[lock_index].unlock();
        return ret;
    } else return 0;
}

// Snap the stack of a thread, and the stacks of its parents
long Profiler::recordThread(JNIEnv *env, AwaitData *ad, int start, const char *info,
    bool assumeSampled, AwaitData *rabbit, u32 existing_lock) {
    if (!ad) ad = awaitData(false);
    if (!ad || !ad->java_stack_id) return -1;

    bool recursive = existing_lock < CONCURRENCY_LEVEL;;

    if (assumeSampled) {
        long f;
        // Return only if this has already been saved.
        do {
            f = ad->flags;
            if (f & AD_STACK_SAVED)
                return ad->java_stack_id;
        } while (__sync_val_compare_and_swap(&ad->flags, f, f | AD_STACK_SAMPLED | AD_STACK_SAVED) != f);
    }
    else {
        // return unless explicitly sampled but not saved
        auto prev = __sync_val_compare_and_swap(&ad->flags, AD_STACK_SAMPLED, AD_STACK_SAMPLED | AD_STACK_SAVED);
        if (prev & AD_STACK_SAVED) {
            if (ad->java_stack_hash) return ad->java_stack_hash;
            else return ad->java_stack_id;;
        }
        if (!(prev & AD_STACK_SAMPLED)) return 0;
    }

    u32 lock_index;
    if (recursive)
        lock_index = existing_lock;
    else {
        lock_index = tryLock();
        if (lock_index >= CONCURRENCY_LEVEL) {
            ad->unsave();
            atomicInc(stats._chainFail);
            return -2;
        }
    }

    ASGCT_CallFrame *frames = _calltrace_buffer[lock_index]->_asgct_frames;
    jvmtiFrameInfo *jvmti_frames = _calltrace_buffer[lock_index]->_jvmti_frames;
    _savedAwaitStacks = true;

    // If there's a parent, make sure that it's recorded first, so we can get its hash.
    long parent_hash = 0;
    auto pad = ad->parentAwaitData();
    if (pad) {
        if (pad->java_stack_id) {
            // Safety check for cycle
            if (rabbit == ad) {
                return -3;
            }
            if (rabbit) {
                rabbit = rabbit->parentAwaitData();
                rabbit = rabbit ? rabbit->parentAwaitData() : nullptr;
            } else rabbit = ad;
            parent_hash = __atomic_load_n(&pad->java_stack_hash, __ATOMIC_ACQUIRE);
            if (!parent_hash)
                parent_hash = recordThread(env, pad, 0, info, true, rabbit, lock_index);
        }
    }

    // Mark our identity, initially via the ID chosen from java
    int num_frames = makeFrame(frames, BCI_AWAIT_MARKER, ad->java_stack_id);

    if (_debug_frames && info)
        num_frames += makeFrame(frames + num_frames, BCI_ERROR, info);

    // Make sure we have a strong reference to the thread...
    jthread thread = env->NewLocalRef(ad->weak_thread_ref);
    if (!thread) {
        num_frames += makeFrame(frames + num_frames, BCI_ERROR, "gcd_thread");
        __atomic_store_n(&ad->thread_id, 0, __ATOMIC_RELEASE);  // AwaitData can now-be re-used
        __atomic_store_n(&ad->flags,0, __ATOMIC_RELEASE);
        _call_trace_storage->put(num_frames, frames, 1, nullptr);
        if (existing_lock >= CONCURRENCY_LEVEL)
            _locks[lock_index].unlock();
        atomicInc(stats._chainFail);
        return -1;
    }
    // ... and that the thread is still alive.
    jint thread_state;
    VM::jvmti()->GetThreadState(thread, &thread_state);
    int first_java = num_frames;
    int jpos = -1;
    if ((thread_state & 1) == 1) {
        jpos = num_frames;
        // Get the stack and make runChain substitutions
        num_frames += getJavaTraceJvmti(thread, jvmti_frames + jpos, frames + jpos, start,
                                        _max_stack_depth);
        num_frames = substituteAwaitMarkers(ad, frames, first_java, num_frames);
        atomicInc(stats._chained);
    } else {
        atomicInc(stats._chainFail);
        num_frames += makeFrame(frames + num_frames, BCI_ERROR, "dead_thread");
    }
    env->DeleteLocalRef(thread);

    if (parent_hash > 0) {
        // chain to the parent
        num_frames += makeFrame(frames + num_frames, BCI_AWAIT_INSERTION, parent_hash);
    }

    // Store thread by its unique[ish] hash
    long hash = (long) (CallTraceStorage::calcHash(num_frames - jpos, frames + jpos) >> 1);
    ad->java_stack_hash = hash;  // maybe we'll find a use for this ....
    frames[0].method_id = (jmethodID) hash;
    _call_trace_storage->put(num_frames, frames, 1, nullptr);
    // and then store a redirection from node id to hash, re-using our frame storage
    num_frames = makeFrame(frames, BCI_AWAIT_MARKER, ad->java_stack_id);
    num_frames +=  makeFrame(frames + num_frames, BCI_AWAIT_INSERTION, hash);
    _call_trace_storage->put(num_frames, frames, 1, nullptr);

    if (existing_lock >= CONCURRENCY_LEVEL)
        _locks[lock_index].unlock();

    return hash;
}

u64 Profiler::recordSample(void *ucontext, u64 counter, EventType event_type, Event *event,
                           u64 *tagp, Deferred *deferred, Registration *registrationp) {
    int tid = fastThreadId();
    if (Protect::protectedOperation())
        return bail(tid, event_type, -1);

    atomicInc(_total_samples);

    u32 lock_index = tryLock();
    if (lock_index > CONCURRENCY_LEVEL)
        return bail(tid, event_type, -1);

    u64 stack_walk_begin = _features.stats ? OS::nanotime() : 0;

    ASGCT_CallFrame* frames = _calltrace_buffer[lock_index]->_asgct_frames;
    jvmtiFrameInfo* jvmti_frames = _calltrace_buffer[lock_index]->_jvmti_frames;

    int num_frames = 0;

    AwaitData* tlad = threadLocalAwaitData(false);
    // MS: definitely not a VT continuation if not  virtual thread.
    bool possibly_truncated = tlad && tlad->mounted_await_data;
    const char *unsafe_frame = NULL;  // MS
    int first_java_frame = -1;

    u64 tag_temp = 0;

    AwaitData *ad = NULL;

    // MS: When called from deferred recording thread, stitch stacks
    if (deferred) {
        // Use await data from time of deferral
        ad = &deferred->await_data;

        if (!deferred->isContinuation) {
            num_frames = deferred->num_frames;
            memcpy(frames, deferred->frames, num_frames * sizeof(frames[0]));
        } else {
            ASGCT_CallFrame *df = deferred->frames;
            const char *err = NULL;
            int nDeferred = deferred->num_frames;
            if (deferred->sampled_thread_ref) {
                atomicInc(deferral_epoch);
                int iJvmti, jDeferred;
                // Create index from methods in deferred stack to earliest position in deferred stack.
                for (jDeferred = nDeferred - 1; jDeferred >= 0; jDeferred--)
                    _deferred_pos[mix(df[jDeferred].method_id)] = jDeferred + 1;
                jvmtiFrameInfo *bufJvmti = _deferred_buf->_jvmti_frames;
                ASGCT_CallFrame *bufAsgct = _deferred_buf->_asgct_frames;
                int nJvmti = getJavaTraceJvmti(deferred->sampled_thread_ref, bufJvmti, bufAsgct, 0, _max_stack_depth) -
                             1;
                const int j1 = deferred->first_java_frame;
                for (iJvmti = 0; iJvmti < nJvmti; iJvmti++) {
                    // Is this frame found in our deferred stack?
                    jmethodID id = (bufAsgct++)->method_id;
                    jDeferred = (int) _deferred_pos[mix(id)];
                    if (jDeferred > j1 && jDeferred < (nDeferred - 1) &&
                        (bufAsgct -  _deferred_buf->_asgct_frames) < nJvmti &&
                        // position looks reasonable; check for exact jmethod match
                        df[jDeferred - 1].method_id == id &&
                        // and check the next one, so we have two in a row
                        df[jDeferred].method_id == bufAsgct->method_id)
                        break;
                }
                if (iJvmti < nJvmti) {
                    // Found a match at deferred[j] == jvmti[i], so copy over frames up through j
                    nDeferred = jDeferred;
                    iJvmti++;
                } else {
                    // No match.  We'll copy all the frames over
                    iJvmti = 0;
                    nDeferred = deferred->num_frames;
                    bufAsgct = _deferred_buf->_asgct_frames;
                    atomicInc(stats._stitchFail);
                    err = "stitch_error";
                }
                // Copy over deferred frames
                while (nDeferred--) frames[num_frames++] = *df++;
                // then jvmti frames
                if (!err) atomicInc(stats._stitched);
                if (_debug_frames)
                    num_frames += makeFrame(frames + num_frames, BCI_ERROR, "stitch_point");
                do {
                    frames[num_frames++] = *bufAsgct++;
                } while (num_frames < _max_stack_depth && ++iJvmti < nJvmti);
            } else {
                // Thread no longer exists, presumably gc'd
                err = "deferred_gcd";
                while (nDeferred--) frames[num_frames++] = *df++;
            }
            if (err)
                num_frames += makeFrame(frames + num_frames, BCI_ERROR, err);

            registrationp = &deferred->registration;
            if (deferred->needsTag && registrationp)
                tagp = &tag_temp;
        }
    }
    // Not deferred.  Capture stacks as normal.
    else {

        if (_add_event_frame && event_type >= ALLOC_SAMPLE && event_type <= PARK_SAMPLE) {
            u32 class_id = ((EventWithClassId *) event)->_class_id;
            if (class_id != 0) {
                // Convert event_type to frame_type, e.g. ALLOC_SAMPLE -> BCI_ALLOC
                jint frame_type = BCI_ALLOC - (event_type - ALLOC_SAMPLE);
                num_frames = makeFrame(frames, frame_type, class_id);
            }
        }

        StackContext java_ctx = {0};
        if (hasNativeStack(event_type)) {
            if (_features.pc_addr && event_type <= WALL_CLOCK_SAMPLE) {
                num_frames += makeFrame(frames + num_frames, BCI_ADDRESS, StackFrame(ucontext).pc());
            }
            if (_cstack != CSTACK_NO) {
                num_frames += getNativeTrace(ucontext, frames + num_frames, event_type, tid, &java_ctx, &unsafe_frame);
            }
        }

    // If an unsafe frame was detected in native stack, skip java stack.
    if (unsafe_frame && _cstack < CSTACK_VM) {
        long n = atomicInc(_failures[-java_skipped])+1;
        if (n==1 || ((n & (n - 1)) == 0)) {
            Log::info("Skipping unsafe %ld %s", n, unsafe_frame);
        }
        num_frames += makeFrame(frames + num_frames, BCI_ERROR, "java_skipped");
    }

        else {
            first_java_frame = num_frames;
            if (_cstack == CSTACK_VMX) {
                num_frames += StackWalker::walkVM(ucontext, frames + num_frames, _max_stack_depth, VM_EXPERT, false);
            } else if (event_type <= WALL_CLOCK_SAMPLE) {
                // Async events
                if (_cstack == CSTACK_VM) {
                    num_frames += StackWalker::walkVM(ucontext, frames + num_frames, _max_stack_depth, VM_NORMAL, false);
                } if (_cstack == CSTACK_DWARF_VM) {
                    num_frames += StackWalker::walkVM(ucontext, frames + num_frames, _max_stack_depth, VM_NORMAL, true);
                } else {
                    int java_frames = getJavaTraceAsync(ucontext, frames + num_frames, _max_stack_depth, &java_ctx);
                    if (java_frames > 0 && java_ctx.pc != NULL && VMStructs::hasMethodStructs()) {
                        NMethod *nmethod = CodeHeap::findNMethod(java_ctx.pc);
                        if (nmethod != NULL) {
                            fillFrameTypes(frames + num_frames, java_frames, nmethod);
                        }
                    }
                    num_frames += java_frames;
                }
            } else if (event_type >= ALLOC_SAMPLE && event_type <= ALLOC_OUTSIDE_TLAB && _alloc_engine == &alloc_tracer) {
                VMThread *vm_thread;
                if (VMStructs::hasStackStructs() && (vm_thread = VMThread::current()) != NULL) {
                    num_frames += StackWalker::walkVM(ucontext, frames + num_frames, _max_stack_depth, vm_thread->anchor(), false);
                } else {
                    num_frames += getJavaTraceAsync(ucontext, frames + num_frames, _max_stack_depth, &java_ctx);
                }
            } else if (event_type == MALLOC_SAMPLE ||
                       event_type == JEMALLOC_SAMPLE || event_type == JEMALLOC_LIVE) { // MS
                num_frames += getJavaTraceAsync(ucontext, frames + num_frames, _max_stack_depth, &java_ctx);
            } else {
                // Lock events and instrumentation events can safely call synchronous JVM TI stack walker.
                // Skip Instrument.recordSample() method
                int start_depth = event_type == INSTRUMENTED_METHOD ? 1 : 0;
                num_frames += getJavaTraceJvmti(0, jvmti_frames + num_frames, frames + num_frames, start_depth, _max_stack_depth);
            }
        }

        if (num_frames == 0) {
            num_frames += makeFrame(frames + num_frames, BCI_ERROR, "no_Java_frame");
        }

        if (_add_thread_frame) {
            num_frames += makeFrame(frames + num_frames, BCI_THREAD_ID, tid);
        }
        if (_add_sched_frame) {
            num_frames += makeFrame(frames + num_frames, BCI_ERROR, OS::schedPolicy(0));
        }

    }

    if (stack_walk_begin != 0) {
        u64 stack_walk_end = OS::nanotime();
        atomicInc(_total_stack_walk_time, stack_walk_end - stack_walk_begin);
    }

    if (!ad) ad = awaitData(false);
    if (!deferred && unsafe_frame == NULL) {
        // MS: Possibly pass our accumulated stacks to the deferred recording thread.
        if (ad && _recording_deferred && runContinuationId) {
            // Possibly truncated virtual stack
            if (possibly_truncated && first_java_frame >= 0) {
                int i;
                for (i = first_java_frame; i < num_frames; i++) {
                    if (frames[i].method_id == runContinuationId) {
                        if (enqueueDeferred(counter, event_type, event, tagp != nullptr,
                                            frames, i, first_java_frame,
                                            tlad, ad, true, registrationp, _pts[lock_index])) {
                            _locks[lock_index].unlock();
                            return 1;
                        } else {
                            num_frames += makeFrame(frames + num_frames, BCI_ERROR, "defer_failed");
                            break;
                        }
                    }
                }
                if (i == num_frames)
                    num_frames += makeFrame(frames + num_frames, BCI_ERROR, "runContinuation_not_found");
            } else if (event_type == JEMALLOC_LIVE && _recording_deferred && registrationp) {
                // jemalloc sample to linearize
                if (enqueueDeferred(counter, event_type, event, tagp != nullptr,
                                    frames, num_frames, first_java_frame,
                                    tlad, ad, false, registrationp, _pts[lock_index])) {
                    _locks[lock_index].unlock();
                    return 1;
                } else {
                    num_frames += makeFrame(frames + num_frames, BCI_ERROR, "defer_failed");
                }
            }
        }
    }

    num_frames = substituteAwaitMarkers(ad, frames, first_java_frame, num_frames);

    // If we're processing a virtual thread, chain to
    AwaitData* pad = nullptr;
    if (deferred) {
        pad = deferred->await_data.parentAwaitData();
        if (pad) {
            if (pad->java_stack_id) {
                if (_debug_frames)
                    num_frames += makeFrame(frames + num_frames, BCI_ERROR, "defer_chain");
                // If the parent thread has been saved already, chain to its hash directly
                long  parent_hash = __atomic_load_n(&pad->java_stack_hash, __ATOMIC_ACQUIRE);
                if (!parent_hash) parent_hash = pad->java_stack_id;
                num_frames += makeFrame(frames + num_frames, BCI_AWAIT_INSERTION, parent_hash);
            } else pad = nullptr;
        }
    }

    // MS: Add custom id frame
    if (event_type == CUSTOM) {
        // static cast is discouraged, but we know that this is a CustomEvent
        auto *e = static_cast<CustomEvent *>(event);
        num_frames += makeFrame(frames + num_frames, BCI_CUSTOM, e->info);
    }
    // MS: Add event type identification frame
    else if (_eventtypeframes) {
        const char *tpe = nullptr;
        switch (event_type) {
            case EXECUTION_SAMPLE: tpe = nullptr;
                break;
            case LOCK_SAMPLE:
            case PARK_SAMPLE: tpe = "Lock";
                break;
            case ALLOC_SAMPLE: tpe = "Alloc";
                break;
            case ALLOC_LIVE: tpe = "Live";
                break;
            case JEMALLOC_LIVE: tpe = "LiveNative";
                break;
            case JEMALLOC_SAMPLE: tpe = "AllocNative";
                break;
            default:
                tpe = "Unknown";
                break;
        }
        if (tpe)
            num_frames += makeFrame(frames + num_frames, BCI_CUSTOM, tpe);
    }

    // MS: Add external context marker if set so parent process can attach stack
    if (externalContext && *externalContext && *externalContext != -1L) {
        num_frames += makeFrame(frames + num_frames, BCI_STACK_TAG, (jmethodID) *externalContext);
    }

    u32 call_trace_id = _call_trace_storage->put(num_frames, frames, counter,
                                                tagp); // MS
    if (event)  // MS: there might not be an event if this is a persistent live reference.
        _jfr.recordEvent(lock_index, tid, call_trace_id, event_type, event);

    _locks[lock_index].unlock();
    u64 trace = (u64)tid << 32 | call_trace_id;

    if (registrationp)
        registrationp->run(trace, tagp ? *tagp : 0);

    return trace;
}
// MS: Record custom sample explicitly, optionally with stack id hash and error frame
void Profiler::recordExternalSample(u64 counter, const char* customType, const char * error, u64 sidref) {
    atomicInc(_total_samples);
    ASGCT_CallFrame frames[4];
    int n = 0;
    if (sidref) n += makeFrame(frames + n, BCI_STACK_TAG, (jmethodID) sidref);
    if (error) n += makeFrame(frames + n, BCI_ERROR, error);
    if (customType) n += makeFrame(frames + n, BCI_CUSTOM, customType);
    if (externalContext && *externalContext && *externalContext != -1L)
        n += makeFrame(frames + n, BCI_STACK_TAG, (jmethodID) *externalContext);
    if (n)
       _call_trace_storage->put(n, frames, counter, 0);
}


void Profiler::recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, int num_frames, ASGCT_CallFrame* frames) {
    atomicInc(_total_samples);

    if (_add_thread_frame) {
        num_frames += makeFrame(frames + num_frames, BCI_THREAD_ID, tid);
    }
    if (_add_sched_frame) {
        num_frames += makeFrame(frames + num_frames, BCI_ERROR, OS::schedPolicy(tid));
    }

    u32 call_trace_id = _call_trace_storage->put(num_frames, frames, counter, nullptr);

    u32 lock_index = getLockIndex(tid);
    if (!_locks[lock_index].tryLock() &&
        !_locks[lock_index = (lock_index + 1) % CONCURRENCY_LEVEL].tryLock() &&
        !_locks[lock_index = (lock_index + 2) % CONCURRENCY_LEVEL].tryLock()) {
        // Too many concurrent signals already
        atomicInc(_failures[-ticks_skipped]);
        return;
    }

    if (event)  // Possibly no event for persistent live
        _jfr.recordEvent(lock_index, tid, call_trace_id, event_type, event);

    _locks[lock_index].unlock();
}

// Replace runChain with reference to node hashe
int Profiler::substituteAwaitMarkers(AwaitData *ad, ASGCT_CallFrame *frames, int first_java_frame,
                                     int num_frames) const {
    if (!ad || !ad->targetMethodId || !ad->expectedIndicator || !ad->await_stack_ids[0]) return num_frames;
    jmethodID iid = (jmethodID) ad->targetMethodId;
    if (_debug_frames) {
        // Wrap each runChain with debug frames
        int npush = 0;
        for (int i = 0; i < num_frames; i++) {
            if (frames[i].method_id == iid) npush += 2;
        }
        if (npush && num_frames + npush < _max_stack_depth) {
            num_frames += npush;
            for (int i = num_frames - 1; i >= 0; i--) {
                int j = i - npush;
                if (frames[j].method_id == iid) {
                    npush -= 2;
                    i -= 2;
                    frames[i + 1] = frames[j];
                    makeFrame(frames + i, BCI_ERROR, "begin_insert");
                    makeFrame(frames + i + 2, BCI_ERROR, "end_insert");
                } else {
                    frames[i] = frames[j];
                }
            }
        }
    }

    const long *ids = (const long *) ad->await_stack_ids;
    int i = 0;
    int lastInsertion = -1;
    // Replace each runChain with corresponding reference
    while (long id = *ids++) {
        // zero terminated
        for (; i < num_frames; i++) {
            if (frames[i].method_id == iid) {
                frames[i].method_id = (jmethodID) id;
                frames[i].bci = BCI_AWAIT_INSERTION;
                __atomic_store_n(&ad->sampledIndicator, ad->expectedIndicator, __ATOMIC_RELEASE);
                lastInsertion = i;
                break;
            }
        }
    }

    // If we had more node hashes than runChains, add them innermost
    num_frames = lastInsertion >= 0 ? lastInsertion + 1 : num_frames;
    if (*ids && num_frames + 3 < _max_stack_depth) {
        if (_debug_frames)
            num_frames += makeFrame(frames + num_frames, BCI_ERROR, "begin_dangling");
        long id;
        while ((id = *ids++) && num_frames < _max_stack_depth) {
            num_frames += makeFrame(frames + num_frames, BCI_AWAIT_INSERTION, id);
        }
        if (_debug_frames)
            num_frames += makeFrame(frames + num_frames, BCI_ERROR, "end_dangling");
    }

    return num_frames;
}

void Profiler::recordExternalSamples(u64 samples, u64 counter, int tid, u32 call_trace_id, EventType event_type,
                                     Event *event) {
    _call_trace_storage->add(call_trace_id, samples, counter);

    u32 lock_index = getLockIndex(tid);
    if (!_locks[lock_index].tryLock() &&
        !_locks[lock_index = (lock_index + 1) % CONCURRENCY_LEVEL].tryLock() &&
        !_locks[lock_index = (lock_index + 2) % CONCURRENCY_LEVEL].tryLock())
    {
        return;
    }

    _jfr.recordEvent(lock_index, tid, call_trace_id, event_type, event);

    _locks[lock_index].unlock();
}

// MS: Increase counter on a trace that was already recorded, extracting trace/thread id from long
void Profiler::recordExternalSample(u64 counter, EventType event_type, Event* event, long trace) {
    int tid = trace >> 32;
    u32 call_trace_id = (u32) trace;
    recordExternalSample(counter, tid, event_type, event, call_trace_id);
}

// MS: Increase counter on a trace that was already recorded.
void Profiler::recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, u32 call_trace_id) {
    _call_trace_storage->add(call_trace_id, 1, counter);

    u32 lock_index = getLockIndex(tid);
    if (!_locks[lock_index].tryLock() &&
        !_locks[lock_index = (lock_index + 1) % CONCURRENCY_LEVEL].tryLock() &&
        !_locks[lock_index = (lock_index + 2) % CONCURRENCY_LEVEL].tryLock())
    {
        return;
    }

    if (event)
        _jfr.recordEvent(lock_index, tid, call_trace_id, event_type, event);

    _locks[lock_index].unlock();
}

void Profiler::recordEventOnly(EventType event_type, Event* event) {
    if (!_jfr.active()) {
        return;
    }

    int tid = fastThreadId();
    u32 lock_index = getLockIndex(tid);
    if (!_locks[lock_index].tryLock() &&
        !_locks[lock_index = (lock_index + 1) % CONCURRENCY_LEVEL].tryLock() &&
        !_locks[lock_index = (lock_index + 2) % CONCURRENCY_LEVEL].tryLock())
    {
        return;
    }

    _jfr.recordEvent(lock_index, tid, 0, event_type, event);

    _locks[lock_index].unlock();
}

void Profiler::tryResetCounters() {
    // Reset counters only for non-JFR recording, otherwise resetting may cause missing stack traces for some
    // allocation events and skewed incorrect number of samples.
    // In JFR recording, each sample is recorded individually, so accumulated counters are not actually used.
    if (!_jfr.active()) {
        _call_trace_storage->resetCounters();
    }
}

void Profiler::writeLog(LogLevel level, const char* message) {
    _jfr.recordLog(level, message, strlen(message));
}

void Profiler::writeLog(LogLevel level, const char* message, size_t len) {
    _jfr.recordLog(level, message, len);
}

void* Profiler::dlopen_hook(const char* filename, int flags) {
    void* result = dlopen(filename, flags);
    if (result != NULL) {
        instance()->updateSymbols(false);
        MallocTracer::installHooks();
    }
    return result;
}

void Profiler::switchLibraryTrap(bool enable) {
    if (_dlopen_entry != NULL) {
        void* impl = enable ? (void*)dlopen_hook : (void*)dlopen;
        __atomic_store_n(_dlopen_entry, impl, __ATOMIC_RELEASE);
    }
}

Error Profiler::installTraps(const char* begin, const char* end, bool nostop) {
    const void* begin_addr = NULL;
    if (begin != NULL && (begin_addr = resolveSymbol(begin)) == NULL) {
        return Error("Begin address not found");
    }

    const void* end_addr = NULL;
    if (end != NULL && (end_addr = resolveSymbol(end)) == NULL) {
        return Error("End address not found");
    }

    _begin_trap.assign(begin_addr);
    _end_trap.assign(end_addr);
    _nostop = nostop;

    if (_begin_trap.entry() == 0) {
        _engine->enableEvents(true);
    } else {
        _engine->enableEvents(nostop);
        if (!_begin_trap.install()) {
            return Error("Cannot install begin breakpoint");
        }
    }

    return Error::OK;
}

void Profiler::uninstallTraps() {
    _begin_trap.uninstall();
    _end_trap.uninstall();
    _engine->enableEvents(false);
}

void Profiler::trapHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    StackFrame frame(ucontext);

    if (_begin_trap.covers(frame.pc())) {
        profiling_window._start_time = TSC::ticks();
        _engine->enableEvents(true);
        _begin_trap.uninstall();
        _end_trap.install();
        frame.pc() = _begin_trap.entry();
    } else if (_end_trap.covers(frame.pc())) {
        _engine->enableEvents(_nostop);
        _end_trap.uninstall();
        profiling_window._end_time = TSC::ticks();
        recordEventOnly(PROFILING_WINDOW, &profiling_window);
        _begin_trap.install();
        frame.pc() = _end_trap.entry();
    } else if (orig_trapHandler != NULL) {
        orig_trapHandler(signo, siginfo, ucontext);
    }
}

void Profiler::segvHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    StackFrame frame(ucontext);
    uintptr_t pc = frame.pc();

    uintptr_t length = SafeAccess::skipLoad(pc);
    if (length > 0) {
        // Skip the fault instruction, as if it successfully loaded NULL
        frame.pc() += length;
        frame.retval() = 0;
        return;
    }

    length = SafeAccess::skipLoadArg(pc);
    if (length > 0) {
        // Act as if the load returned default_value argument
        frame.pc() += length;
        frame.retval() = frame.arg1();
        return;
    }

    StackWalker::checkFault();

    // Workaround for JDK-8313796. Setting cstack=dwarf also helps
    if (VMStructs::isInterpretedFrameValidFunc((const void*)pc) && frame.skipFaultInstruction()) {
        return;
    }

    if (WX_MEMORY && Trap::isFaultInstruction(pc)) {
        return;
    }

    orig_segvHandler(signo, siginfo, ucontext);
}

void Profiler::wakeupHandler(int signo) {
    // Dummy handler for interrupting syscalls
}

void Profiler::setupSignalHandlers() {
    SigAction prev_handler = OS::installSignalHandler(SIGTRAP, AllocTracer::trapHandler);
    if (prev_handler == AllocTracer::trapHandler) {
        // Handlers already configured
        return;
    } else if (prev_handler != (void*)SIG_DFL && prev_handler != (void*)SIG_IGN) {
        orig_trapHandler = prev_handler;
    }

    if (VM::hotspot_version() > 0 || !VM::loaded()) {
        // HotSpot tolerates interposed SIGSEGV/SIGBUS handler; other JVMs probably not
        orig_segvHandler = OS::replaceCrashHandler(segvHandler);
    }

    // MS
    if (OS::installForkHandler()) {
        Log::warn("error installing fork handler: %s", strerror(errno));
    }

    OS::installSignalHandler(WAKEUP_SIGNAL, NULL, wakeupHandler);
}

void Profiler::setThreadInfo(int tid, const char* name, jlong java_thread_id) {
    MutexLocker ml(_thread_names_lock);
    _thread_names[tid] = name;
    _thread_ids[tid] = java_thread_id;
}

void Profiler::updateThreadName(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    if (_update_thread_names) {
        JitWriteProtection jit(true);  // workaround for JDK-8262896
        jvmtiThreadInfo thread_info;
        int native_thread_id = VMThread::nativeThreadId(jni, thread);
        if (native_thread_id >= 0 && jvmti->GetThreadInfo(thread, &thread_info) == 0) {
            jlong java_thread_id = VMThread::javaThreadId(jni, thread);
            setThreadInfo(native_thread_id, thread_info.name, java_thread_id);
            jvmti->Deallocate((unsigned char*)thread_info.name);
        }
    }
}

void Profiler::updateJavaThreadNames() {
    if (_update_thread_names && VM::loaded()) {
        jvmtiEnv* jvmti = VM::jvmti();
        jint thread_count;
        jthread* thread_objects;
        if (jvmti->GetAllThreads(&thread_count, &thread_objects) != 0) {
            return;
        }

        JNIEnv* jni = VM::jni();
        for (int i = 0; i < thread_count; i++) {
            updateThreadName(jvmti, jni, thread_objects[i]);
        }

        jvmti->Deallocate((unsigned char*)thread_objects);
    }
}

void Profiler::updateNativeThreadNames() {
    if (_update_thread_names) {
        ThreadList* thread_list = OS::listThreads();
        char name_buf[64];

        while (thread_list->hasNext()) {
            int tid = thread_list->next();
            MutexLocker ml(_thread_names_lock);
            std::map<int, std::string>::iterator it = _thread_names.lower_bound(tid);
            if (it == _thread_names.end() || it->first != tid) {
                if (OS::threadName(tid, name_buf, sizeof(name_buf))) {
                    _thread_names.insert(it, std::map<int, std::string>::value_type(tid, name_buf));
                }
            }
        }

        delete thread_list;
    }
}

bool Profiler::excludeTrace(FrameName* fn, CallTrace* trace) {
    if(trace->frames[0].bci == BCI_AWAIT_MARKER) return true;
    bool checkInclude = fn->hasIncludeList();
    bool checkExclude = fn->hasExcludeList();
    if (!(checkInclude || checkExclude)) {
        return false;
    }

    for (int i = 0; i < trace->num_frames; i++) {
        const char* frame_name = fn->name(trace->frames[i], true);
        if (checkExclude && fn->exclude(frame_name)) {
            return true;
        }
        if (checkInclude && fn->include(frame_name)) {
            checkInclude = false;
            if (!checkExclude) break;
        }
    }

    return checkInclude;
}

Engine* Profiler::selectEngine(const char* event_name) {
    if (event_name == NULL) {
        return &noop_engine;
    } else if (strcmp(event_name, EVENT_CPU) == 0) {
        if (FdTransferClient::hasPeer() || PerfEvents::supported()) {
            return &perf_events;
        } else if (CTimer::supported()) {
            return &ctimer;
        } else {
            return &wall_clock;
        }
    } else if (strcmp(event_name, EVENT_WALL) == 0) {
        if (VM::isOpenJ9()) {
            return &j9_wall_clock;
        } else {
            return &wall_clock;
        }
    } else if (strcmp(event_name, EVENT_CTIMER) == 0) {
        return &ctimer;
    } else if (strcmp(event_name, EVENT_ITIMER) == 0) {
        return &itimer;
    } else if (strchr(event_name, '.') != NULL && strchr(event_name, ':') == NULL) {
        return &instrument;
    } else {
        return &perf_events;
    }
}

Engine* Profiler::selectAllocEngine(Arguments& args) {
    // MS: Object sampler is used for both java and jemalloc native allocations.  Will be enabled if either in use.
    bool object_sampling = args._jvm && VM::addSampleObjectsCapability();
    bool jemalloc_sampling =  args._jemalloc && ObjectSampler::checkJemallocEnabled();
    if (object_sampling || jemalloc_sampling) {
        return &object_sampler;
    } else if (VM::isOpenJ9()) {
        return &j9_object_sampler;
    } else {
        return &alloc_tracer;
    }
}

Engine* Profiler::activeEngine() {
    switch (_event_mask) {
        case EM_ALLOC:
            return _alloc_engine;
        case EM_LOCK:
            return &lock_tracer;
        case EM_WALL:
            return &wall_clock;
        case EM_NATIVEMEM:
            return &malloc_tracer;
        default:
            return _engine;
    }
}

Error Profiler::checkJvmCapabilities() {
    if (VM::loaded()) {
        if (!VMStructs::hasJavaThreadId()) {
            return Error("Could not find Thread ID field. Unsupported JVM?");
        }

        if (VMThread::key() < 0) {
            return Error("Could not find VMThread bridge. Unsupported JVM?");
        }

        if (_dlopen_entry == NULL) {
            CodeCache* lib = findJvmLibrary("libj9prt");
            if (lib == NULL || (_dlopen_entry = lib->findImport(im_dlopen)) == NULL) {
                return Error("Could not set dlopen hook. Unsupported JVM?");
            }
        }

        if (!VMStructs::libjvm()->hasDebugSymbols()) {
            Log::warn("Install JVM debug symbols to improve profile accuracy");
        }
    }

    return Error::OK;
}

Error Profiler::start(Arguments& args, bool reset) {
    MutexLocker ml(_state_lock);
    if (_state > IDLE) {
        return Error("Profiler already started");
    }

    // If profiler is started from a native app, try to detect a running JVM and attach to it
    if (!VM::loaded()) {
        VM::tryAttach();
    }

    Error error = checkJvmCapabilities();
    if (error) {
        return error;
    }

    _eventtypeframes = args._eventtypeframes;  // MS
    _persist = args._persist; // MS
    _debug_frames = args._debug_frames;

    _event_mask = (args._event != NULL ? EM_CPU : 0) |
                  (args._alloc >= 0 ? EM_ALLOC : 0) |
                  (args._lock >= 0 ? EM_LOCK : 0) |
                  (args._wall >= 0 ? EM_WALL : 0) |
                  (args._nativemem >= 0 ? EM_NATIVEMEM : 0);

    if (_event_mask == 0) {
        return Error("No profiling events specified");
    } else if ((_event_mask & (_event_mask - 1)) && args._output != OUTPUT_JFR &&
                 !_eventtypeframes) { // MS: event frames allow multiple events
        return Error("Only JFR output supports multiple events");
    } else if (!VM::loaded() && (_event_mask & (EM_LOCK))) {
        return Error("Profiling event is not supported with non-Java processes");
    }

    if (args._fdtransfer) {
        if (!FdTransferClient::connectToServer(args._fdtransfer_path)) {
            return Error("Failed to initialize FdTransferClient");
        }
    }

    // Save the arguments for shutdown or restart
    args.save();

    if (reset || _start_time == 0) {
        // Reset counters
        _total_samples = 0;
        _total_stack_walk_time = 0;
        memset(_failures, 0, sizeof(_failures));

        // Reset dictionaries and bitmaps
        lockAll();
        _class_map.clear();
        _thread_filter.clear();
        _call_trace_storage->clear();
        // Make sure frame structure is consistent throughout the entire recording
        _add_event_frame = args._output != OUTPUT_JFR;
        _add_thread_frame = args._threads && args._output != OUTPUT_JFR;
        _add_sched_frame = args._sched;
        unlockAll();

        // Reset thread names and IDs
        MutexLocker ml(_thread_names_lock);
        _thread_names.clear();
        _thread_ids.clear();
    }

    // (Re-)allocate calltrace buffers
    if (_max_stack_depth != args._jstackdepth) {
        _max_stack_depth = args._jstackdepth;
        size_t nelem = _max_stack_depth + MAX_NATIVE_FRAMES + RESERVED_FRAMES;

        for (int i = 0; i < CONCURRENCY_LEVEL; i++) {
            free(_calltrace_buffer[i]);
            _calltrace_buffer[i] = (CallTraceBuffer*)calloc(nelem, sizeof(CallTraceBuffer));
            if (_calltrace_buffer[i] == NULL) {
                _max_stack_depth = 0;
                return Error("Not enough memory to allocate stack trace buffers (try smaller jstackdepth)");
            }
        }

        if (_deferred_buf) free((void *) _deferred_buf);
        if (_deferred_pos) free((void *) _deferred_pos);
        _deferred_buf = (CallTraceBuffer*) calloc(nelem, sizeof(CallTraceBuffer));
        _deferred_pos = (u32*) calloc((DEFERRED_POS_MASK+1), sizeof(u32));
    }

    _features = args._features;
    if (VM::hotspot_version() < 8) {
        _features.java_anchor = 0;
        _features.gc_traces = 0;
    }
    if (!VMStructs::hasClassNames()) {
        _features.vtable_target = 0;
    }
    if (!VMStructs::hasCompilerStructs()) {
        _features.comp_task = 0;
    }

    _update_thread_names = args._threads || args._output == OUTPUT_JFR;
    _thread_filter.init(args._filter);

    _engine = selectEngine(args._event);
    if (_engine == &wall_clock && args._wall >= 0) {
        return Error("Cannot start wall clock with the selected event");
    } else if (_engine != &perf_events && args._target_cpu != -1) {
        return Error("target-cpu is only supported with perf_events");
    }

    _cstack = args._cstack;
    if (_cstack == CSTACK_DWARF && !DWARF_SUPPORTED) {
        return Error("DWARF unwinding is not supported on this platform");
    } else if (_cstack == CSTACK_LBR && _engine != &perf_events) {
        return Error("Branch stack is supported only with PMU events");
    } else if (_cstack >= CSTACK_VM && !VMStructs::hasStackStructs()) {
        return Error("VMStructs stack walking is not supported on this JVM/platform");
    }

    if (VM::isOpenJ9() && _cstack == CSTACK_DEFAULT && DWARF_SUPPORTED) {
        // OpenJ9 libs are compiled with frame pointers omitted
        _cstack = CSTACK_DWARF;
    }

    // Kernel symbols are useful only for perf_events without --all-user
    updateSymbols(_engine == &perf_events && !args._alluser);

    error = installTraps(args._begin, args._end, args._nostop);
    if (error) {
        return error;
    }
    switchLibraryTrap(true);

    if (args._output == OUTPUT_JFR) {
        error = _jfr.start(args, reset);
        if (error) {
            uninstallTraps();
            switchLibraryTrap(false);
            return error;
        }
    }

    error = _engine->start(args);
    if (error) {
        goto error1;
    }

    if (_event_mask & EM_ALLOC) {
        _alloc_engine = selectAllocEngine(args);
        error = _alloc_engine->start(args);
        if (error) {
            goto error2;
        }
    }
    if (_event_mask & EM_LOCK) {
        error = lock_tracer.start(args);
        if (error) {
            goto error3;
        }
    }
    if (_event_mask & EM_WALL) {
        error = wall_clock.start(args);
        if (error) {
            goto error4;
        }
    }
    if (_event_mask & EM_NATIVEMEM) {
        error = malloc_tracer.start(args);
        if (error) {
            goto error5;
        }
    }

    switchThreadEvents(JVMTI_ENABLE);

    _state = RUNNING;
    _start_time = time(NULL);
    _epoch++;

    if (args._timeout != 0 || args._output == OUTPUT_JFR) {
        _stop_time = addTimeout(_start_time, args._timeout);
        startTimer();
    }

    return Error::OK;

error5:
    if (_event_mask & EM_NATIVEMEM) malloc_tracer.stop();

error4:
    if (_event_mask & EM_LOCK) lock_tracer.stop();

error3:
    if (_event_mask & EM_ALLOC) _alloc_engine->stop();

error2:
    _engine->stop();

error1:
    uninstallTraps();
    switchLibraryTrap(false);

    lockAll();
    _jfr.stop();
    unlockAll();

    FdTransferClient::closePeer();
    return error;
}

// MS
void Profiler::stop_jemalloc() {
    MutexLocker ml(_state_lock);
    if ((_event_mask & EM_ALLOC) && _alloc_engine) _alloc_engine->stop_jemalloc();
}

Error Profiler::stop(bool restart) {
    MutexLocker ml(_state_lock);
    if (_state != RUNNING) {
        return Error("Profiler is not active");
    }

    uninstallTraps();

    if (_event_mask & EM_WALL) wall_clock.stop();
    if (_event_mask & EM_LOCK) lock_tracer.stop();
    if (_event_mask & EM_ALLOC) _alloc_engine->stop();
    if (_event_mask & EM_NATIVEMEM) malloc_tracer.stop();

    _engine->stop();

    switchLibraryTrap(false);
    switchThreadEvents(JVMTI_DISABLE);
    updateJavaThreadNames();
    updateNativeThreadNames();

    // Make sure no periodic events sent after JFR stops
    stopTimer();

    // Log before stopping JFR to include stats in the recording
    logStats();

    // Acquire all spinlocks to avoid race with remaining signals
    lockAll();
    _jfr.stop();
    unlockAll();

    if (!restart) {
        FdTransferClient::closePeer();
    }

    _state = IDLE;
    return Error::OK;
}

volatile GlobalFlags Profiler::globalFlags = GF_NONE;  // MS

Error Profiler::check(Arguments& args) {
    MutexLocker ml(_state_lock);
    if (_state > IDLE) {
        return Error("Profiler already started");
    }

    Error error = checkJvmCapabilities();

    if (!error && args._event != NULL) {
        _engine = selectEngine(args._event);
        error = _engine->check(args);
    }
    if (!error && args._alloc >= 0) {
        _alloc_engine = selectAllocEngine(args);
        error = _alloc_engine->check(args);
    }
    if (!error && args._nativemem >= 0) {
        error = malloc_tracer.check(args);
    }
    if (!error && args._lock >= 0) {
        error = lock_tracer.check(args);
    }

    if (!error) {
        if (args._wall >= 0 && _engine == &wall_clock) {
            return Error("Cannot start wall clock with the selected event");
        }

        if (args._cstack == CSTACK_DWARF && !DWARF_SUPPORTED) {
            return Error("DWARF unwinding is not supported on this platform");
        } else if (args._cstack == CSTACK_LBR && _engine != &perf_events) {
            return Error("Branch stack is supported only with PMU events");
        } else if (args._cstack >= CSTACK_VM && !VMStructs::hasStackStructs()) {
            return Error("VMStructs stack walking is not supported on this JVM/platform");
        }
    }

    return error;
}

Error Profiler::flushJfr() {
    MutexLocker ml(_state_lock);
    if (_state != RUNNING) {
        return Error("Profiler is not active");
    }

    updateJavaThreadNames();
    updateNativeThreadNames();

    lockAll();
    _jfr.flush();
    unlockAll();

    return Error::OK;
}

Error Profiler::dump(Writer& out, Arguments& args) {
    MutexLocker ml(_state_lock);
    // MS: Stop allocation engine and dump if persisting
    bool alloc_flush =_persist && _event_mask & EM_ALLOC && _state == RUNNING;
    if (alloc_flush) {
        _alloc_engine->stop();
        _event_mask &= !EM_ALLOC; // will be reset at next start
    }

    if (_state != IDLE && _state != RUNNING) {
        return Error("Profiler has not started");
    }

    if (_state == RUNNING) {
        updateJavaThreadNames();
        updateNativeThreadNames();

        if (args._double_buffer) {
            CallTraceStorage* other = &_call_trace_storages[1 - (_call_trace_storage - _call_trace_storages)];
            other->clear();
            lockAll();
            _snapped_call_trace_storage = _call_trace_storage;
            _call_trace_storage = other;
            unlockAll();
            if (alloc_flush) {
                _event_mask |= EM_ALLOC;
                VM::addSampleObjectsCapability();
                _alloc_engine->start(_global_args);
            }
        } else
            _snapped_call_trace_storage = _call_trace_storage;
    }

    recordThreads(VM::jni());

    switch (args._output) {
        case OUTPUT_COLLAPSED:
            dumpCollapsed(out, args);
            break;
        case OUTPUT_FLAMEGRAPH:
            dumpFlameGraph(out, args, false);
            break;
        case OUTPUT_TREE:
            dumpFlameGraph(out, args, true);
            break;
        case OUTPUT_TEXT:
            dumpText(out, args);
            break;
        case OUTPUT_JFR:
            if (_state == RUNNING) {
                lockAll();
                _jfr.flush();
                unlockAll();
            }
            break;
        default:
            return Error("No output format selected");
    }

    return Error::OK;
}

void Profiler::printUsedMemory(Writer& out) {
    size_t call_trace_storage = _call_trace_storage->usedMemory();
    size_t flight_recording = _jfr.usedMemory();
    size_t dictionaries = _class_map.usedMemory() + _symbol_map.usedMemory() + _thread_filter.usedMemory();

    size_t code_cache = _runtime_stubs.usedMemory();
    int native_lib_count = _native_libs.count();
    for (int i = 0; i < native_lib_count; i++) {
        code_cache += _native_libs[i]->usedMemory();
    }
    code_cache += native_lib_count * sizeof(CodeCache);

    char buf[1024];
    const size_t KB = 1024;
    snprintf(buf, sizeof(buf) - 1,
             "Call trace storage: %7zu KB\n"
             "  Flight recording: %7zu KB\n"
             "      Dictionaries: %7zu KB\n"
             "        Code cache: %7zu KB\n"
             "------------------------------\n"
             "             Total: %7zu KB\n",
             call_trace_storage / KB, flight_recording / KB, dictionaries / KB, code_cache / KB,
             (call_trace_storage + flight_recording + dictionaries + code_cache) / KB);
    out << buf;
}

void Profiler::logStats() {
    if (!_features.stats) return;

    u64 stacks = _total_samples - _failures[-ticks_skipped];
    u64 avg_time = stacks == 0 ? 0 : _total_stack_walk_time / stacks;
    Log::info("Collected %llu stacks, avg time = %llu ns", stacks, avg_time);
}

void Profiler::lockAll() {
    for (int i = 0; i < CONCURRENCY_LEVEL; i++) _locks[i].lock();
}

void Profiler::unlockAll() {
    for (int i = 0; i < CONCURRENCY_LEVEL; i++) _locks[i].unlock();
}

void Profiler::switchThreadEvents(jvmtiEventMode mode) {
    if (_thread_events_state != mode && VM::loaded()) {
        jvmtiEnv* jvmti = VM::jvmti();
        jvmti->SetEventNotificationMode(mode, JVMTI_EVENT_THREAD_START, NULL);
        jvmti->SetEventNotificationMode(mode, JVMTI_EVENT_THREAD_END, NULL);
        _thread_events_state = mode;
    }
}

static ASGCT_CallFrame* dump_buf = NULL;
static size_t dump_buf_size = 0;
static void allocate_dump_buf(int i) {
    if (i >= dump_buf_size) {
        if (dump_buf_size == 0) dump_buf_size = 1000*1000;
        while(i >= dump_buf_size) {
            dump_buf_size *= 2;
        }
        dump_buf = (ASGCT_CallFrame*) realloc((void*) dump_buf, dump_buf_size);
    }
}

static void set_dump_frame(int i, int bci, jmethodID id) {
    allocate_dump_buf(i);
    dump_buf[i].bci = bci;
    dump_buf[i].method_id = id;
}
static void set_dump_frame(int i, ASGCT_CallFrame* frame) {
    allocate_dump_buf(i);
    dump_buf[i] = *frame;
}

/*
 * Dump stacks in FlameGraph input format:
 *
 * <frame>;<frame>;...;<topmost frame> <count>
 */
void Profiler::dumpCollapsed(Writer& out, Arguments& args) {
    FrameName fn(args, args._style | STYLE_NO_SEMICOLON, _epoch, _thread_names_lock, _thread_names);
    char buf[32];
    u64 printed_sample_count = 0;
    Dictionary* dict = args._memoizeframes ? new Dictionary() : NULL;
    unsigned int mask = 1 << 29;

    std::vector<CallTraceSample*> samples;
    _snapped_call_trace_storage->collectSamples(samples);
    FrameIterator fi(samples, _savedAwaitStacks);

    int iout = 0;
    bool binary = args._binary_dump;

    for (std::vector<CallTraceSample*>::const_iterator it = samples.begin(); it != samples.end(); ++it) {
        CallTrace* trace = (*it)->acquireTrace();
        if (trace == NULL || excludeTrace(&fn, trace)) continue;

        u64 counter = args._counter == COUNTER_SAMPLES ? (*it)->samples : (*it)->counter;
        if (counter == 0) continue;
        int n = fi.setAndCount(trace, true);

        if (binary)
            set_dump_frame(iout++, 0, (jmethodID) counter);

        ASGCT_CallFrame* frame;
        int j = n-1;
        while((frame = fi.prev()) != NULL) {
            if (binary)
                set_dump_frame(iout++, frame);
            else {
                const char *frame_name = fn.name(*frame);
                if (dict) {
                    unsigned int i = dict->lookup(frame_name, strlen(frame_name), mask);
                    if (i & mask) // not new
                        out << (i & ~mask);
                    else
                        out << i << "=" << frame_name;
                } else {
                    out << frame_name;
                }
                out << (j-- == 0 ? ' ' : ';');
            }
        }
        if (binary)
            set_dump_frame(iout++, 0, 0);
        else {
            // Beware of locale-sensitive conversion
            out.write(buf, snprintf(buf, sizeof(buf), "%llu\n", counter));
            printed_sample_count++;
        }
    }

    if (dict) delete dict;
    if (binary) {
        out << "buf=" << (long) dump_buf
            << ",szf=" << (int) sizeof(ASGCT_CallFrame)
            << ",ido" << (int) offsetof(ASGCT_CallFrame, method_id);
    }
    logEmptyOutput(args, printed_sample_count, out);
}

void Profiler::dumpFlameGraph(Writer& out, Arguments& args, bool tree) {
    char title[64];
    if (args._title == NULL) {
        Engine* active_engine = activeEngine();
        if (args._counter == COUNTER_SAMPLES) {
            strcpy(title, active_engine->title());
        } else {
            snprintf(title, sizeof(title), "%s (%s)", active_engine->title(), active_engine->units());
        }
    }

    FlameGraph flamegraph(args._title == NULL ? title : args._title, args._counter, args._minwidth, args._reverse, args._inverted);
    u64 printed_sample_count = 0;

    {
        FrameName fn(args, args._style & ~STYLE_ANNOTATE, _epoch, _thread_names_lock, _thread_names);

        std::vector<CallTraceSample*> samples;
        _snapped_call_trace_storage->collectSamples(samples);
        FrameIterator fi(samples, _savedAwaitStacks);

        for (std::vector<CallTraceSample*>::const_iterator it = samples.begin(); it != samples.end(); ++it) {
            CallTrace* trace = (*it)->acquireTrace();
            if (trace == NULL || excludeTrace(&fn, trace)) continue;

            u64 counter = args._counter == COUNTER_SAMPLES ? (*it)->samples : (*it)->counter;
            if (counter == 0) continue;

            int num_frames = trace->num_frames;

            Trie* f = flamegraph.root();
            if (args._reverse) {
                // Thread frames always come first
                if (_add_sched_frame) {
                    const char* frame_name = fn.name(trace->frames[--num_frames]);
                    f = flamegraph.addChild(f, frame_name, FRAME_NATIVE, counter);
                }
                if (_add_thread_frame) {
                    const char* frame_name = fn.name(trace->frames[--num_frames]);
                    f = flamegraph.addChild(f, frame_name, FRAME_NATIVE, counter);
                }

                for (int j = 0; j < num_frames; j++) {
                    const char* frame_name = fn.name(trace->frames[j]);
                    FrameTypeId frame_type = fn.type(trace->frames[j]);
                    f = flamegraph.addChild(f, frame_name, frame_type, counter);
                }
            } else {
                for (int j = num_frames - 1; j >= 0; j--) {
                    const char* frame_name = fn.name(trace->frames[j]);
                    FrameTypeId frame_type = fn.type(trace->frames[j]);
                    f = flamegraph.addChild(f, frame_name, frame_type, counter);
                }
            }
            f->_total += counter;
            f->_self += counter;
            printed_sample_count++;
        }
    }

    flamegraph.dump(out, tree);
    logEmptyOutput(args, printed_sample_count, out);
}

void Profiler::dumpText(Writer& out, Arguments& args) {
    FrameName fn(args, args._style | STYLE_DOTTED, _epoch, _thread_names_lock, _thread_names);
    char buf[1024] = {0};

    std::vector<CallTraceSample> samples;
    FrameIterator *fi;
    u64 total_counter = 0;
    {
        std::map<u64, CallTraceSample> map;
        _snapped_call_trace_storage->collectSamples(map);
        fi = new FrameIterator(map, _savedAwaitStacks);
        samples.reserve(map.size());

        for (std::map<u64, CallTraceSample>::const_iterator it = map.begin(); it != map.end(); ++it) {
            CallTrace* trace = it->second.trace;
            u64 counter = it->second.counter;
            if (trace == NULL || counter == 0) continue;

            total_counter += counter;
            if (trace->num_frames == 0 || excludeTrace(&fn, trace)) continue;
            samples.push_back(it->second);
        }
    }

    // Print summary
    snprintf(buf, sizeof(buf) - 1,
            "--- Execution profile ---\n"
            "Total samples       : %lld\n",
            _total_samples);
    out << buf;

    double spercent = 100.0 / _total_samples;
    for (int i = 1; i < ASGCT_FAILURE_TYPES; i++) {
        const char* err_string = asgctError(-i);
        if (err_string != NULL && _failures[i] > 0) {
            snprintf(buf, sizeof(buf), "%-20s: %lld (%.2f%%)\n", err_string, _failures[i], _failures[i] * spercent);
            out << buf;
        }
    }
    out << "\n";

    double cpercent = 100.0 / total_counter;
    const char* units_str = activeEngine()->units();

    // Print top call stacks
    if (args._dump_traces > 0) {
        std::sort(samples.begin(), samples.end(), [](const CallTraceSample& a, const CallTraceSample& b) {
            return a.counter > b.counter;
        });

        int max_count = args._dump_traces;
        for (std::vector<CallTraceSample>::const_iterator it = samples.begin(); it != samples.end() && --max_count >= 0; ++it) {
            snprintf(buf, sizeof(buf) - 1, "--- %lld %s (%.2f%%), %lld sample%s\n",
                     it->counter, units_str, it->counter * cpercent,
                     it->samples, it->samples == 1 ? "" : "s");
            out << buf;

            CallTrace* trace = it->trace;
            fi->set(trace, false);
            ASGCT_CallFrame* aframe;
            int j = 0;
            while((aframe = fi->next())) {
                const char* frame_name = fn.name(*aframe);
                snprintf(buf, sizeof(buf) - 1, "  [%2d] %s\n", j++, frame_name);
                out << buf;
            }
            out << "\n";
        }
    }

    // Print top methods
    if (args._dump_flat > 0) {
        std::map<std::string, MethodSample> histogram;
        for (std::vector<CallTraceSample>::const_iterator it = samples.begin(); it != samples.end(); ++it) {
            const char* frame_name = fn.name(it->trace->frames[0]);
            histogram[frame_name].add(it->samples, it->counter);
        }

        std::vector<NamedMethodSample> methods(histogram.begin(), histogram.end());
        std::sort(methods.begin(), methods.end(), sortByCounter);

        snprintf(buf, sizeof(buf) - 1, "%12s  percent  samples  top\n"
                                       "  ----------  -------  -------  ---\n", units_str);
        out << buf;

        int max_count = args._dump_flat;
        for (std::vector<NamedMethodSample>::const_iterator it = methods.begin(); it != methods.end() && --max_count >= 0; ++it) {
            snprintf(buf, sizeof(buf) - 1, "%12lld  %6.2f%%  %7lld  %s\n",
                     it->second.counter, it->second.counter * cpercent, it->second.samples, it->first.c_str());
            out << buf;
        }
    }
}

time_t Profiler::addTimeout(time_t start, int timeout) {
    if (timeout == 0) {
        return (time_t)0x7fffffff;
    } else if (timeout > 0) {
        return start + timeout;
    }

    struct tm t;
    localtime_r(&start, &t);

    int hh = (timeout >> 16) & 0xff;
    if (hh < 24) {
        t.tm_hour = hh;
    }
    int mm = (timeout >> 8) & 0xff;
    if (mm < 60) {
        t.tm_min = mm;
    }
    int ss = timeout & 0xff;
    if (ss < 60) {
        t.tm_sec = ss;
    }

    time_t result = mktime(&t);
    if (result <= start) {
        result += (hh < 24 ? 86400 : (mm < 60 ? 3600 : 60));
    }
    return result;
}

void Profiler::startTimer() {
    if (VM::loaded()) {
        JNIEnv* jni = VM::jni();
        jclass Thread = jni->FindClass("java/lang/Thread");
        jmethodID init = jni->GetMethodID(Thread, "<init>", "(Ljava/lang/String;)V");
        jmethodID setDaemon = jni->GetMethodID(Thread, "setDaemon", "(Z)V");

        jstring name = jni->NewStringUTF("Async-profiler Timer");
        if (name != NULL && init != NULL && setDaemon != NULL) {
            jthread thread_obj = jni->NewObject(Thread, init, name);
            if (thread_obj != NULL) {
                jni->CallVoidMethod(thread_obj, setDaemon, JNI_TRUE);
                MutexLocker ml(_timer_lock);
                _timer_id = (void*)(intptr_t)(0x80000000 | _epoch);
                if (VM::jvmti()->RunAgentThread(thread_obj, jvmtiTimerEntry, _timer_id, JVMTI_THREAD_NORM_PRIORITY) == 0) {
                    return;
                }
                _timer_id = NULL;
            }
        }

        jni->ExceptionDescribe();
    } else {
        // If profiling a native app, start a raw pthread instead of a JVM thread
        MutexLocker ml(_timer_lock);
        _timer_id = (void*)(intptr_t)(0x80000000 | _epoch);
        pthread_t thread;
        if (pthread_create(&thread, NULL, pthreadTimerEntry, _timer_id) == 0) {
            pthread_detach(thread);
            return;
        }
        _timer_id = NULL;
    }
}

void Profiler::stopTimer() {
    MutexLocker ml(_timer_lock);
    if (_timer_id != NULL) {
        _timer_id = NULL;
        _timer_lock.notify();
    }
}

void Profiler::timerLoop(void* timer_id) {
    u64 current_micros = OS::micros();
    u64 stop_micros = _stop_time * 1000000ULL;
    u64 sleep_until = _jfr.active() ? current_micros + 1000000 : stop_micros;

    while (true) {
        {
            // Release _timer_lock after sleep to avoid deadlock with Profiler::stop
            MutexLocker ml(_timer_lock);
            while (_timer_id == timer_id && !_timer_lock.waitUntil(sleep_until)) {
                // timeout not reached
            }
            if (_timer_id != timer_id) return;
        }

        if ((current_micros = OS::micros()) >= stop_micros) {
            restart(_global_args);
            return;
        }

        bool need_switch_chunk = _jfr.timerTick(current_micros, _gc_id);
        if (need_switch_chunk) {
            // Flush under profiler state lock
            flushJfr();
        }

        sleep_until = current_micros + 1000000;
    }
}

void Profiler::logEmptyOutput(Arguments& args, u64 printed_samples_count, Writer& out) {
    if (!out.good()) {
        Log::warn("Output file may be incomplete");
        return;
    }
    if (args._loop) {
        return;
    }
    if (_total_samples - _failures[-ticks_skipped] == 0) {
        Log::info("No samples were collected");
        return;
    }
    if (printed_samples_count == 0) {
        Log::info("All samples were filtered out");
        return;
    }
}

Error Profiler::runInternal(Arguments& args, Writer& out) {
    switch (args._action) {
        case ACTION_START:
        case ACTION_RESUME: {
            Error error = start(args, args._action == ACTION_START);
            if (error) {
                return error;
            }
            if (!args._quiet) {
                out << "Profiling started\n";
            }
            break;
        }
        case ACTION_STOP_JEMALLOC: {
            stop_jemalloc();
            break;
        }
        case ACTION_STOP: {
            Error error = stop();
            if (args._output == OUTPUT_NONE) {
                if (error) {
                    return error;
                }
                if (!args._quiet) {
                    out << "Profiling stopped after " << uptime() << " seconds. No dump options specified\n";
                }
                break;
            }
            // Fall through
        }
        case ACTION_DUMP: {
            Error error = dump(out, args);
            if (error) {
                return error;
            }
            break;
        }
        case ACTION_CHECK: {
            Error error = check(args);
            if (error) {
                return error;
            }
            out << "OK\n";
            break;
        }
        case ACTION_STATUS: {
            MutexLocker ml(_state_lock);
            if (_state == RUNNING) {
                out << "Profiling is running for " << uptime() << " seconds\n";
            } else {
                out << "Profiler is not active\n";
            }
            break;
        }
        case ACTION_MEMINFO: {
            MutexLocker ml(_state_lock);
            printUsedMemory(out);
            break;
        }
        case ACTION_LIST: {
            out << "Basic events:\n";
            out << "  " << EVENT_CPU << "\n";
            out << "  " << EVENT_ALLOC << "\n";
            out << "  " << EVENT_NATIVEMEM << "\n";
            out << "  " << EVENT_LOCK << "\n";
            out << "  " << EVENT_WALL << "\n";
            out << "  " << EVENT_ITIMER << "\n";
            if (CTimer::supported()) {
                out << "  " << EVENT_CTIMER << "\n";
            }

            out << "Java method calls:\n";
            out << "  ClassName.methodName\n";

            if (PerfEvents::supported()) {
                out << "Perf events:\n";
                for (int event_id = 0; ; event_id++) {
                    const char* event_name = PerfEvents::getEventName(event_id);
                    if (event_name == NULL) break;
                    out << "  " << event_name << "\n";
                }
            }
            break;
        }
        case ACTION_VERSION:
            out << PROFILER_VERSION;
            break;
        default:
            break;
    }
    return Error::OK;
}

Error Profiler::run(Arguments& args) {
    if (!args.hasOutputFile()) {
        LogWriter out;
        return runInternal(args, out);
    } else {
        // Open output file under the lock to avoid races with background timer
        MutexLocker ml(_state_lock);
        AtomicOutputFile out(args);
        if (!out.is_open()) {
            return Error("Could not open output file");
        }
        return runInternal(args, out);
    }
}

Error Profiler::restart(Arguments& args) {
    MutexLocker ml(_state_lock);

    Error error = stop(args._loop);
    if (error) {
        return error;
    }

    if (args._file != NULL && args._output != OUTPUT_NONE && args._output != OUTPUT_JFR) {
        AtomicOutputFile out(args);
        if (!out.is_open()) {
            return Error("Could not open output file");
        }
        error = dump(out, args);
        if (error) {
            return error;
        }
    }

    if (args._loop) {
        args._fdtransfer = false;  // keep the previous connection
        args._file_num++;
        return start(args, true);
    }

    return Error::OK;
}

void Profiler::shutdown(Arguments& args) {
    MutexLocker ml(_state_lock);

    // The last chance to dump profile before VM terminates
    if (_state == RUNNING) {
        args._action = ACTION_STOP;
        Error error = run(args);
        if (error) {
            Log::error("%s", error.message());
        }
    }

    _state = TERMINATED;
}

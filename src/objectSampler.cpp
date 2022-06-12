/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <atomic>
#include "objectSampler.h"
#include "profiler.h"
#include "tsc.h"


u64 ObjectSampler::_interval;
u64 ObjectSampler::_nativeInterval;
bool ObjectSampler::_live;
bool ObjectSampler::_persist;
volatile u64 ObjectSampler::_allocated_bytes;

static volatile bool native_enabled;

static u32 lookupClassId(jvmtiEnv* jvmti, jclass cls) {
    u32 class_id = 0;
    char* class_name;
    if (jvmti->GetClassSignature(cls, &class_name, NULL) == 0) {
        if (class_name[0] == 'L') {
            class_id = Profiler::instance()->classMap()->lookup(class_name + 1, strlen(class_name) - 2);
        } else {
            class_id = Profiler::instance()->classMap()->lookup(class_name);
        }
        jvmti->Deallocate((unsigned char*)class_name);
    }
    return class_id;
}


class LiveRefs {
  private:
    enum { MAX_REFS = 1024 };
    bool _persist;
    SpinLock _lock;
    SpinLock _nativeLock;
    jweak _refs[MAX_REFS];

    struct {
        jlong size;
        u64 trace;
        u64 time;
        u64 hash;
        bool published;
    } _values[MAX_REFS];
    bool _full;

    // Corresponding storage for native address pointers
    u32 _max_native_addrs = MAX_REFS;  // number of unfreed address slots
    u32 _max_native_resizes = 8;  // double the above this many times
    u32 _num_stored_addrs = 0;    // actual number currently stored
    u32 _last_native_alloc = 0;   // index of most recent alloc
    const void** _addrs;
    typedef struct {
        size_t size;
        u64 trace;
        u64 time;
        u64 hash;
        bool published;
    } NativeValue;
    NativeValue *_native_values;
    
    static inline bool collected(jweak w) {
        return *(void**)((uintptr_t)w & ~(uintptr_t)1) == NULL;
    }

    // The usual golden ratio drill.
    u32 addr2index(const void *addr) {
        u64 h = (u64) addr;
        h *= 0x9E3779B97F4A7C15L;
        h ^= h >> 32;
        h ^= (h >> 16);
        return h & (_max_native_addrs - 1);
    }
    
    // Called under lock - releases lock if successfully clears.
    bool record_native_free(u32 i, const void *addr) {
        if (_addrs[i] != addr) return false;
        // We only need to publish the free if we previously published the malloc.  Otherwise no harm done.
        if (_persist && _native_values[i].published) {
            Profiler::instance()->recordExternalSample(_native_values[i].size, "FreeNative", _native_values[i].hash);
        }
        _num_stored_addrs--;
        _addrs[i] = 0;
        _nativeLock.unlock();
        return true;
    }

    // Must be called under lock!
    void allocate_native_storage() {
        _addrs = (const void**) OS::safeAlloc(_max_native_addrs * sizeof(void*));
        memset(_addrs, 0, _max_native_addrs * sizeof(void*));
        _native_values = (NativeValue*) OS::safeAlloc(_max_native_addrs * sizeof(NativeValue));
        memset(_native_values, 0, _max_native_addrs * sizeof(NativeValue));
    }
    // Must be called under lock!
    void resize_native_storage() {
        if (_max_native_resizes) {
            _max_native_resizes--;
            u32 n = _max_native_addrs;
            _max_native_addrs *= 2;
            // Move all entries to their new positions
            _last_native_alloc = addr2index(_addrs[_last_native_alloc]);
            auto addrTmp = _addrs;
            auto valueTmp = _native_values;
            allocate_native_storage();
            for (u32 i=0; i<n; i++) {
                auto addr = addrTmp[i];
                if (addr) {
                    u32 j = addr2index(addr);
                    _addrs[j] = addr;
                    _native_values[j] = valueTmp[i];
                }
            }
            OS::safeFree(addrTmp, sizeof(n * sizeof(void*)));
            OS::safeFree(valueTmp, sizeof(n*sizeof(NativeValue)));
            Log::info("Alloc: resized to %d", _max_native_addrs);
        } else {
            Log::error("Alloc: too many resizes, disabling!");
            native_enabled = false;
        }
    }

  public:
    // Note that the _nativeLock starts out unlocked, since jemalloc needs to record malloc/free
    // whether or not liveref sampling has started.  See comments in add(const void* addr ...) too.
    LiveRefs() : _lock(1), _nativeLock(0) {
        allocate_native_storage();
    }

    void init(bool persist) {
        _persist = persist;
        if (!persist) {
            memset(_refs, 0, sizeof(_refs));
            memset(_values, 0, sizeof(_values));
        }
        _full = false;

        _lock.unlock();
    }

    void gc() {
        _full = false;
    }

    void add(const void *addr, size_t size, bool isFree, u64 trace, u64 tag) {
         {
            u32 tries = 0;
             if (isFree) {
                 // If we missed a free, the corresponding alloc entry in _addrs would never
                 // be cleared, so we must take a full blocking lock here.  We don't have that problem
                 // with heap objects, because their weak refs would eventually get cleared on their
                 // own.
                 _nativeLock.lock();  // i.e. not tryLock
                 // Commonly, we will see an allocation and then immediately its free, so optimize for this
                 // case.  (Note that this does not mean there weren`t intervening allocations, just that
                 // they weren't sampled.
                 if (record_native_free(_last_native_alloc, addr)) return;
                 u32 start = addr2index(addr), i=start;
                 do {
                    tries += 1;
                    if (record_native_free(i, addr)) {
                        if (tries > 100)
                            Log::warn("Free: addr=%x tries=%d", addr, start, tries);
                        return;
                    }
                } while ((i = (i + 1) & (_max_native_addrs - 1)) != start);
                _nativeLock.unlock();
                Log::warn("Free: Unable to find %x!", addr);
                return;
            }
            else if (addr) {
                if (!_nativeLock.tryLock())
                    return;
                 u32 start = addr2index(addr), i=start;
                 do {
                    tries += 1;
                    if (!_addrs[i]) {
                        _num_stored_addrs++;
                        _last_native_alloc = i;
                        _addrs[i] = addr;
                        _native_values[i].size = size;
                        _native_values[i].trace = trace;
                        _native_values[i].time = TSC::ticks();
                        _native_values[i].hash = tag;
                        _native_values[i].published = false;

                        if(_num_stored_addrs > _max_native_addrs / 2)
                            resize_native_storage();

                        _nativeLock.unlock();
                        if (tries > 100)
                            Log::warn("Alloc: addr=%x start=%d tries=%d", addr, start, tries);
                        return;
                    }
                } while ((i = (i + 1) & (_max_native_addrs - 1)) != start);
                native_enabled = false;
                _nativeLock.unlock();
                Log::error("Alloc: Out of storage space!", addr);
            } else {
                Log::warn("Weird, addr=0");
            }
         }
    }

    void add(JNIEnv* jni, jobject object, jlong size, u64 trace, u64 tag) {
        if (_full) {
            return;
        }

        jweak wobject = jni->NewWeakGlobalRef(object);
        if (wobject == NULL) {
            return;
        }

        if (_lock.tryLock()) {
            u32 start = (((uintptr_t)object >> 4) * 31 + ((uintptr_t)jni >> 4) + trace) & (MAX_REFS - 1);
            u32 i = start;
            do {
                jweak w = _refs[i];
                if (w == NULL || collected(w)) {
                    if (w != NULL) {
                        jni->DeleteWeakGlobalRef(w);
                        if (_persist && _values[i].published) {
                            // We've already published the allocation.  Now publish the deallocation.  The stack is no
                            // longer in call trace storage, so we publish a stub, which includes the identifying hash.
                            Profiler::instance()->recordExternalSample(_values[i].size, "Free", _values[i].hash);
                        }
                    }
                    _refs[i] = wobject;
                    _values[i].size = size;
                    _values[i].trace = trace;
                    _values[i].time = TSC::ticks();
                    _values[i].hash = tag;
                    _values[i].published = false;
                    _lock.unlock();
                    return;
                }
            } while ((i = (i + 1) & (MAX_REFS - 1)) != start);

            _full = true;
            _lock.unlock();
        }

        jni->DeleteWeakGlobalRef(wobject);
        return;
    }

    // Dump unpublished allocations into stack storage.
    void dump(JNIEnv* jni) {

        jvmtiEnv* jvmti = VM::jvmti();
        Profiler* profiler = Profiler::instance();

        _lock.lock();
        for (u32 i = 0; i < MAX_REFS; i++) {
            if ((i % 32) == 0) jni->PushLocalFrame(64);

            jweak w = _refs[i];
            if (w != NULL) {
                jobject obj = jni->NewLocalRef(w);
                if (obj != NULL) {
                    // object still exists
                    if (!_persist || !_values[i].published) {
                        // need to publish the initial allocation
                        LiveObject event;
                        event._alloc_size = _values[i].size;
                        event._alloc_time = _values[i].time;
                        event._class_id = lookupClassId(jvmti, jni->GetObjectClass(obj));
                        int tid = _values[i].trace >> 32;
                        u32 call_trace_id = (u32) _values[i].trace;
                        // This will augment the counter of the stack we stored (with zero count) at the initial
                        // allocation.
                        profiler->recordExternalSample(event._alloc_size, tid, LIVE_OBJECT, &event, call_trace_id);
                        _values[i].published = true;
                        if (!_persist) {
                            // Won't need this anymore for the next sampling cycle
                            jni->DeleteWeakGlobalRef(w);
                            _refs[i] = 0;
                        } // otherwise, keep the reference around so we can (possibly) send a Free event
                    }
                } else {
                    // Object is gone.
                    jni->DeleteWeakGlobalRef(w);
                    _refs[i] = 0;
                    if (_persist && _values[i].published) {
                        // We've already published the allocation.  Now publish the deallocation.  The stack is no
                        // longer in call trace storage, so we publish a stub, which includes the identifying hash.
                        // If we hadn't published, then we just ignore this allocation, since it was made and freed
                        // during the same cycle.
                        profiler->recordExternalSample(_values[i].size, "Free", _values[i].hash);
                    }
                }
            }

            if ((i % 32) == 31 || i == MAX_REFS - 1) jni->PopLocalFrame(NULL);
        }

        _nativeLock.lock();
        for (u32 i = 0; i < _max_native_addrs; i++) {
            if (_addrs[i]) {
                if (!_native_values[i].published) {
                    int tid = _native_values[i].trace >> 32;
                    u32 call_trace_id = (u32) _native_values[i].trace;
                    profiler->recordExternalSample(_native_values[i].size, tid, LIVE_OBJECT, 0, call_trace_id);
                    _native_values[i].published = true;
                    if (!_persist)
                        _addrs[0] = 0;
                }
            }
        }
        _nativeLock.unlock();
    }
};

static LiveRefs live_refs;

void ObjectSampler::SampledObjectAlloc(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                       jobject object, jclass object_klass, jlong size) {
    if (_enabled) {
        recordAllocation(jvmti, jni, ALLOC_SAMPLE, object, object_klass, size);
    }
}

void ObjectSampler::NativeAlloc(const void *addr, size_t size, bool isFree) {
    if (_enabled)
        recordAllocation(addr, size, isFree);
}

void ObjectSampler::GarbageCollectionStart(jvmtiEnv* jvmti) {
    live_refs.gc();
}

void ObjectSampler::recordAllocation(const void* addr, size_t size, bool isFree) {
    if (_live && native_enabled) {
        jlong tsize = size > _nativeInterval ? size : _nativeInterval;
        u64 tag = 0;
        u64 trace = Profiler::instance()->recordSample(NULL, 0, NATIVE_ALLOC, 0, &tag);
        live_refs.add(addr, tsize, isFree, trace, tag);
    }
}

void ObjectSampler::recordAllocation(jvmtiEnv* jvmti, JNIEnv* jni, EventType event_type,
                                     jobject object, jclass object_klass, jlong size) {
    AllocEvent event;
    jlong tsize = size > _interval ? size : _interval;
    event._total_size = tsize;
    event._instance_size = size;
    event._class_id = lookupClassId(jvmti, object_klass);

    if (_live) {
        u64 tag = 0;
        u64 trace = Profiler::instance()->recordSample(NULL, 0, event_type, &event, &tag);
        live_refs.add(jni, object, tsize, trace, tag);
    } else {
        Profiler::instance()->recordSample(NULL, event._total_size, event_type, &event);
    }
}

void ObjectSampler::initLiveRefs(bool live, bool persist) {
    _live = live;
    _persist = persist;
    if (_live) {
        live_refs.init(persist);
    }
}

void ObjectSampler::dumpLiveRefs() {
    if (_live) {
        live_refs.dump(VM::jni());
    }
}

Error ObjectSampler::check(Arguments& args) {
    if (!VM::canSampleObjects()) {
        return Error("SampledObjectAlloc is not supported on this JVM");
    }
    return Error::OK;
}

typedef void (*prof_backtrace_hook_t)(void **, unsigned *, unsigned);
/* ptr, size, backtrace vector, backtrace vector length */
typedef void (*prof_sample_hook_t)(const void *, size_t, void **, unsigned);
/* ptr, size */
typedef void (*prof_sample_free_hook_t)(const void *, size_t);
typedef int (*mallctl_t)(const char *name, void *oldp,  size_t *oldlenp, void *newp, size_t newlen);

static void stubBTHook(void **, unsigned *, unsigned) {
    return;
}

static void sampleHook(const void * ptr, size_t sz, void ** bt, unsigned btlen) {
    ObjectSampler::NativeAlloc(ptr, sz, false);
}
static void freeHook(const void * ptr, size_t sz) {
    ObjectSampler::NativeAlloc(ptr, sz, true);
}


static mallctl_t mallctl_ptr;
static volatile bool attemptedToSetJemallocHooks = false;
static int mallctl(const char *name, void *oldp,  size_t *oldlenp, void *newp, size_t newlen) {
    if (!mallctl_ptr)
        mallctl_ptr = (mallctl_t) dlsym(RTLD_DEFAULT, "mallctl");
    if (mallctl_ptr) {
        int ret = (*mallctl_ptr)(name, oldp, oldlenp, newp, newlen);
        Log::info("mallctl %s returns %d", name, ret);
        return ret;
    } else {
        Log::warn("mallctl is unavailable; %s not invoked", name);
        return -1;
    }
}


static int setBTHook(prof_backtrace_hook_t hook) {
    size_t sz = sizeof(hook);
    return mallctl("experimental.hooks.prof_sample", NULL, &sz, &hook, sz);
}
static int setSampleHook(prof_sample_hook_t hook) {
    size_t sz = sizeof(hook);
    return mallctl("experimental.hooks.prof_sample", NULL, &sz, &hook, sz);
}
static int setSampleFreeHook(prof_sample_free_hook_t hook) {
    size_t sz = sizeof(hook);
    return mallctl("experimental.hooks.prof_sample_free", NULL, &sz, &hook, sz);
}

Error ObjectSampler::start(Arguments& args) {
    Error error = check(args);
    if (error) {
        return error;
    }

    _interval = args._alloc > 0 ? args._alloc : DEFAULT_ALLOC_INTERVAL;

    // Try first to set the boring backtrace hook; if this fails, we won't bother with
    // anything else.
    if(!attemptedToSetJemallocHooks && !setBTHook(stubBTHook)) {
        attemptedToSetJemallocHooks = true;
        native_enabled = true;
        {
            size_t log_sample = 0;
            size_t sz = sizeof(log_sample);
            // Must start with jemalloc and 
            //    MALLOC_CONF="prof:true,prof_active:false,lg_prof_sample:19"
            // so profiling is enabled but not yet started, and sample interval is set (log base 2).
            // The interval cannot be set once the program has started, but we here extract it so we
            // we can report a proper stack value.
            native_enabled &= !mallctl("opt.lg_prof_sample", &log_sample, &sz, NULL, 0);
            _nativeInterval = log_sample>0 ? 1 << log_sample : 0;
            Log::info("nativeInterval=%d", _nativeInterval);
            native_enabled &= (_nativeInterval > 0);
        }
        {
            bool flag = true;
            size_t sz = sizeof(flag);
            // Turn on sampling.
            native_enabled &= !mallctl("prof.active", NULL, &sz, &flag, sz);
        }
        native_enabled &= !setSampleFreeHook(freeHook);
        native_enabled &= !setSampleHook(sampleHook);
    }

    if(!native_enabled)
        Log::warn("Alloc: native memory profiling disabled.");

    initLiveRefs(args._live, args._eventtypeframes);

    jvmtiEnv* jvmti = VM::jvmti();
    jvmti->SetHeapSamplingInterval(_interval);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC, NULL);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_GARBAGE_COLLECTION_START, NULL);

    return Error::OK;
}

void ObjectSampler::stop() {
    jvmtiEnv* jvmti = VM::jvmti();
    jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_GARBAGE_COLLECTION_START, NULL);
    jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC, NULL);

    // We don't turn off native sampling ever, because missing free events would cause us to
    // accumulate orphan allocations.

    dumpLiveRefs();
}

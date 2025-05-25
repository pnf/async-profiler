/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <atomic>
#include "objectSampler.h"
#include "profiler.h"
#include "tsc.h"
#include <dlfcn.h> //MS


// MS: Anything with jemalloc in its name is ours...

u64 ObjectSampler::_interval;
u64 ObjectSampler::_jemallocInterval;
bool ObjectSampler::_live;
bool ObjectSampler::_persist;  // MS: data is persisted across sampling restarts
volatile u64 ObjectSampler::_allocated_bytes;

static volatile bool jemalloc_enabled;

// MS Failsafe: ensure no jemalloc sampling after 30 seconds of no object sampling
static volatile u64 lastJemallocSampleTime = 0;

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
    // MS: Storage is statically sized upstream.  We double up to 10 times
    enum { INIT_REFS = 1024 };
    int MAX_TRIES = 1000;
    bool _persist;
    SpinLock _lock;
    SpinLock _jemallocLock;

    u32 _max_refs = INIT_REFS;  // number of uncollected object slots
    int _max_ref_resizes = 10;  // double the above this many times
    u32 _num_stored_refs = 0;    // actual number currently stored
    jweak *_refs;
    typedef struct {
        jlong size;
        u64 trace;
        u64 time;
        u64 hash;  // MS: unique ID of allocation
        bool published;  // MS: has allocation been dumped yet
    } RefData;
    RefData* _values;
    bool _full;

    // MS: Storage for native allocations.
    u32 _max_jemalloc_addrs = INIT_REFS;  // number of unfreed address slots
    int _max_jemalloc_resizes = 10;  // double the above this many times
    u32 _num_stored_addrs = 0;    // actual number currently stored
    u32 _last_jemalloc_alloc = 0;   // index of most recent alloc
    const void** _addrs;
    typedef struct {
        size_t size;
        u64 trace;
        u64 time;
        u64 hash;
        bool published;
    } JEMallocValue;
    JEMallocValue *_jemalloc_values;

    static inline bool collected(jweak w) {
        return *(void**)((uintptr_t)w & ~(uintptr_t)1) == NULL;
    }

    // MS: The usual golden ratio drill.
    u32 addr2index(const void *addr) {
        u64 h = (u64) addr;
        h *= 0x9E3779B97F4A7C15L;
        h ^= h >> 32;
        h ^= (h >> 16);
        return h & (_max_jemalloc_addrs - 1);
    }

    // Called under lock - releases lock if successfully clears.
    bool record_jemalloc_free(u32 i, const void *addr) {
        if (_addrs[i] != addr) return false;
        // We only need to publish the free if we previously published the malloc.  Otherwise no harm done.
        if (_persist && _jemalloc_values[i].published) {
            Profiler::instance()->recordExternalSample(_jemalloc_values[i].size, "FreeNative", NULL, _jemalloc_values[i].hash);
        }
        _num_stored_addrs--;
        _addrs[i] = 0;
        _jemallocLock.unlock();
        return true;
    }

    // MS: for dynamic sizing of ref storage
    void allocate_ref_storage() {
        _refs = (jweak*) OS::safeAlloc(_max_refs * sizeof(jweak));
        memset(_refs, 0, _max_refs * sizeof(jweak));
        _values = (RefData*) OS::safeAlloc(_max_refs * sizeof(RefData));
        memset(_values,0,  _max_refs * sizeof(RefData));
    }
    // MS
    void resize_ref_storage() {
        if (_max_ref_resizes > 0) {
            _max_ref_resizes--;
            u32 n = _max_refs;
            _max_refs *= 2;
            auto refsTmp = _refs;
            auto valuesTmp = _values;
            allocate_ref_storage();
            // We never look up entries after adding them - just detect whether they're collected - so it doesn't
            // matter where we move them as long as they're sparse.
            for (u32 i=0; i<n; i++) {
                _refs[i*2] = refsTmp[i];
                _values[i*2] = valuesTmp[i];
            }
            OS::safeFree(refsTmp, n * sizeof(jweak));
            OS::safeFree(valuesTmp, n * sizeof(RefData));
        }
    }

    // Must be called under lock!
    void allocate_jemalloc_storage() {
        _addrs = (const void**) OS::safeAlloc(_max_jemalloc_addrs * sizeof(void*));
        memset(_addrs, 0, _max_jemalloc_addrs * sizeof(void*));
        _jemalloc_values = (JEMallocValue*) OS::safeAlloc(_max_jemalloc_addrs * sizeof(JEMallocValue));
        memset(_jemalloc_values, 0, _max_jemalloc_addrs * sizeof(JEMallocValue));
    }
    // Must be called under lock!
    void resize_jemalloc_storage() {
        if (_max_jemalloc_resizes > 0) {
            _max_jemalloc_resizes--;
            u32 n = _max_jemalloc_addrs;
            _max_jemalloc_addrs *= 2;
            // Move all entries to their new positions
            _last_jemalloc_alloc = addr2index(_addrs[_last_jemalloc_alloc]);
            auto addrTmp = _addrs;
            auto valueTmp = _jemalloc_values;
            allocate_jemalloc_storage();
            for (u32 i=0; i<n; i++) {
                auto addr = addrTmp[i];
                if (addr) {
                    u32 j = addr2index(addr);
                    _addrs[j] = addr;
                    _jemalloc_values[j] = valueTmp[i];
                }
            }
            OS::safeFree(addrTmp, n * sizeof(void*));
            OS::safeFree(valueTmp, n * sizeof(JEMallocValue));
            Log::info("Alloc: resized to %d", _max_jemalloc_addrs);
        } else {
            Log::error("Alloc: too many resizes, disabling!");
            jemalloc_enabled = false;
        }
    }

  public:
    // MS:
    // Note that the _jemallocLock starts out unlocked, since jemalloc needs to record malloc/free
    // whether or not liveref sampling has started.  See comments in add(const void* addr ...) too.
    LiveRefs() : _lock(1), _jemallocLock(0) {
        allocate_jemalloc_storage();
        allocate_ref_storage();
    }

    // MS: don't wipe ref storge if persist is set
    void init(bool persist) {
        _persist = persist;
        if (!persist) {
            memset(_refs, 0, _max_refs * sizeof(jweak));
            memset(_values, 0, _max_refs * sizeof(RefData));
        }
        _full = false;
        _lock.unlock();
    }

    void gc() {
        _full = false;
    }

    // MS: Private method to actually blow away storage.
    void clear() {
        // Will be called only in a stopped state, which means _jemallocLock is unlocked, but _lock is locked.

        _jemallocLock.lock();
        _num_stored_addrs = 0;
        _last_jemalloc_alloc = 0;
        // Retain storage, but clear it.
        memset(_addrs, 0, _max_jemalloc_addrs * sizeof(void*));
        memset(_jemalloc_values, 0, _max_jemalloc_addrs * sizeof(JEMallocValue));
        _jemallocLock.unlock();

        _num_stored_refs = 0;
        memset(_refs, 0, _max_refs * sizeof(jweak));
        memset(_values,0,  _max_refs * sizeof(RefData));
    }

    // MS: Record native allocation or free.
    // Return NULL if jemalloc allocation successfully tracked
    const char* add(const void *addr, size_t size, bool isFree, u64 trace, u64 tag) {
         {
             if (!addr) return NULL;
             u32 start = addr2index(addr), i=start, tries=0;
             if (isFree) {
                 // If we missed a free, the corresponding alloc entry in _addrs would never
                 // be cleared, so we must take a full blocking lock here.  We don't have that problem
                 // with heap objects, because their weak refs would eventually get cleared on their
                 // own.
                 _jemallocLock.lock();  // i.e. not tryLock
                 // Commonly, we will see an allocation and then immediately its free, so optimize for this
                 // case.  (Note that this does not mean there weren`t intervening allocations, just that
                 // they weren't sampled.
                 if (record_jemalloc_free(_last_jemalloc_alloc, addr)) return NULL;
                 do {
                    if (record_jemalloc_free(i, addr))
                        return NULL;
                    else if (tries++ > MAX_TRIES) {
                        _jemallocLock.unlock();
                        return "JEMallocFreeTries";
                    }
                 } while ((i = (i + 1) & (_max_jemalloc_addrs - 1)) != start);
                _jemallocLock.unlock();
                return "JEMallocFreeCorr";
            }
            else {
                if (!_jemallocLock.tryLock())
                    return "JEMallocLock";
                 do {
                    if (!_addrs[i]) {
                        _last_jemalloc_alloc = i;
                        _addrs[i] = addr;
                        _jemalloc_values[i].size = size;
                        _jemalloc_values[i].trace = trace;
                        _jemalloc_values[i].time = TSC::ticks();
                        _jemalloc_values[i].hash = tag;
                        _jemalloc_values[i].published = false;

                        if(_num_stored_addrs++ > _max_jemalloc_addrs / 2)
                            resize_jemalloc_storage();
                        _jemallocLock.unlock();
                        return NULL;
                    } else if (tries++ > MAX_TRIES) {
                        _jemallocLock.unlock();
                        return "JEMallocTries";
                    }
                 } while ((i = (i + 1) & (_max_jemalloc_addrs - 1)) != start);
                jemalloc_enabled = false;
                _jemallocLock.unlock();
                return "JEMallocSlots";
            }
         }
    }


    const char* // MS: Return NULL if heap object allocation successfully tracked
    add(JNIEnv* jni, jobject object, jlong size, u64 trace,
                    u64 tag) { // MS tag entries with unique id
        if (_full) {
            return "AllocFull"; // MS - return semi-meaningful error
        }

        jweak wobject = jni->NewWeakGlobalRef(object);
        if (wobject == NULL) {
            return NULL;  // we've done all we can
        }

        if (_lock.tryLock()) {
            u32 start = (((uintptr_t)object >> 4) * 31 + ((uintptr_t)jni >> 4) + trace) & (_max_refs - 1);
            u32 i = start;
            u32 tries = 0;
            do {
                jweak w = _refs[i];
                if (w == NULL || collected(w)) {
                    if (w != NULL) {
                        jni->DeleteWeakGlobalRef(w);
                        // MS:
                        if (_persist && _values[i].published) {
                            // We've already published the allocation.  Now publish the deallocation.  The stack is no
                            // longer in call trace storage, so we publish a stub, which includes the identifying hash.
                            Profiler::instance()->recordExternalSample(_values[i].size, "Free", NULL, _values[i].hash);
                        }
                    }
                    _refs[i] = wobject;
                    _values[i].size = size;
                    _values[i].trace = trace;
                    _values[i].time = TSC::ticks();
                    _values[i].hash = tag;  // MS
                    _values[i].published = false; // MS
                    if(_num_stored_refs++ > _max_refs / 2) // MS
                        resize_ref_storage();
                    _lock.unlock();
                    return NULL;
                } else if (tries++ > MAX_TRIES) {  // MS
                    _full = true;
                    _lock.unlock();
                    return "AllocTries";
                }
            } while ((i = (i + 1) & (_max_refs - 1)) != start);

            _full = true;
            _lock.unlock();
            return NULL;
        }

        jni->DeleteWeakGlobalRef(wobject);
        return "AllocLock";
    }

    // Dump unpublished allocations into stack storage.
    void dump(JNIEnv* jni) {
        _lock.lock();
        Profiler* profiler = Profiler::instance();

        // MS: might be called for non-java process for native memory profiling, so condition object ref
        // tracking on jvm.
        if (VM::loaded()) {
            jvmtiEnv* jvmti = VM::jvmti();
            // Reset counters before dumping to collect live objects only
            // MS: unless persisting
            if (!_persist)
                profiler->tryResetCounters();

            for (u32 i = 0; i < _max_refs; i++) {
                if ((i % 32) == 0) jni->PushLocalFrame(64);

                jweak w = _refs[i];
                if (w != NULL) {
                    jobject obj = jni->NewLocalRef(w);
                    if (obj != NULL) {
                        // object still exists
                        if (!_persist || !_values[i].published) {
                            // need to publish the initial allocation
                            LiveObject event;
                            event._start_time = TSC::ticks();
                            event._alloc_size = _values[i].size;
                            event._alloc_time = _values[i].time;
                            event._class_id = lookupClassId(jvmti, jni->GetObjectClass(obj));
                            int tid = _values[i].trace >> 32;
                            u32 call_trace_id = (u32) _values[i].trace;
                            // This will augment the counter of the stack we stored (with zero count) at the initial
                            // allocation.
                            profiler->recordExternalSample(event._alloc_size, LIVE_OBJECT, &event, _values[i].trace);
                            // upstream: profiler->recordExternalSamples(1, event._alloc_size, tid, call_trace_id, LIVE_OBJECT, &event);
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
                            profiler->recordExternalSample(_values[i].size, "Free", NULL, _values[i].hash);
                        }
                    }
                }

                if ((i % 32) == 31 || i == _max_refs - 1) jni->PopLocalFrame(NULL);
            }
        }

        _jemallocLock.lock();
        for (u32 i = 0; i < _max_jemalloc_addrs; i++) {
            if (_addrs[i]) {
                if (!_jemalloc_values[i].published) {
                    int tid = _jemalloc_values[i].trace >> 32;
                    u32 call_trace_id = (u32) _jemalloc_values[i].trace;
                    // Just ticking up counter on previously stored stack; event=0, so won't go to jfr, and type is irrelevant.
                    profiler->recordExternalSample(_jemalloc_values[i].size, tid, LIVE_OBJECT, NULL, call_trace_id);
                    _jemalloc_values[i].published = true;
                    if (!_persist)
                        _addrs[0] = 0;
                }
            }
        }
        _jemallocLock.unlock();
    }
};

static LiveRefs live_refs;

void ObjectSampler::SampledObjectAlloc(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                       jobject object, jclass object_klass, jlong size) {
    if (_enabled) {
        recordAllocation(jvmti, jni, ALLOC_SAMPLE, object, object_klass, size);
    }
}

void ObjectSampler::JEMalloc(const void *addr, size_t size, bool isFree) {
    if (_enabled)
        recordJEMalloc(addr, size, isFree);
}

void ObjectSampler::GarbageCollectionStart(jvmtiEnv* jvmti) {
    live_refs.gc();
}

void ObjectSampler::recordJEMalloc(const void* addr, size_t size, bool isFree) {
    if (_live && jemalloc_enabled) {
        if (lastJemallocSampleTime == 0 ||  OS::nanotime() < lastJemallocSampleTime) {
            jlong tsize = size > _jemallocInterval ? size : _jemallocInterval;
            u64 tag = 0;
            u64 trace = Profiler::instance()->recordSample(NULL, 0, JEMALLOC_SAMPLE, 0, &tag);
            const char *err = live_refs.add(addr, tsize, isFree, trace, tag);
            if (err) {
                Profiler::instance()->recordExternalSample(tsize, "Lost", err, 0);
                Log::warn("Unable to record jemalloc allocation of %ld, %s", isFree ? -tsize : size, err);
            }
        } else {
            Log::warn("Turning off jemalloc allocation after timeout.");
            jemallocShutdown();
        }
    }
}

void ObjectSampler::recordAllocation(jvmtiEnv* jvmti, JNIEnv* jni, EventType event_type,
                                     jobject object, jclass object_klass, jlong size) {
    AllocEvent event;
    event._start_time = TSC::ticks();
    event._total_size = size > _interval ? size : _interval;
    event._instance_size = size;
    event._class_id = lookupClassId(jvmti, object_klass);

    if (!_persist) {
        u64 trace = Profiler::instance()->recordSample(NULL, event._total_size, event_type, &event);
        if (_live && trace != 0) {
            live_refs.add(jni, object, size, trace, 0);
        }
    } else {
        if (_live) {
            u64 tag = 0;
            // Store a trace of zero size.  We'll increment only if it's still alive at dump time.
            u64 trace = Profiler::instance()->recordSample(NULL, 0, event_type, &event, &tag);
            const char *err = live_refs.add(jni, object, event._total_size, trace, tag);
            if (err) {
                Log::warn("Unable to record object allocation of %llu, %s", event._total_size, err);
                // Add to the lost allocation counter
                Profiler::instance()->recordExternalSample(event._total_size, "Lost", err, 0);
                // Increment count on the allocation, since it will otherwise not be reported
                Profiler::instance()->recordExternalSample(event._total_size, LIVE_OBJECT, 0, trace);
            }
        } else {
            Profiler::instance()->recordSample(NULL, event._total_size, event_type, &event);
        }
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

// MS: jemalloc hooks
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
    ObjectSampler::JEMalloc(ptr, sz, false);
}
static void freeHook(const void * ptr, size_t sz) {
    ObjectSampler::JEMalloc(ptr, sz, true);
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
    return mallctl("experimental.hooks.prof_backtrace", NULL, &sz, &hook, sz);
}
static int setSampleHook(prof_sample_hook_t hook) {
    size_t sz = sizeof(hook);
    return mallctl("experimental.hooks.prof_sample", NULL, &sz, &hook, sz);
}
static int setSampleFreeHook(prof_sample_free_hook_t hook) {
    size_t sz = sizeof(hook);
    return mallctl("experimental.hooks.prof_sample_free", NULL, &sz, &hook, sz);
}

bool ObjectSampler::checkJemallocEnabled() {
    if (!attemptedToSetJemallocHooks) {
        attemptedToSetJemallocHooks = true;
        jemalloc_enabled = !setBTHook(stubBTHook);
        if (jemalloc_enabled) {
            size_t log_sample = 0;
            size_t sz = sizeof(log_sample);
            // Must start with jemalloc and
            //    MALLOC_CONF="prof:true,prof_active:false,lg_prof_sample:19"
            // so profiling is enabled but not yet started, and sample interval is set (log base 2).
            // The interval cannot be set once the program has started, but we here extract it so we
            // we can report a proper stack value.
            jemalloc_enabled &= !mallctl("opt.lg_prof_sample", &log_sample, &sz, NULL, 0);
            _jemallocInterval = log_sample>0 ? 1 << log_sample : 0;
            Log::info("jemallocInterval=%llu", _jemallocInterval);
            jemalloc_enabled &= (_jemallocInterval > 0);
        }
        if (jemalloc_enabled) {
            bool flag = true;
            size_t sz = sizeof(flag);
            // Turn on sampling.
            jemalloc_enabled &= !mallctl("prof.active", NULL, &sz, &flag, sz);
        }
        jemalloc_enabled &= !setSampleFreeHook(freeHook);
        jemalloc_enabled &= !setSampleHook(sampleHook);
    }
    if(!jemalloc_enabled)
        Log::warn("Alloc: jemalloc memory profiling disabled.");
    return jemalloc_enabled;
}

Error ObjectSampler::start(Arguments& args) {
    lastJemallocSampleTime = 0;

    jemalloc_enabled = args._jemalloc && checkJemallocEnabled();

    _interval = args._alloc > 0 ? args._alloc : DEFAULT_ALLOC_INTERVAL;

    initLiveRefs(args._live, args._persist);

    if (VM::loaded()) {
        jvmtiEnv * jvmti = VM::jvmti();
        jvmti->SetHeapSamplingInterval(_interval);
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC, NULL);
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_GARBAGE_COLLECTION_START, NULL);
    }
    return Error::OK;
}

void ObjectSampler::jemallocShutdown() {
    if (jemalloc_enabled) {
        jemalloc_enabled = false;
        attemptedToSetJemallocHooks = false;
        lastJemallocSampleTime = 0;
        bool flag = false;
        size_t sz = sizeof(flag);
        mallctl("prof.active", NULL, &sz, &flag, sz);
        setBTHook((prof_backtrace_hook_t) NULL);
        setSampleFreeHook((prof_sample_free_hook_t) NULL);
        setSampleHook((prof_sample_hook_t) NULL);
        live_refs.clear();
    }
}

void ObjectSampler::stop() {
    if (VM::loaded()) {
        jvmtiEnv* jvmti = VM::jvmti();
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_GARBAGE_COLLECTION_START, NULL);
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC, NULL);

        VM::releaseSampleObjectsCapability();
    }
    // We don't turn off jemalloc sampling immediately if we might re-enable sampling, because missing free events would cause us to
    // accumulate orphan allocations.  Ideally the client calls stop_jemalloc when
    // completely done sampling, but, if they don't, we have a 30 second timeout.
    lastJemallocSampleTime = OS::nanotime() + 30L*1000L*1000L*1000L;

    dumpLiveRefs();
}

void ObjectSampler::stop_jemalloc() {
    jemallocShutdown();
}

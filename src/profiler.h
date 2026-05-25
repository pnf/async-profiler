/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PROFILER_H
#define _PROFILER_H

#include <map>
#include <string>
#include <time.h>
#include "arch.h"
#include "arguments.h"
#include "callTraceStorage.h"
#include "codeCache.h"
#include "dictionary.h"
#include "engine.h"
#include "event.h"
#include "flightRecorder.h"
#include "log.h"
#include "mutex.h"
#include "spinLock.h"
#include "threadFilter.h"
#include "trap.h"
#include "vmEntry.h"
#include "writer.h"
#include "queue/blockingconcurrentqueue.h"


const int MAX_NATIVE_FRAMES = 128;
const int RESERVED_FRAMES   = 10;  // for synthetic frames
const int CONCURRENCY_LEVEL = 16;

union CallTraceBuffer {
    ASGCT_CallFrame _asgct_frames[1];
    jvmtiFrameInfo _jvmti_frames[1];
};


class FrameName;
class NMethod;
class StackContext;

enum State {
    NEW,
    IDLE,
    RUNNING,
    TERMINATED
};

enum AwaitFrameType {
  AW_METHOD =1,
  AW_STRING =2
};

// Iterates over frames with (potentially) inserted await stacks
class FrameIterator {
private:
  static const int MAX_DEPTH = 50;
  CallTrace* traceStack[MAX_DEPTH];
  int positionStack[MAX_DEPTH];
  std::map<jmethodID, CallTrace*> awaitTraces;
  int depth = 0;
  int i = 0;
  bool hasAwaits = false;
  void addAwaitTrace(CallTrace* trace) {
    if(trace->frames[0].bci == BCI_AWAIT_MARKER) {
        awaitTraces[trace->frames[0].method_id] = trace;
        hasAwaits = true;
    }
  }
public:
  FrameIterator(std::vector<CallTraceSample*> &samples, bool savedAwaitStacks);
  FrameIterator(std::vector<CallTraceSample> &samples, bool savedAwaitStacks);
  FrameIterator(std::map<long long unsigned int, CallTraceSample> &samples, bool savedAwaitStacks);
  void set(CallTrace* trace_, bool reversed, int ignore_last = 0);
  int setAndCount(CallTrace* trace_, bool reversed, int ignore_last = 0);
  ASGCT_CallFrame* prev();
  ASGCT_CallFrame* next();
};

static const int MAX_AWAIT_STACKS = 10;

// Post stack-saving registration does not require allocation.
// Subclasses should contain neither data members nor virtual methods.
typedef void (*sc_run_t)(u64* data, u64 trace, u64 tag);
typedef void (*sc_free_t)(u64* data);
class Registration {
private:
    u64 data[3];
    sc_run_t _run;
    sc_free_t _clean;
public:
    Registration() : _run(NULL), _clean(NULL) {}
    Registration(u64 d1, u64 d2, u64 d3, sc_run_t run_, sc_free_t free_) : data{d1, d2, d3}, _run(run_), _clean(free_) {}
    // Called after stack trace has been stored.  Run out of lock sampling lock.
    void run(u64 trace, u64 tag) {
        if(_run) _run(data, trace, tag);
    }
    // To be called if recordSample returns zero, which means that run was never called.
    void clean() {
        if(_clean) _clean(data);
    }
};

#define AD_STACK_SAMPLED 1L
#define AD_STACK_SAVED 2L

struct AwaitData {
    // The order of fields is important if getAwaitDataAddress() is used.
    // When sampling occurs, we will search for a method_id == insertionId.
    // Starting from the innermost frame, we replace matching ids with successive
    // elements of stackId.
    // And we put the value expectedIndicator into sampledIndicator
    long targetMethodId;      // 0
    long expectedIndicator;   // 1
    long sampledIndicator;    // 2
    volatile long flags;      // 3
    volatile long thread_id;  // 4
    long java_stack_id;       // 5
    long java_stack_hash;     // 6
    long parent_await_data;   // 7
    long await_stack_ids[MAX_AWAIT_STACKS+1]; // 8
    const char* debugInfo;
    jthread weak_thread_ref;   // weak ref to corresponding virtual thread
    union {
        AwaitData* mounted_await_data = nullptr;  // if this is a platform thread
        AwaitData* next_await_data;     // if an entry in the map
        struct {
            int lock;
            volatile int depth;
        };
    };
    bool sample() volatile {
        long f;
        do {
            f = flags;
        } while (__sync_val_compare_and_swap(&flags, f, f | AD_STACK_SAMPLED) != f);
        return (f & (AD_STACK_SAMPLED|AD_STACK_SAVED)) == AD_STACK_SAMPLED;
    }

    void unsave() volatile {
        long f;
        do {
            f = flags;
        } while (__sync_val_compare_and_swap(&flags, f, f & ~AD_STACK_SAVED) != f);
    }

    AwaitData* parentAwaitData() volatile {
        return (AwaitData*) parent_await_data;
    }

};

struct Stats {
    long _enqueued = 0L;
    long _enqueueFail = 0L;
    long _stitched = 0L;
    long _stitchFail = 0L;
    long _chained = 0L;
    long _chainFail = 0L;
    long _vtMapLinks = 0L;
    long _vtMapEntries = 0L;
    long _vtMapInsertions = 0L;
    long _vtMapContended = 0L;
    long _vtMapDepthInsertions = 0L;
    long _vtMapMisses = 0L;
    long _vtMapHits = 0L;
    long _vtMounts = 0L;
    long _vtEnds = 0L;
    long _protected = 0L;
    Stats diff(Stats& prev) {
        Stats d;
        for (int i=0; i<sizeof(Stats)/sizeof(long); i++)
            ((long*)&d)[i] = ((long*) this)[i] - ((long*)&prev)[i];
        prev = *this;
        return d;
    }
};


struct Deferred {
    ASGCT_CallFrame frames[DEFAULT_JSTACKDEPTH]{}; // frames captured from signal callback
    AwaitData await_data{};               // await data for captured thread
    jthread sampled_thread_ref{};
    JNIEnv* jniEnv{};
    u64 counter{};
    EventType event_type = (EventType) 0;
    Event event;
    int first_java_frame{};
    int num_frames{};
    Registration registration;
    bool needsTag{};
    bool isContinuation{};
};

typedef moodycamel::BlockingConcurrentQueue<Deferred>::producer_token_t producer_token_t;
typedef moodycamel::BlockingConcurrentQueue<Deferred>::consumer_token_t consumer_token_t;

enum GlobalFlags {
    GF_NONE = 0,
    GF_NO_SHUTDOWN = 1
};

enum AwaitMapAction {
    AWAIT_MAP_ACTION_FIND_OR_CLAIM = 0,
    AWAIT_MAP_ACTION_FIND_CREATE = 1,
    AWAIT_MAP_ACTION_REMOVE = 2
};

class Profiler {
  private:
    Mutex _state_lock;
    State _state;
    Trap _begin_trap;
    Trap _end_trap;
    bool _nostop;
    Mutex _thread_names_lock;
    // TODO: single map?
    std::map<int, std::string> _thread_names;
    std::map<int, jlong> _thread_ids;
    Mutex _contexts_lock;
    std::map<std::string, long*> _contexts;
    Dictionary _class_map;
    Dictionary _symbol_map;
    ThreadFilter _thread_filter;
    CallTraceStorage _call_trace_storages[2];
    CallTraceStorage* _call_trace_storage;
    CallTraceStorage* _snapped_call_trace_storage;
    FlightRecorder _jfr;
    Engine* _engine;
    Engine* _alloc_engine;
    int _event_mask;
    bool _eventtypeframes;
    bool _persist;
    bool _debug_frames;

    time_t _start_time;
    time_t _stop_time;
    int _epoch;
    u32 _gc_id;
    WaitableMutex _timer_lock;
    void* _timer_id;

    u64 _total_samples;
    u64 _total_stack_walk_time;
    u64 _failures[ASGCT_FAILURE_TYPES];

    SpinLock _locks[CONCURRENCY_LEVEL];
    CallTraceBuffer* _calltrace_buffer[CONCURRENCY_LEVEL];
    int _max_stack_depth;
    StackWalkFeatures _features;
    CStack _cstack;
    bool _add_event_frame;
    bool _add_thread_frame;
    bool _add_sched_frame;
    bool _update_thread_names;
    volatile jvmtiEventMode _thread_events_state;

    SpinLock _stubs_lock;
    CodeCache _runtime_stubs;
    CodeCacheArray _native_libs;
    const void* _call_stub_begin;
    const void* _call_stub_end;

    // dlopen() hook support
    void** _dlopen_entry;
    static void* dlopen_hook(const char* filename, int flags);
    void switchLibraryTrap(bool enable);

    Error installTraps(const char* begin, const char* end, bool nostop);
    void uninstallTraps();

    void addJavaMethod(const void* address, int length, jmethodID method);
    void addRuntimeStub(const void* address, int length, const char* name);

    void onThreadStart(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);
    void onThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);
    void onVirtualThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);
    void onGarbageCollectionFinish();

    const char* asgctError(int code);
    u32 getLockIndex(int tid);
    jmethodID getCurrentCompileTask();
    int getNativeTrace(void* ucontext, ASGCT_CallFrame* frames, EventType event_type, int tid, StackContext* java_ctx, const char** unsafe);
    int getJavaTraceAsync(void* ucontext, ASGCT_CallFrame* frames, int max_depth, StackContext* java_ctx);
    int getJavaTraceJvmti(jthread othread, jvmtiFrameInfo* jvmti_frames, ASGCT_CallFrame* frames, int start_depth, int max_depth);
    void fillFrameTypes(ASGCT_CallFrame* frames, int num_frames, NMethod* nmethod);
    void setThreadInfo(int tid, const char* name, jlong java_thread_id);
    void updateThreadName(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);
    void updateJavaThreadNames();
    void updateNativeThreadNames();
    bool excludeTrace(FrameName* fn, CallTrace* trace);
    void mangle(const char* name, char* buf, size_t size);
    Engine* selectEngine(const char* event_name);
    Engine* selectAllocEngine(Arguments& args);
    Engine* activeEngine();
    Error checkJvmCapabilities();

    time_t addTimeout(time_t start, int timeout);
    void startTimer();
    void stopTimer();
    void timerLoop(void* timer_id);

    void logEmptyOutput(Arguments& args, u64 printed_samples_count, Writer& out);

    static void jvmtiTimerEntry(jvmtiEnv* jvmti, JNIEnv* jni, void* arg) {
        instance()->timerLoop(arg);
    }

    static void* pthreadTimerEntry(void* arg) {
        instance()->timerLoop(arg);
        return NULL;
    }

    void lockAll();
    void unlockAll();
    u32 tryLock();

    void dumpCollapsed(Writer& out, Arguments& args);
    void dumpFlameGraph(Writer& out, Arguments& args, bool tree);
    void dumpText(Writer& out, Arguments& args);

    int bail(int tid, EventType event_type, int lock_index);
    bool enqueueDeferred(u64 counter, EventType event_type, Event* event, bool needsTag,
                         ASGCT_CallFrame* frames, int num_frames, int first_java_frame,
                         AwaitData* tlad, AwaitData* ad, bool isContinuation,
                         Registration* registrationp, producer_token_t *pt);

    int substituteAwaitMarkers(AwaitData* ad, ASGCT_CallFrame* frames, int first_java_frame, int num_frames) const;



    volatile bool _savedAwaitStacks = false;
    AwaitData* _vtAwaitData;
    AwaitData* getVTAwaitData(long vtid, AwaitMapAction action, JNIEnv* env = nullptr);
    jthread cleanupAwaitData(AwaitData *ad);
    int _vtSlots;
    int _vtBucketSize;
    Mutex _record_thread_lock;
    moodycamel::BlockingConcurrentQueue<Deferred> *_dq;
    moodycamel::ConsumerToken *_ct;
    moodycamel::ProducerToken* _pts[CONCURRENCY_LEVEL];
    CallTraceBuffer* _deferred_buf;
    u32* _deferred_pos;
    volatile bool _recording_deferred;
    static Profiler* const _instance;

  public:
    Profiler() :
        _state(NEW),
        _begin_trap(2),
        _end_trap(3),
        _thread_filter(),
        _call_trace_storages(),
        _call_trace_storage(_call_trace_storages),
        _snapped_call_trace_storage(_call_trace_storages),  // deliberately not different
        _jfr(),
        _start_time(0),
        _epoch(0),
        _gc_id(0),
        _timer_id(NULL),
        _max_stack_depth(0),
        _thread_events_state(JVMTI_DISABLE),
        _stubs_lock(),
        _runtime_stubs("[stubs]"),
        _native_libs(),
        _call_stub_begin(NULL),
        _call_stub_end(NULL),
        _dlopen_entry(NULL),
        stats{},
        _vtAwaitData(NULL),
        _vtSlots(0),
        _vtBucketSize(0),
        _dq(0),
        _ct(NULL),
        _recording_deferred(false),
        _deferred_buf(NULL),
        _deferred_pos(NULL),
        _debug_frames(false)
        {
        for (int i = 0; i < CONCURRENCY_LEVEL; i++) {
            _calltrace_buffer[i] = NULL;
        }
    }
    void enqueueDeferred(Registration& registration);
    AwaitData* virtualMount(JNIEnv* env, jthread vthread);

    volatile static GlobalFlags globalFlags;
    Stats stats;

    static Profiler* instance() {
        return _instance;
    }

    bool savedAwaitStacks() {
      return _savedAwaitStacks;
    }

    AwaitData* threadLocalAwaitData(bool may_init);
    AwaitData* awaitData(bool may_init = false, bool may_virtual = true);
    int initAwaitData(int slots);
    long saveAwaitFrames(AwaitFrameType,long*,int);
    void setExternalContext(long ctx, const char* shmpath);

    u64 total_samples() { return _total_samples; }
    long uptime()       { return time(NULL) - _start_time; }

    Dictionary* classMap() { return &_class_map; }
    ThreadFilter* threadFilter() { return &_thread_filter; }
    CodeCacheArray* nativeLibs() { return &_native_libs; }

    Error run(Arguments& args);
    Error runInternal(Arguments& args, Writer& out);
    Error restart(Arguments& args);
    void shutdown(Arguments& args);
    Error check(Arguments& args);
    Error start(Arguments& args, bool reset);
    Error stop(bool restart = false);
    void stop_jemalloc();
    Error flushJfr();
    Error dump(Writer& out, Arguments& args);
    void printUsedMemory(Writer& out);
    void logStats();
    void switchThreadEvents(jvmtiEventMode mode);
    int convertNativeTrace(int native_frames, const void** callchain, ASGCT_CallFrame* frames, EventType event_type, const char ** unsafe);
    u64 recordSample(void* ucontext, u64 counter, EventType event_type, Event* event, u64* tagp = NULL, Deferred* deferred = NULL, Registration* registrationp = NULL);
    long recordThread(JNIEnv *env, AwaitData *, int start, const char *info, bool assumeSampled, AwaitData* rabbit = nullptr, u32 existing_lock = CONCURRENCY_LEVEL + 1);
    u32 recordThreads(JNIEnv *env);
    void recordExternalSample(u64 counter, const char* custom, const char* error, u64 sidref);
    void recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, int num_frames, ASGCT_CallFrame* frames);
    void recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, u32 call_trace_id);
    void processDeferred(JNIEnv* env, int n, long ms);
    void recordExternalSamples(u64 samples, u64 counter, int tid, u32 call_trace_id, EventType event_type, Event* event);
    void recordExternalSample(u64 counter, EventType event_type, Event* event, long trace);
    void recordEventOnly(EventType event_type, Event* event);
    u64 recordCustom(int offset, double value, const char* info, u64 counter);
    void addCustomEventType(int offset, const char* name);
    void tryResetCounters();
    void writeLog(LogLevel level, const char* message);
    void writeLog(LogLevel level, const char* message, size_t len);

    void updateSymbols(bool kernel_symbols);
    const void* resolveSymbol(const char* name);
    const char* getLibraryName(const char* native_symbol);
    CodeCache* findJvmLibrary(const char* lib_name);
    CodeCache* findLibraryByName(const char* lib_name);
    CodeCache* findLibraryByAddress(const void* address);
    const char* findNativeMethod(const void* address);
    CodeBlob* findRuntimeStub(const void* address);
    bool isAddressInCode(const void* pc);

    void trapHandler(int signo, siginfo_t* siginfo, void* ucontext);
    static void segvHandler(int signo, siginfo_t* siginfo, void* ucontext);
    static void wakeupHandler(int signo);
    static void setupSignalHandlers();

    // CompiledMethodLoad is also needed to enable DebugNonSafepoints info by default
    static void JNICALL CompiledMethodLoad(jvmtiEnv* jvmti, jmethodID method,
                                           jint code_size, const void* code_addr,
                                           jint map_length, const jvmtiAddrLocationMap* map,
                                           const void* compile_info) {
        instance()->addJavaMethod(code_addr, code_size, method);
    }

    static void JNICALL DynamicCodeGenerated(jvmtiEnv* jvmti, const char* name,
                                             const void* address, jint length) {
        instance()->addRuntimeStub(address, length, name);
    }

    static void JNICALL ThreadStart(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
        instance()->onThreadStart(jvmti, jni, thread);
    }

    static void JNICALL ThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
        instance()->onThreadEnd(jvmti, jni, thread);
    }

    static void JNICALL VirtualThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
        instance()->onVirtualThreadEnd(jvmti, jni, thread);
    }

    static void JNICALL GarbageCollectionFinish(jvmtiEnv* jvmti) {
        instance()->onGarbageCollectionFinish();
    }

    friend class Recording;
};

#endif // _PROFILER_H

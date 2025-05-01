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
  static const int MAX_DEPTH = 5;
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

struct AwaitData;
struct Deferred {
    ASGCT_CallFrame frames[DEFAULT_JSTACKDEPTH]; // frames captured from signal callback
    volatile AwaitData* awaitData;               // await data for captured thread
    jthread thread;
    u64 counter;
    EventType event_type;
    Event event;
    int first_java_frame;
};

typedef moodycamel::BlockingConcurrentQueue<Deferred>::producer_token_t producer_token_t;

struct AwaitData {
    // The order of fields is important if getAwaitDataAddress() is used.
    // When sampling occurs, we will search for a method_id == insertionId.
    // Starting from the innermost frame, we replace matching ids with successive
    // elements of stackId.
    // And we put the value sampledSignalToSet into sampledSignal
    long insertionId;
    long sampledSignalToSet;
    long sampledSignal;
    long stackId[MAX_AWAIT_STACKS+1];
    // os thread-local data:
    long mounted_vthread_id;
    jthread mounted_vthread;
    producer_token_t* producer_token;
};

enum GlobalFlags {
    GF_NONE = 0,
    GF_NO_SHUTDOWN = 1
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
    CallTraceStorage _call_trace_storage;
    FlightRecorder _jfr;
    Engine* _engine;
    Engine* _alloc_engine;
    int _event_mask;
    bool _eventtypeframes;
    bool _persist;

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

    void dumpCollapsed(Writer& out, Arguments& args);
    void dumpFlameGraph(Writer& out, Arguments& args, bool tree);
    void dumpText(Writer& out, Arguments& args);

    int bail(int tid, EventType event_type, int lock_index);

    bool _savedAwaitStacks = false;
    volatile AwaitData* _vtAwaitData;
    int _vtSlots;

    moodycamel::BlockingConcurrentQueue<Deferred> _dq;

    static Profiler* const _instance;

  public:
    Profiler() :
        _state(NEW),
        _begin_trap(2),
        _end_trap(3),
        _thread_filter(),
        _call_trace_storage(),
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
        _vtAwaitData(NULL),
        _vtSlots(0),
        _dq(CONCURRENCY_LEVEL * 2) {

        for (int i = 0; i < CONCURRENCY_LEVEL; i++) {
            _calltrace_buffer[i] = NULL;
        }
    }

    volatile static GlobalFlags globalFlags;

    static Profiler* instance() {
        return _instance;
    }

    bool savedAwaitStacks() {
      return _savedAwaitStacks;
    }

    AwaitData* threadLocalAwaitData(bool may_init);
    volatile AwaitData* awaitData(bool may_init = false);
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
    u64 recordSample(void* ucontext, u64 counter, EventType event_type, Event* event, u64* tagp = NULL, Deferred* deferred = NULL);
    void recordExternalSample(u64 counter, const char* custom, const char* error, u64 sidref);
    void recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, int num_frames, ASGCT_CallFrame* frames);
    void recordExternalSample(u64 counter, int tid, EventType event_type, Event* event, u32 call_trace_id);
    void recordDeferred(int n, long ms);
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

    static void JNICALL GarbageCollectionFinish(jvmtiEnv* jvmti) {
        instance()->onGarbageCollectionFinish();
    }

    friend class Recording;
};

#endif // _PROFILER_H

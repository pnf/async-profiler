/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _EVENT_H
#define _EVENT_H

#include <stdint.h>
#include "os.h"


// The order is important: look for event_type comparison
enum EventType {
    PERF_SAMPLE,
    EXECUTION_SAMPLE,
    INSTRUMENTED_METHOD,
    NATIVE_ALLOC,  // must be before alloc_sample due to inequality check in profiler.cpp
    ALLOC_SAMPLE,
    ALLOC_OUTSIDE_TLAB,
    LIVE_OBJECT,
    LOCK_SAMPLE,
    PARK_SAMPLE,
    PROFILING_WINDOW,
    CUSTOM
};

class Event {
  public:
    u32 id() {
        return *(u32*)this;
    }
};

class ExecutionEvent : public Event {
  public:
    ThreadState _thread_state;

    ExecutionEvent() : _thread_state(THREAD_UNKNOWN) {
    }
};

class AllocEvent : public Event {
  public:
    u32 _class_id;
    u64 _total_size;
    u64 _instance_size;
};

class LockEvent : public Event {
  public:
    u32 _class_id;
    u64 _start_time;
    u64 _end_time;
    uintptr_t _address;
    long long _timeout;
};

class LiveObject : public Event {
  public:
    u32 _class_id;
    u64 _alloc_size;
    u64 _alloc_time;
};

class ProfilingWindow : public Event {
  public:
    u64 _start_time;
    u64 _end_time;
};

class CustomEvent : public Event {
  public:
    int offset;
    double value;
    const char* info;
};

#endif // _EVENT_H

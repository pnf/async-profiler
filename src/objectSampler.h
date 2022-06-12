/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OBJECTSAMPLER_H
#define _OBJECTSAMPLER_H

#include <jvmti.h>
#include "arch.h"
#include "engine.h"
#include "event.h"


class ObjectSampler : public Engine {
  protected:
    static u64 _interval;
    static u64 _nativeInterval;
    static bool _live;
    static bool _persist;
    static volatile u64 _allocated_bytes;

    static void initLiveRefs(bool live, bool persist);
    static void dumpLiveRefs();

    static void recordAllocation(jvmtiEnv* jvmti, JNIEnv* jni, EventType event_type,
                                 jobject object, jclass object_klass, jlong size);
    static void recordAllocation(const void* addr, size_t size, bool isFree);

  public:
    const char* title() {
        return "Allocation profile";
    }

    const char* units() {
        return "bytes";
    }

    Error check(Arguments& args);
    Error start(Arguments& args);
    void stop();

    static void JNICALL SampledObjectAlloc(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                           jobject object, jclass object_klass, jlong size);

    static void JNICALL GarbageCollectionStart(jvmtiEnv* jvmti);

    static void NativeAlloc(const void*, size_t, bool);
};

#endif // _OBJECTSAMPLER_H

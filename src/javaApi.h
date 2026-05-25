/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _JAVAAPI_H
#define _JAVAAPI_H

#include <jvmti.h>
#include <jni.h>


class JavaAPI {
  public:
    static void registerNatives(jvmtiEnv* jvmti, JNIEnv* jni);
    static bool startHttpServer(jvmtiEnv* jvmti, JNIEnv* jni, const char* address);
    static void callThreadStringCallback(JNIEnv* env, jthread thread, const char* str);
};

#endif // _JAVAAPI_H

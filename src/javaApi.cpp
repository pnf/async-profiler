/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>
#include <math.h> // MS
#include <dlfcn.h> //MS
#include "asprof.h"
#include "incbin.h"
#include "javaApi.h"
#include "os.h"
#include "profiler.h"
#include "vmStructs.h"
#include "jfrMetadata.h"
#include "zlib/gzlog.h" // MS

INCLUDE_HELPER_CLASS(SERVER_NAME, SERVER_CLASS, "one/profiler/Server")


static void throwNew(JNIEnv* env, const char* exception_class, const char* message) {
    jclass cls = env->FindClass(exception_class);
    if (cls != NULL) {
        env->ThrowNew(cls, message);
    }
}

// MS methods follow:

// Wrapper to expose jmethodID to java programs
extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_getMethodID(JNIEnv* env, jclass unused, jclass klass, jstring method, jstring sig, jboolean isStatic) {
  const char* method_str = env->GetStringUTFChars(method, NULL);
  const char* sig_str = env->GetStringUTFChars(sig, NULL);
  jmethodID id = isStatic ? env->GetStaticMethodID(klass, method_str, sig_str) : env->GetMethodID(klass, method_str, sig_str);
  env->ReleaseStringUTFChars(method, method_str);
  env->ReleaseStringUTFChars(sig, sig_str);
  return (jlong) id;
}

// Permanently create a string in C memory.
extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_saveString(JNIEnv* env, jobject unused, jstring name) {
    const char* name_str = env->GetStringUTFChars(name, NULL);
    char *p = strdup(name_str);
    env->ReleaseStringUTFChars(name, name_str);
    return (jlong) p;
}

extern "C"  DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_externalContext(JNIEnv* env, jobject unused, jlong ctx, jstring shmpath) {
   const char *shmpath_str = shmpath ? env->GetStringUTFChars(shmpath, NULL) : NULL;
   Profiler::instance()->setExternalContext((long) ctx, shmpath_str);
   if(shmpath) env->ReleaseStringUTFChars(shmpath, shmpath_str);
}

extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_getAwaitDataAddress(JNIEnv* env, jclass unused) {
    return (jlong) Profiler::instance()->awaitData(true);
}

extern "C" DLLEXPORT jint JNICALL
Java_one_profiler_AsyncProfiler_initAwaitData(JNIEnv* env, jclass unused, jint slots) {
    return Profiler::instance()->initAwaitData(slots);
}

extern "C" DLLEXPORT long JNICALL
Java_one_profiler_AsyncProfiler_saveAwaitFrames(JNIEnv* env, jobject unused, int ft, jlongArray ids, jint nids) {
  jlong *elems = (jlong*) env->GetPrimitiveArrayCritical(ids, 0);
  long ret = Profiler::instance()->saveAwaitFrames(static_cast<AwaitFrameType>(ft), elems, nids);
  env->ReleasePrimitiveArrayCritical(ids, (void*) elems, 0);
  return ret;
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_recordDeferred(JNIEnv* env, jobject unused, jint n, jlong ms) {
   Profiler::instance()->recordDeferred(env,n, ms);
}


extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_addCustomEventType(JNIEnv* env, jobject unused, jint i, jstring event, jstring value) {
    const char* event_str = env->GetStringUTFChars(event, NULL);
    const char* value_str = env->GetStringUTFChars(value, NULL);
    char* name  = new char[strlen(event_str) + strlen(value_str) + 2];
    sprintf(name, "%s:%s", event_str, value_str);
    Profiler::instance()->addCustomEventType(i, name);
    JfrMetadata::addCustom(i, event_str, event_str, value_str);
    env->ReleaseStringUTFChars(event, event_str);
    env->ReleaseStringUTFChars(value, value_str);
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_recordCustomEvent(JNIEnv* env, jobject unused, jint i, double v, jlong n, jlong info) {
    u64 counter = n > 0 ? (u64) n : 0;
    Profiler::instance()->recordCustom(i, v, (const char*) info, counter);
}

extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_testMalloc(JNIEnv* env, jclass unused, jlong sz) {
    return (jlong) malloc((size_t) sz);
}
extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_testFree(JNIEnv* env, jclass unused, jlong addr) {
   free((void*) addr);
}

// Used only to test that a stack containing this method is marked as unsafe.
extern "C" DLLEXPORT jdouble JNICALL
Java_one_profiler_AsyncProfiler_testIgnored(JNIEnv* env, jclass unused, jint count) {
   double x = sin(count);
   while(count-- > 0)
       x = sin(x);
   return x;
}

extern "C" DLLEXPORT jlongArray JNICALL
Java_one_profiler_AsyncProfiler_getInternals(JNIEnv* env, jclass unused) {
    const unsigned int SZ = 2;
    long elements[SZ] = {(long) OS::getAllocated(), (long) Protect::timesProtected() };
    jlongArray ret = env->NewLongArray(SZ);
    env->SetLongArrayRegion(ret, 0, SZ, elements);
    return ret;
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_start0(JNIEnv* env, jobject unused, jstring event, jlong interval, jboolean reset) {
    Arguments args;
    const char* event_str = env->GetStringUTFChars(event, NULL);
    if (strcmp(event_str, EVENT_ALLOC) == 0) {
        args._alloc = interval > 0 ? interval : 0;
    } else if (strcmp(event_str, EVENT_LOCK) == 0) {
        args._lock = interval >= 0 ? interval : DEFAULT_LOCK_INTERVAL;
    } else {
        args._event = event_str;
        args._interval = interval;
    }

    Error error = Profiler::instance()->start(args, reset);
    env->ReleaseStringUTFChars(event, event_str);

    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
    }
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_stop0(JNIEnv* env, jobject unused) {
    Error error = Profiler::instance()->stop();

    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
    }
}

extern "C" DLLEXPORT jstring JNICALL
Java_one_profiler_AsyncProfiler_execute0(JNIEnv* env, jobject unused, jstring command) {
    Arguments args;
    const char* command_str = env->GetStringUTFChars(command, NULL);
    Error error = args.parse(command_str);
    env->ReleaseStringUTFChars(command, command_str);

    if (error) {
        throwNew(env, "java/lang/IllegalArgumentException", error.message());
        return NULL;
    }

    Log::open(args);

    if (!args.hasOutputFile()) {
        BufferWriter out;
        error = Profiler::instance()->runInternal(args, out);
        if (!error) {
            out << '\0';
            if (out.size() >= 0x3fffffff) {
                throwNew(env, "java/lang/IllegalStateException", "Output exceeds string size limit");
                return NULL;
            }
            return env->NewStringUTF(out.buf());
        }
    } else {
        FileWriter out(args.file());
        if (!out.is_open()) {
            throwNew(env, "java/io/IOException", strerror(errno));
            return NULL;
        }
        error = Profiler::instance()->runInternal(args, out);
        if (!error) {
            return env->NewStringUTF("OK");
        }
    }

    throwNew(env, "java/lang/IllegalStateException", error.message());
    return NULL;
}

extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_getSamples(JNIEnv* env, jobject unused) {
    return (jlong)Profiler::instance()->total_samples();
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_filterThread0(JNIEnv* env, jobject unused, jthread thread, jboolean enable) {
    int thread_id;
    if (thread == NULL) {
        thread_id = OS::threadId();
    } else if ((thread_id = VMThread::nativeThreadId(env, thread)) < 0) {
        return;
    }

    ThreadFilter* thread_filter = Profiler::instance()->threadFilter();
    if (enable) {
        thread_filter->add(thread_id);
    } else {
        thread_filter->remove(thread_id);
    }
}

extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_gzlogOpen(JNIEnv* env, jobject unused, jstring path ) {
   const char* path_str = env->GetStringUTFChars(path, NULL);
   jlong ret = (jlong) gzlog_open(path_str);
   env->ReleaseStringUTFChars(path, path_str);
   return ret;
}

extern "C" DLLEXPORT jint JNICALL
Java_one_profiler_AsyncProfiler_gzlogWrite(JNIEnv* env, jobject unused, jlong log, jbyteArray data, jint offset, jint len) {
    const char *data_str = (const char*) env->GetByteArrayElements(data, NULL) + offset;
    jint ret = (jlong) gzlog_write((gzlog*) log, data_str, len);
    env->ReleaseByteArrayElements(data, (jbyte*) data_str, JNI_ABORT);
    return ret;
}

extern "C" DLLEXPORT jint JNICALL
   Java_one_profiler_AsyncProfiler_gzlogFlush(JNIEnv* env, jobject unused, jlong log) {
   return gzlog_compress((gzlog*) log);
}

extern "C" DLLEXPORT jint JNICALL
Java_one_profiler_AsyncProfiler_gzlogClose(JNIEnv* env, jobject unused, jlong log) {
    return gzlog_close((gzlog*) log);
}

#define F(name, sig)  {(char*)#name, (char*)sig, (void*)Java_one_profiler_AsyncProfiler_##name}

static const JNINativeMethod profiler_natives[] = {
    F(start0,        "(Ljava/lang/String;JZ)V"),
    F(stop0,         "()V"),
    F(execute0,      "(Ljava/lang/String;)Ljava/lang/String;"),
    F(getSamples,    "()J"),
    F(filterThread0, "(Ljava/lang/Thread;Z)V"),
    F(getMethodID,   "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;Z)J"),
    F(getAwaitDataAddress, "()J"),
    F(initAwaitData, "(I)I"),
    F(saveAwaitFrames, "(I[JI)J"),
    F(externalContext, "(JLjava/lang/String;)V"),
    F(saveString,    "(Ljava/lang/String;)J"),
    F(recordCustomEvent, "(IDJLL)V"),
    F(addCustomEventType, "(ILjava/lang/String;Ljava/lang/String;)V"),
    F(testMalloc, "(J)J"),
    F(recordDeferred, "(IJ)V"),
    F(getInternals,"()[J"),
    F(testFree, "(J)V"),
    F(testIgnored, "(I)D"),
    F(getInternals,"()[J"),
    F(gzlogOpen,"(Ljava/lang/String;)J"),
    F(gzlogWrite,"(J[BII)I"),
    F(gzlogFlush,"(J)I"),
    F(gzlogClose,"(J)I")
};

static const JNINativeMethod* execute0 = &profiler_natives[2];

#undef F


// Since AsyncProfiler class can be renamed or moved to another package (shaded),
// we look for the actual class in the stack trace.
void JavaAPI::registerNatives(jvmtiEnv* jvmti, JNIEnv* jni) {
    jvmtiFrameInfo frame[10];
    jint frame_count;
    if (jvmti->GetStackTrace(NULL, 0, sizeof(frame) / sizeof(frame[0]), frame, &frame_count) != 0) {
        return;
    }

    jclass System = jni->FindClass("java/lang/System");
    jmethodID load = jni->GetStaticMethodID(System, "load", "(Ljava/lang/String;)V");
    jmethodID loadLibrary = jni->GetStaticMethodID(System, "loadLibrary", "(Ljava/lang/String;)V");

    // Look for System.load() or System.loadLibrary() method in the stack trace.
    // The next frame will belong to AsyncProfiler class.
    for (int i = 0; i < frame_count - 1; i++) {
        if (frame[i].method == load || frame[i].method == loadLibrary) {
            jclass profiler_class;
            if (jvmti->GetMethodDeclaringClass(frame[i + 1].method, &profiler_class) == 0) {
                for (int j = 0; j < sizeof(profiler_natives) / sizeof(JNINativeMethod); j++) {
                    jni->RegisterNatives(profiler_class, &profiler_natives[j], 1);
                }
            }
            break;
        }
    }

    jni->ExceptionClear();
}

bool JavaAPI::startHttpServer(jvmtiEnv* jvmti, JNIEnv* jni, const char* address) {
    jclass handler = jni->FindClass("com/sun/net/httpserver/HttpHandler");
    jobject loader;
    if (handler != NULL && jvmti->GetClassLoader(handler, &loader) == 0) {
        jclass cls = jni->DefineClass(SERVER_NAME, loader, (const jbyte*)SERVER_CLASS, INCBIN_SIZEOF(SERVER_CLASS));
        if (cls != NULL && jni->RegisterNatives(cls, execute0, 1) == 0) {
            jmethodID method = jni->GetStaticMethodID(cls, "start", "(Ljava/lang/String;)V");
            if (method != NULL) {
                jni->CallStaticVoidMethod(cls, method, jni->NewStringUTF(address));
                if (!jni->ExceptionCheck()) {
                    return true;
                }
            }
        }
    }

    jni->ExceptionDescribe();
    return false;
}

/*
 * Copyright 2017 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "vmStructs.h"
#include "vmEntry.h"


CodeCache* VMStructs::_libjvm = NULL;

bool VMStructs::_has_class_names = false;
bool VMStructs::_has_class_loader_data = false;
bool VMStructs::_has_thread_bridge = false;
bool VMStructs::_has_perm_gen = false;

int VMStructs::_klass_name_offset = -1;
int VMStructs::_symbol_length_offset = -1;
int VMStructs::_symbol_length_and_refcount_offset = -1;
int VMStructs::_symbol_body_offset = -1;
int VMStructs::_class_loader_data_offset = -1;
int VMStructs::_class_loader_data_next_offset = -1;
int VMStructs::_methods_offset = -1;
int VMStructs::_thread_osthread_offset = -1;
int VMStructs::_thread_anchor_offset = -1;
int VMStructs::_thread_state_offset = -1;
int VMStructs::_osthread_id_offset = -1;
int VMStructs::_anchor_sp_offset = -1;
int VMStructs::_anchor_pc_offset = -1;
int VMStructs::_frame_size_offset = -1;
int VMStructs::_is_gc_active_offset = -1;
int VMStructs::_code_heap_memory_offset = -1;
int VMStructs::_code_heap_segmap_offset = -1;
int VMStructs::_code_heap_segment_shift = -1;
int VMStructs::_vs_low_offset = -1;
int VMStructs::_vs_high_offset = -1;
char* VMStructs::_code_heap[3] = {};
char* VMStructs::_collected_heap_addr = NULL;
const void* VMStructs::_code_heap_low = NO_MIN_ADDRESS;
const void* VMStructs::_code_heap_high = NO_MAX_ADDRESS;

jfieldID VMStructs::_eetop;
jfieldID VMStructs::_tid;
jfieldID VMStructs::_klass = NULL;
int VMStructs::_tls_index = -1;
intptr_t VMStructs::_env_offset;

VMStructs::GetStackTraceFunc VMStructs::_get_stack_trace = NULL;
VMStructs::LockFunc VMStructs::_lock_func;
VMStructs::LockFunc VMStructs::_unlock_func;


uintptr_t VMStructs::readSymbol(const char* symbol_name) {
    const void* symbol = _libjvm->findSymbol(symbol_name);
    if (symbol == NULL) {
        // Avoid JVM crash in case of missing symbols
        return 0;
    }
    return *(uintptr_t*)symbol;
}

void VMStructs::init(CodeCache* libjvm) {
    _libjvm = libjvm;

    initOffsets();
    initJvmFunctions();

    JNIEnv* env = VM::jni();
    initThreadBridge(env);
    initLogging(env);
    env->ExceptionClear();
}

void VMStructs::initOffsets() {
    uintptr_t entry = readSymbol("gHotSpotVMStructs");
    uintptr_t stride = readSymbol("gHotSpotVMStructEntryArrayStride");
    uintptr_t type_offset = readSymbol("gHotSpotVMStructEntryTypeNameOffset");
    uintptr_t field_offset = readSymbol("gHotSpotVMStructEntryFieldNameOffset");
    uintptr_t offset_offset = readSymbol("gHotSpotVMStructEntryOffsetOffset");
    uintptr_t address_offset = readSymbol("gHotSpotVMStructEntryAddressOffset");

    if (entry == 0 || stride == 0) {
        return;
    }

    char* code_heaps = NULL;
    int array_data_offset = -1;
    int segment_size_offset = -1;
    int vs_low_bound_offset = -1;
    int vs_high_bound_offset = -1;

    while (true) {
        const char* type = *(const char**)(entry + type_offset);
        const char* field = *(const char**)(entry + field_offset);
        if (type == NULL || field == NULL) {
            break;
        }

        if (strcmp(type, "Klass") == 0) {
            if (strcmp(field, "_name") == 0) {
                _klass_name_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "Symbol") == 0) {
            if (strcmp(field, "_length") == 0) {
                _symbol_length_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_length_and_refcount") == 0) {
                _symbol_length_and_refcount_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_body") == 0) {
                _symbol_body_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "InstanceKlass") == 0) {
            if (strcmp(field, "_class_loader_data") == 0) {
                _class_loader_data_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_methods") == 0) {
                _methods_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "ClassLoaderData") == 0) {
            if (strcmp(field, "_next") == 0) {
                _class_loader_data_next_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "java_lang_Class") == 0) {
            if (strcmp(field, "_klass_offset") == 0) {
                int klass_offset = **(int**)(entry + address_offset);
                _klass = (jfieldID)(uintptr_t)(klass_offset << 2 | 2);
            }
        } else if (strcmp(type, "JavaThread") == 0) {
            if (strcmp(field, "_osthread") == 0) {
                _thread_osthread_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_anchor") == 0) {
                _thread_anchor_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_thread_state") == 0) {
                _thread_state_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "OSThread") == 0) {
            if (strcmp(field, "_thread_id") == 0) {
                _osthread_id_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "JavaFrameAnchor") == 0) {
            if (strcmp(field, "_last_Java_sp") == 0) {
                _anchor_sp_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_last_Java_pc") == 0) {
                _anchor_pc_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "CodeBlob") == 0) {
            if (strcmp(field, "_frame_size") == 0) {
                _frame_size_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "CodeCache") == 0) {
            if (strcmp(field, "_heap") == 0) {
                _code_heap[0] = **(char***)(entry + address_offset);
            } else if (strcmp(field, "_heaps") == 0) {
                code_heaps = **(char***)(entry + address_offset);
            } else if (strcmp(field, "_high_bound") == 0) {
                _code_heap_high = **(const void***)(entry + address_offset);
            } else if (strcmp(field, "_low_bound") == 0) {
                _code_heap_low = **(const void***)(entry + address_offset);
            }
        } else if (strcmp(type, "CodeHeap") == 0) {
            if (strcmp(field, "_memory") == 0) {
                _code_heap_memory_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_segmap") == 0) {
                _code_heap_segmap_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_log2_segment_size") == 0) {
                segment_size_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "VirtualSpace") == 0) {
            if (strcmp(field, "_low_boundary") == 0) {
                vs_low_bound_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_high_boundary") == 0) {
                vs_high_bound_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_low") == 0) {
                _vs_low_offset = *(int*)(entry + offset_offset);
            } else if (strcmp(field, "_high") == 0) {
                _vs_high_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "GrowableArray<int>") == 0) {
            if (strcmp(field, "_data") == 0) {
                array_data_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "Universe") == 0) {
            if (strcmp(field, "_collectedHeap") == 0) {
                _collected_heap_addr = **(char***)(entry + address_offset);
            }
        } else if (strcmp(type, "CollectedHeap") == 0) {
            if (strcmp(field, "_is_gc_active") == 0) {
                _is_gc_active_offset = *(int*)(entry + offset_offset);
            }
        } else if (strcmp(type, "PermGen") == 0) {
            _has_perm_gen = true;
        }

        entry += stride;
    }

    _has_class_names = _klass_name_offset >= 0
            && (_symbol_length_offset >= 0 || _symbol_length_and_refcount_offset >= 0)
            && _symbol_body_offset >= 0
            && _klass != NULL;

    if (_code_heap[0] != NULL && _code_heap_memory_offset >= 0 && vs_low_bound_offset >= 0 && vs_high_bound_offset >= 0) {
        _code_heap_low = *(const void**)(_code_heap[0] + _code_heap_memory_offset + vs_low_bound_offset);
        _code_heap_high = *(const void**)(_code_heap[0] + _code_heap_memory_offset + vs_high_bound_offset);
    } else if (code_heaps != NULL && array_data_offset >= 0 && *(unsigned int*)code_heaps <= 3) {
        unsigned int code_heap_count = *(unsigned int*)code_heaps;
        char* code_heap_array = *(char**)(code_heaps + array_data_offset);
        memcpy(_code_heap, code_heap_array, code_heap_count * sizeof(_code_heap[0]));
    }

    // Invariant: _code_heap[i] != NULL iff all CodeHeap structures are available
    if (_code_heap[0] != NULL && segment_size_offset >= 0 && _code_heap_memory_offset >= 0 && _code_heap_segmap_offset >= 0) {
        _code_heap_segment_shift = *(int*)(_code_heap[0] + segment_size_offset);
    }
    if (_code_heap_segment_shift < 0 || _code_heap_segment_shift > 16) {
        memset(_code_heap, 0, sizeof(_code_heap));
    }
}

void VMStructs::initJvmFunctions() {
    _get_stack_trace = (GetStackTraceFunc)_libjvm->findSymbolByPrefix("_ZN8JvmtiEnv13GetStackTraceEP10JavaThreadiiP");

    if (VM::hotspot_version() == 8 && _class_loader_data_offset >= 0 &&
        _class_loader_data_next_offset == sizeof(uintptr_t) * 8 + 8 &&
        _methods_offset >= 0 && _klass != NULL)
    {
        _lock_func = (LockFunc)_libjvm->findSymbol("_ZN7Monitor28lock_without_safepoint_checkEv");
        _unlock_func = (LockFunc)_libjvm->findSymbol("_ZN7Monitor6unlockEv");
        _has_class_loader_data = _lock_func != NULL && _unlock_func != NULL;
    }
}

void VMStructs::initThreadBridge(JNIEnv* env) {
    // Get eetop field - a bridge from Java Thread to VMThread
    jthread thread;
    if (VM::jvmti()->GetCurrentThread(&thread) != 0) {
        return;
    }

    jclass thread_class = env->GetObjectClass(thread);
    _eetop = env->GetFieldID(thread_class, "eetop", "J");
    _tid = env->GetFieldID(thread_class, "tid", "J");
    if (_eetop == NULL || _tid == NULL) {
        return;
    }

    VMThread* vm_thread = VMThread::fromJavaThread(env, thread);
    if (vm_thread == NULL) {
        return;
    }

    // Workaround for JDK-8132510: it's not safe to call GetEnv() inside a signal handler
    // since JDK 9, so we do it only for threads already registered in ThreadLocalStorage
    for (int i = 0; i < 1024; i++) {
        if (pthread_getspecific((pthread_key_t)i) == vm_thread) {
            _tls_index = i;
            break;
        }
    }

    if (_tls_index < 0) {
        return;
    }

    _env_offset = (intptr_t)env - (intptr_t)vm_thread;
    _has_thread_bridge = true;
}

void VMStructs::initLogging(JNIEnv* env) {
    // Workaround for JDK-8238460
    if (VM::hotspot_version() >= 15) {
        VMManagement* management = VM::management();
        if (management != NULL) {
            management->ExecuteDiagnosticCommand(env, env->NewStringUTF("VM.log what=jni+resolve=error"));
        }
    }
}

VMThread* VMThread::current() {
    return (VMThread*)pthread_getspecific((pthread_key_t)_tls_index);
}

NMethod* CodeHeap::findNMethod(char* heap, const void* pc) {
    unsigned char* heap_start = *(unsigned char**)(heap + _code_heap_memory_offset + _vs_low_offset);
    unsigned char* segmap = *(unsigned char**)(heap + _code_heap_segmap_offset + _vs_low_offset);
    size_t idx = ((unsigned char*)pc - heap_start) >> _code_heap_segment_shift;

    if (segmap[idx] == 0xff) {
        return NULL;
    }
    while (segmap[idx] > 0) {
        idx -= segmap[idx];
    }

    unsigned char* block = heap_start + (idx << _code_heap_segment_shift);
    return block[sizeof(size_t)] ? (NMethod*)(block + 2 * sizeof(size_t)) : NULL;
}

#ifndef SRC_PERFEVENTS_LINUX_H
#define SRC_PERFEVENTS_LINUX_H

/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __linux__

#include <jvmti.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "arch.h"
#include "fdtransferClient.h"
#include "j9StackTraces.h"
#include "log.h"
#include "perfEvents.h"
#include "profiler.h"
#include "spinLock.h"
#include "stackFrame.h"
#include "stackWalker.h"
#include "symbols.h"
#include "tsc.h"
#include "vmStructs.h"


// Ancient fcntl.h does not define F_SETOWN_EX constants and structures
#ifndef F_SETOWN_EX
#define F_SETOWN_EX  15
#define F_OWNER_TID  0

struct f_owner_ex {
    int type;
    pid_t pid;
};
#endif // F_SETOWN_EX

// Introduced in kernel 3.14
#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC  8
#endif // PERF_FLAG_FD_CLOEXEC

enum {
    HW_BREAKPOINT_R  = 1,
    HW_BREAKPOINT_W  = 2,
    HW_BREAKPOINT_RW = 3,
    HW_BREAKPOINT_X  = 4
};

static int fetchInt(const char* file_name) {
    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        return 0;
    }

    char num[16] = "0";
    ssize_t r = read(fd, num, sizeof(num) - 1);
    (void) r;
    close(fd);
    return atoi(num);
}

// Get perf_event_attr.config numeric value of the given tracepoint name
// by reading /sys/kernel/tracing/events/<name>/id (since 4.1)
// or /sys/kernel/debug/tracing/events/<name>/id (before 4.1)
static int findTracepointId(const char* dir, const char* name) {
    char buf[256];
    if ((size_t)snprintf(buf, sizeof(buf), "/sys/kernel/%s/events/%s/id", dir, name) >= sizeof(buf)) {
        return 0;
    }

    *strchr(buf, ':') = '/';  // make path from event name

    return fetchInt(buf);
}

// Get perf_event_attr.type for the given event source
// by reading /sys/bus/event_source/devices/<name>/type
static int findDeviceType(const char* name) {
    char buf[256];
    if ((size_t)snprintf(buf, sizeof(buf), "/sys/bus/event_source/devices/%s/type", name) >= sizeof(buf)) {
        return 0;
    }
    return fetchInt(buf);
}

// Convert pmu/event-name/ to pmu/param1=N,param2=M/
static void resolvePmuEventName(const char* device, char* event, size_t size) {
    char buf[256];
    if ((size_t)snprintf(buf, sizeof(buf), "/sys/bus/event_source/devices/%s/events/%s", device, event) >= sizeof(buf)) {
        return;
    }

    int fd = open(buf, O_RDONLY);
    if (fd == -1) {
        return;
    }

    ssize_t r = read(fd, event, size);
    if (r > 0 && (r == size || event[r - 1] == '\n')) {
        event[r - 1] = 0;
    }
    close(fd);
}

// Set a PMU parameter (such as umask) to the corresponding config field
static bool setPmuConfig(const char* device, const char* param, __u64* config, __u64 val) {
    char buf[256];
    if ((size_t)snprintf(buf, sizeof(buf), "/sys/bus/event_source/devices/%s/format/%s", device, param) >= sizeof(buf)) {
        return false;
    }

    int fd = open(buf, O_RDONLY);
    if (fd == -1) {
        return false;
    }

    ssize_t r = read(fd, buf, sizeof(buf));
    close(fd);

    if (r > 0 && r < sizeof(buf)) {
        if (strncmp(buf, "config:", 7) == 0) {
            config[0] |= val << atoi(buf + 7);
            return true;
        } else if (strncmp(buf, "config1:", 8) == 0) {
            config[1] |= val << atoi(buf + 8);
            return true;
        } else if (strncmp(buf, "config2:", 8) == 0) {
            config[2] |= val << atoi(buf + 8);
            return true;
        }
    }
    return false;
}

// Perf events consume one file descriptor per thread.
// Make sure the current limit is the highest possible.
static void adjustFDLimit() {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0 && rlim.rlim_cur < rlim.rlim_max) {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rlim);
    }
}

struct FunctionWithCounter {
    const char* name;
    int counter_arg;
};

struct PerfEventType {
    const char* name;
    long default_interval;
    __u32 type;
    __u64 config;
    __u64 config1;
    __u64 config2;
    int counter_arg;

    enum {
        IDX_CPU = 0,
        IDX_PREDEFINED = 12,
        IDX_RAW,
        IDX_PMU,
        IDX_BREAKPOINT,
        IDX_TRACEPOINT,
        IDX_KPROBE,
        IDX_UPROBE,
    };

    static PerfEventType AVAILABLE_EVENTS[];
    static FunctionWithCounter KNOWN_FUNCTIONS[];

    static char probe_func[256];

    // Find which argument of a known function serves as a profiling counter,
    // e.g. the first argument of malloc() is allocation size
    static int findCounterArg(const char* name) {
        for (FunctionWithCounter* func = KNOWN_FUNCTIONS; func->name != NULL; func++) {
            if (strcmp(name, func->name) == 0) {
                return func->counter_arg;
            }
        }
        return 0;
    }

    // Breakpoint format: func[+offset][/len][:rwx][{arg}]
    static PerfEventType* getBreakpoint(const char* name, __u32 bp_type, __u32 bp_len) {
        char buf[256];
        strncpy(buf, name, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;

        // Parse counter arg [{arg}]
        int counter_arg = 0;
        char* c = strrchr(buf, '{');
        if (c != NULL && c[1] >= '1' && c[1] <= '9') {
            *c++ = 0;
            counter_arg = atoi(c);
        }

        // Parse access type [:rwx]
        c = strrchr(buf, ':');
        if (c != NULL && c != buf && c[-1] != ':') {
            *c++ = 0;
            if (strcmp(c, "rw") == 0 || strcmp(c, "wr") == 0) {
                bp_type = HW_BREAKPOINT_RW;
            } else if (strcmp(c, "r") == 0) {
                bp_type = HW_BREAKPOINT_R;
            } else if (strcmp(c, "w") == 0) {
                bp_type = HW_BREAKPOINT_W;
            } else if (strcmp(c, "x") == 0) {
                bp_type = HW_BREAKPOINT_X;
                bp_len = sizeof(long);
            } else {
                return NULL;
            }
        }

        // Parse length [/8]
        c = strrchr(buf, '/');
        if (c != NULL) {
            *c++ = 0;
            bp_len = (__u32)strtol(c, NULL, 0);
        }

        // Parse offset [+0x1234]
        long long offset = 0;
        c = strrchr(buf, '+');
        if (c != NULL) {
            *c++ = 0;
            offset = strtoll(c, NULL, 0);
        }

        // Parse symbol or absolute address
        __u64 addr;
        if (strncmp(buf, "0x", 2) == 0) {
            addr = (__u64)strtoll(buf, NULL, 0);
        } else if (buf[0] >= '0' && buf[0] <= '9') {
            // Only hex address is supported.
            return NULL;
        } else {
            addr = (__u64)(uintptr_t)dlsym(RTLD_DEFAULT, buf);
            if (addr == 0) {
                addr = (__u64)(uintptr_t)Profiler::instance()->resolveSymbol(buf);
            }
            if (c == NULL) {
                // If offset is not specified explicitly, add the default breakpoint offset
                offset = BREAKPOINT_OFFSET;
            }
        }

        if (addr == 0) {
            return NULL;
        }

        PerfEventType* breakpoint = &AVAILABLE_EVENTS[IDX_BREAKPOINT];
        breakpoint->config = bp_type;
        breakpoint->config1 = addr + offset;
        breakpoint->config2 = bp_len;
        breakpoint->counter_arg = bp_type == HW_BREAKPOINT_X && counter_arg == 0 ? findCounterArg(buf) : counter_arg;
        return breakpoint;
    }

    static PerfEventType* getTracepoint(int tracepoint_id) {
        PerfEventType* tracepoint = &AVAILABLE_EVENTS[IDX_TRACEPOINT];
        tracepoint->config = tracepoint_id;
        return tracepoint;
    }

    static PerfEventType* getProbe(PerfEventType* probe, const char* type, const char* name, __u64 ret) {
        strncpy(probe_func, name, sizeof(probe_func) - 1);
        probe_func[sizeof(probe_func) - 1] = 0;

        if (probe_func[0] == 0) {
            return NULL;
        }

        if (probe->type == 0 && (probe->type = findDeviceType(type)) == 0) {
            return NULL;
        }

        long long offset = 0;
        char* c = strrchr(probe_func, '+');
        if (c != NULL) {
            *c++ = 0;
            offset = strtoll(c, NULL, 0);
        }

        probe->config = ret;
        probe->config1 = (__u64)(uintptr_t)probe_func;
        probe->config2 = offset;
        return probe;
    }

    static PerfEventType* getRawEvent(__u64 config) {
        PerfEventType* raw = &AVAILABLE_EVENTS[IDX_RAW];
        raw->config = config;
        return raw;
    }

    static PerfEventType* getPmuEvent(const char* name) {
        char buf[256];
        strncpy(buf, name, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;

        char* descriptor = strchr(buf, '/');
        *descriptor++ = 0;
        descriptor[strlen(descriptor) - 1] = 0;

        PerfEventType* raw = &AVAILABLE_EVENTS[IDX_PMU];
        if ((raw->type = findDeviceType(buf)) == 0) {
            return NULL;
        }

        // pmu/rNNN/
        if (descriptor[0] == 'r' && descriptor[1] >= '0') {
            char* end;
            raw->config = strtoull(descriptor + 1, &end, 16);
            if (*end == 0) {
                return raw;
            }
        }

        // Resolve event name to the list of parameters
        resolvePmuEventName(buf, descriptor, sizeof(buf) - (descriptor - buf));

        raw->config = 0;
        raw->config1 = 0;
        raw->config2 = 0;

        // Parse parameters
        while (descriptor != NULL && descriptor[0]) {
            char* p = descriptor;
            if ((descriptor = strchr(p, ',')) != NULL || (descriptor = strchr(p, ':')) != NULL) {
                *descriptor++ = 0;
            }

            __u64 val = 1;
            char* eq = strchr(p, '=');
            if (eq != NULL) {
                *eq++ = 0;
                val = strtoull(eq, NULL, 0);
            }

            if (strcmp(p, "config") == 0) {
                raw->config = val;
            } else if (strcmp(p, "config1") == 0) {
                raw->config1 = val;
            } else if (strcmp(p, "config2") == 0) {
                raw->config2 = val;
            } else if (!setPmuConfig(buf, p, &raw->config, val)) {
                return NULL;
            }
        }

        return raw;
    }

    static PerfEventType* forName(const char* name) {
        // "cpu" is an alias for "cpu-clock"
        if (strcmp(name, EVENT_CPU) == 0) {
            return &AVAILABLE_EVENTS[IDX_CPU];
        }

        // Look through the table of predefined perf events
        for (int i = 0; i <= IDX_PREDEFINED; i++) {
            if (strcmp(name, AVAILABLE_EVENTS[i].name) == 0) {
                return &AVAILABLE_EVENTS[i];
            }
        }

        // Hardware breakpoint
        if (strncmp(name, "mem:", 4) == 0) {
            return getBreakpoint(name + 4, HW_BREAKPOINT_RW, 1);
        }

        // Raw tracepoint ID
        if (strncmp(name, "trace:", 6) == 0) {
            int tracepoint_id = atoi(name + 6);
            return tracepoint_id > 0 ? getTracepoint(tracepoint_id) : NULL;
        }

        // kprobe or uprobe
        if (strncmp(name, "kprobe:", 7) == 0) {
            return getProbe(&AVAILABLE_EVENTS[IDX_KPROBE], "kprobe", name + 7, 0);
        }
        if (strncmp(name, "uprobe:", 7) == 0) {
            return getProbe(&AVAILABLE_EVENTS[IDX_UPROBE], "uprobe", name + 7, 0);
        }
        if (strncmp(name, "kretprobe:", 10) == 0) {
            return getProbe(&AVAILABLE_EVENTS[IDX_KPROBE], "kprobe", name + 10, 1);
        }
        if (strncmp(name, "uretprobe:", 10) == 0) {
            return getProbe(&AVAILABLE_EVENTS[IDX_UPROBE], "uprobe", name + 10, 1);
        }

        // Raw PMU register: rNNN
        if (name[0] == 'r' && name[1] >= '0') {
            char* end;
            __u64 reg = strtoull(name + 1, &end, 16);
            if (*end == 0) {
                return getRawEvent(reg);
            }
        }

        // Raw perf event descriptor: pmu/event-descriptor/
        const char* s = strchr(name, '/');
        if (s > name && s[1] != 0 && s[strlen(s) - 1] == '/') {
            return getPmuEvent(name);
        }

        // Kernel tracepoints defined in debugfs
        s = strchr(name, ':');
        if (s != NULL && s[1] != ':') {
            int tracepoint_id;
            if ((tracepoint_id = findTracepointId("tracing", name)) > 0 ||
                (tracepoint_id = findTracepointId("debug/tracing", name)) > 0) {
                return getTracepoint(tracepoint_id);
            }
        }

        // Finally, treat event as a function name and return an execution breakpoint
        return getBreakpoint(name, HW_BREAKPOINT_X, sizeof(long));
    }
};

// See perf_event_open(2)
#define LOAD_MISS(perf_hw_cache_id) \
    ((perf_hw_cache_id) | PERF_COUNT_HW_CACHE_OP_READ << 8 | PERF_COUNT_HW_CACHE_RESULT_MISS << 16)

// Hardware breakpoint with interval=1 causes an infinite loop on ARM64
#ifdef __aarch64__
#  define BKPT_INTERVAL 2
#else
#  define BKPT_INTERVAL 1
#endif

class RingBuffer {
  private:
    const char* _start;
    unsigned long _offset;

  public:
    RingBuffer(struct perf_event_mmap_page* page) {
        _start = (const char*)page + OS::page_size;
    }

    struct perf_event_header* seek(u64 offset) {
        _offset = (unsigned long)offset & OS::page_mask;
        return (struct perf_event_header*)(_start + _offset);
    }

    u64 next() {
        _offset = (_offset + sizeof(u64)) & OS::page_mask;
        return *(u64*)(_start + _offset);
    }

    u64 peek(unsigned long words) {
        unsigned long peek_offset = (_offset + words * sizeof(u64)) & OS::page_mask;
        return *(u64*)(_start + peek_offset);
    }
};


class PerfEvent : public SpinLock {
  private:
    int _fd;
    struct perf_event_mmap_page* _page;

    friend class PerfEvents;
};


#endif // __linux__


#endif //SRC_PERFEVENTS_LINUX_H

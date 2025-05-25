/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "perfEvents_linux.h"

int PerfEvents::_max_events = 0;
PerfEvent* PerfEvents::_events = NULL;
PerfEventType* PerfEvents::_event_type = NULL;
bool PerfEvents::_alluser;
bool PerfEvents::_kernel_stack;
int PerfEvents::_target_cpu;

int PerfEvents::createForThread(int tid) {
    if (tid >= _max_events) {
        Log::warn("tid[%d] > pid_max[%d]. Restart profiler after changing pid_max", tid, _max_events);
        return -1;
    }

    // Mark _events[tid] early to prevent duplicates. Real fd will be put later.
    if (!__sync_bool_compare_and_swap(&_events[tid]._fd, 0, -1)) {
        // Lost race. The event is created either from PerfEvents::start() or from pthread hook.
        return -1;
    }

    PerfEventType* event_type = _event_type;
    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = event_type->type;

    if (attr.type == PERF_TYPE_BREAKPOINT) {
        attr.bp_type = event_type->config;
    } else {
        attr.config = event_type->config;
    }
    attr.config1 = event_type->config1;
    attr.config2 = event_type->config2;

    // Hardware events may not always support zero skid
    if (attr.type == PERF_TYPE_SOFTWARE) {
        attr.precise_ip = 2;
    }

    attr.sample_period = _interval;
    attr.sample_type = PERF_SAMPLE_CALLCHAIN;
    attr.disabled = 1;
    attr.wakeup_events = 1;

    if (_alluser) {
        attr.exclude_kernel = 1;
    }

    if (!_kernel_stack) {
        attr.exclude_callchain_kernel = 1;
    }

    if (_cstack >= CSTACK_FP) {
        attr.exclude_callchain_user = 1;
    }

#ifdef PERF_ATTR_SIZE_VER5
    if (_cstack == CSTACK_LBR) {
        attr.sample_type |= PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_REGS_USER;
        attr.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_CALL_STACK;
        attr.sample_regs_user = 1ULL << PERF_REG_PC;
    }
#else
#warning "Compiling without LBR support. Kernel headers 4.1+ required"
#endif

    int fd;
    if (FdTransferClient::hasPeer()) {
        fd = FdTransferClient::requestPerfFd(&tid, _target_cpu, &attr);
    } else {
        fd = syscall(__NR_perf_event_open, &attr, tid, _target_cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd == -1 && errno == EINVAL) {
            // Try again without CLOEXEC, it's not supported in very old kernels
            fd = syscall(__NR_perf_event_open, &attr, tid, _target_cpu, -1, 0);
        }
    }

    if (fd == -1) {
        int err = errno;
        Log::warn("perf_event_open for TID %d failed: %s", tid, strerror(err));
        _events[tid]._fd = 0;
        if (isResourceLimit(err) && _current != NULL) {
            // Emergency shutdown
            stop();
        }
        return err;
    }

    void* page = NULL;
    if (_kernel_stack || _cstack == CSTACK_DEFAULT || _cstack == CSTACK_LBR) {
        page = mmap(NULL, 2 * OS::page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (page == MAP_FAILED) {
            Log::warn("perf_event mmap failed: %s", strerror(errno));
            page = NULL;
        }
    }

    _events[tid].reset();
    _events[tid]._fd = fd;
    _events[tid]._page = (struct perf_event_mmap_page*)page;

    struct f_owner_ex ex;
    ex.type = F_OWNER_TID;
    ex.pid = tid;

    int err;
    if (fcntl(fd, F_SETFL, O_ASYNC) < 0 || fcntl(fd, F_SETSIG, _signal) < 0 || fcntl(fd, F_SETOWN_EX, &ex) < 0) {
        err = errno;
        Log::warn("perf_event fcntl failed: %s", strerror(err));
    } else if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0 || ioctl(fd, PERF_EVENT_IOC_REFRESH, 1) < 0) {
        err = errno;
        Log::warn("perf_event ioctl failed: %s", strerror(err));
    } else {
        return 0;
    }

    // Failed to setup perf_event - rollback changes
    if (page != NULL) {
        munmap(page, 2 * OS::page_size);
        _events[tid]._page = NULL;
    }
    close(fd);
    _events[tid]._fd = 0;

    return err;
}

void PerfEvents::destroyForThread(int tid) {
    if (tid >= _max_events) {
        return;
    }

    PerfEvent* event = &_events[tid];
    int fd = event->_fd;
    if (fd > 0 && __sync_bool_compare_and_swap(&event->_fd, fd, 0)) {
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        close(fd);
    }
    if (event->_page != NULL) {
        event->lock();
        munmap(event->_page, 2 * OS::page_size);
        event->_page = NULL;
        event->unlock();
    }
}

u64 PerfEvents::readCounter(siginfo_t* siginfo, void* ucontext) {
    switch (_event_type->counter_arg) {
        case 1: return StackFrame(ucontext).arg0();
        case 2: return StackFrame(ucontext).arg1();
        case 3: return StackFrame(ucontext).arg2();
        case 4: return StackFrame(ucontext).arg3();
        default: {
            u64 counter;
            return read(siginfo->si_fd, &counter, sizeof(counter)) == sizeof(counter) ? counter : 1;
        }
    }
}

void PerfEvents::signalHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    if (siginfo->si_code <= 0) {
        // Looks like an external signal; don't treat as a profiling event
        return;
    }

    if (_enabled) {
        ExecutionEvent event(TSC::ticks());
        u64 counter = readCounter(siginfo, ucontext);
        Profiler::instance()->recordSample(ucontext, counter, PERF_SAMPLE, &event);
    } else {
        resetBuffer(OS::threadId());
    }

    ioctl(siginfo->si_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(siginfo->si_fd, PERF_EVENT_IOC_REFRESH, 1);
}

void PerfEvents::signalHandlerJ9(int signo, siginfo_t* siginfo, void* ucontext) {
    if (siginfo->si_code <= 0) {
        // Looks like an external signal; don't treat as a profiling event
        return;
    }

    if (_enabled) {
        u64 counter = readCounter(siginfo, ucontext);
        J9StackTraceNotification notif;
        StackContext java_ctx;
        notif.num_frames = _cstack == CSTACK_NO ? 0 : walk(OS::threadId(), ucontext, notif.addr, MAX_J9_NATIVE_FRAMES, &java_ctx);
        J9StackTraces::checkpoint(counter, &notif);
    } else {
        resetBuffer(OS::threadId());
    }

    ioctl(siginfo->si_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(siginfo->si_fd, PERF_EVENT_IOC_REFRESH, 1);
}

const char* PerfEvents::title() {
    if (_event_type == NULL || strcmp(_event_type->name, "cpu-clock") == 0) {
        return "CPU profile";
    } else if (_event_type->type == PERF_TYPE_SOFTWARE || _event_type->type == PERF_TYPE_HARDWARE || _event_type->type == PERF_TYPE_HW_CACHE) {
        return _event_type->name;
    } else {
        return "Flame Graph";
    }
}

const char* PerfEvents::units() {
    return _event_type == NULL || strcmp(_event_type->name, "cpu-clock") == 0 ? "ns" : "total";
}

Error PerfEvents::check(Arguments& args) {
    PerfEventType* event_type = PerfEventType::forName(args._event);
    if (event_type == NULL) {
        return Error("Unsupported event type");
    } else if (event_type->counter_arg > 4) {
        return Error("Only arguments 1-4 can be counted");
    }

    if (!setupThreadHook()) {
        return Error("Could not set pthread hook");
    }

    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = event_type->type;

    if (attr.type == PERF_TYPE_BREAKPOINT) {
        attr.bp_type = event_type->config;
    } else {
        attr.config = event_type->config;
    }
    attr.config1 = event_type->config1;
    attr.config2 = event_type->config2;

    attr.sample_period = event_type->default_interval;
    attr.sample_type = PERF_SAMPLE_CALLCHAIN;
    attr.disabled = 1;

    if (args._alluser) {
        attr.exclude_kernel = 1;
    }

#ifdef PERF_ATTR_SIZE_VER5
    if (args._cstack == CSTACK_LBR) {
        attr.sample_type |= PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_REGS_USER;
        attr.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_CALL_STACK;
        attr.sample_regs_user = 1ULL << PERF_REG_PC;
    }
#endif

    int fd = syscall(__NR_perf_event_open, &attr, 0, args._target_cpu, -1, 0);
    if (fd == -1) {
        return Error(strerror(errno));
    }

    close(fd);
    return Error::OK;
}

Error PerfEvents::start(Arguments& args) {
    _event_type = PerfEventType::forName(args._event);
    if (_event_type == NULL) {
        return Error("Unsupported event type");
    } else if (_event_type->counter_arg > 4) {
        return Error("Only arguments 1-4 can be counted");
    }

    if (!setupThreadHook()) {
        return Error("Could not set pthread hook");
    }

    _target_cpu = args._target_cpu;

    if (args._interval < 0) {
        return Error("interval must be positive");
    }
    _interval = args._interval ? args._interval : _event_type->default_interval;
    _cstack = args._cstack;
    _signal = args._signal == 0 ? OS::getProfilingSignal(0) : args._signal & 0xff;
    _count_overrun = false;

    _alluser = args._alluser;
    _kernel_stack = !_alluser && _cstack != CSTACK_NO;
    if (_kernel_stack && !Symbols::haveKernelSymbols()) {
        Log::warn("Kernel symbols are unavailable due to restrictions. Try\n"
                  "  sysctl kernel.perf_event_paranoid=1\n"
                  "  sysctl kernel.kptr_restrict=0");
        _kernel_stack = false;
        // Automatically switch on alluser for non-CPU events, if kernel profiling is unavailable
        _alluser = strcmp(args._event, EVENT_CPU) != 0 && !supported();
    }

    adjustFDLimit();

    int max_events = OS::getMaxThreadId();
    if (max_events != _max_events) {
        free(_events);
        _events = (PerfEvent*)calloc(max_events, sizeof(PerfEvent));
        _max_events = max_events;
    }

    if (VM::isOpenJ9()) {
        OS::installSignalHandler(_signal, signalHandlerJ9);
        Error error = J9StackTraces::start(args);
        if (error) {
            return error;
        }
    } else {
        OS::installSignalHandler(_signal, signalHandler);
    }

    // Enable pthread hook before traversing currently running threads
    enableThreadHook();

    // Create perf_events for all existing threads
    int err = createForAllThreads();
    if (err) {
        stop();
        if (err == EACCES || err == EPERM) {
            return Error("Perf events unavailable. Try --fdtransfer or --all-user option or 'sysctl kernel.perf_event_paranoid=1'");
        } else if (isResourceLimit(err)) {
            return Error("Perf events resource limit. Check 'ulimit -n'");
        } else {
            return Error("Perf events unavailable");
        }
    }
    return Error::OK;
}

void PerfEvents::stop() {
    disableThreadHook();
    for (int i = 0; i < _max_events; i++) {
        destroyForThread(i);
    }
    J9StackTraces::stop();
}



int PerfEvents::walk(int tid, void* ucontext, const void** callchain, int max_depth, StackContext* java_ctx) {
    PerfEvent* event = &_events[tid];
    if (!event->tryLock()) {
        return 0;  // the event is being destroyed
    }

    int depth = 0;

    struct perf_event_mmap_page* page = event->_page;
    if (page != NULL) {
        u64 tail = page->data_tail;
        u64 head = page->data_head;
        rmb();

        RingBuffer ring(page);

        while (tail < head) {
            struct perf_event_header* hdr = ring.seek(tail);
            if (hdr->type == PERF_RECORD_SAMPLE) {
                u64 nr = ring.next();
                while (nr-- > 0) {
                    u64 ip = ring.next();
                    if (ip < PERF_CONTEXT_MAX) {
                        const void* iptr = (const void*)ip;
                        if (CodeHeap::contains(iptr) || depth >= max_depth) {
                            // Stop at the first Java frame
                            java_ctx->pc = iptr;
                            goto stack_complete;
                        }
                        callchain[depth++] = iptr;
                    }
                }

                if (_cstack == CSTACK_LBR) {
                    u64 bnr = ring.next();

                    // Last userspace PC is stored right after branch stack
                    const void* pc = (const void*)ring.peek(bnr * 3 + 2);
                    if (CodeHeap::contains(pc) || depth >= max_depth) {
                        java_ctx->pc = pc;
                        goto stack_complete;
                    }
                    callchain[depth++] = pc;

                    while (bnr-- > 0) {
                        const void* from = (const void*)ring.next();
                        const void* to = (const void*)ring.next();
                        ring.next();

                        if (CodeHeap::contains(to) || depth >= max_depth) {
                            java_ctx->pc = to;
                            goto stack_complete;
                        }
                        callchain[depth++] = to;

                        if (CodeHeap::contains(from) || depth >= max_depth) {
                            java_ctx->pc = from;
                            goto stack_complete;
                        }
                        callchain[depth++] = from;
                    }
                }

                break;
            }
            tail += hdr->size;
        }

        stack_complete:
        page->data_tail = head;
    }

    event->unlock();

    if (_cstack == CSTACK_FP) {
        depth += StackWalker::walkFP(ucontext, callchain + depth, max_depth - depth, java_ctx);
    } else if (_cstack == CSTACK_DWARF) {
        depth += StackWalker::walkDwarf(ucontext, callchain + depth, max_depth - depth, java_ctx);
    }

    return depth;
}

void PerfEvents::resetBuffer(int tid) {
    PerfEvent* event = &_events[tid];
    if (!event->tryLock()) {
        return;  // the event is being destroyed
    }

    struct perf_event_mmap_page* page = event->_page;
    if (page != NULL) {
        u64 head = page->data_head;
        rmb();
        page->data_tail = head;
    }

    event->unlock();
}

// This function determines engine selection for CPU profiling.
// Returns true if perf_events AND kernel measurements are available.
bool PerfEvents::supported() {
    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 1000000000;
    attr.sample_type = PERF_SAMPLE_CALLCHAIN;
    attr.disabled = 1;

    int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd == -1) {
        return false;
    }

    close(fd);
    return true;
}

PerfEventType PerfEventType::AVAILABLE_EVENTS[] = {
        {"cpu-clock",    DEFAULT_INTERVAL, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK},
        {"page-faults",                 1, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS},
        {"context-switches",            2, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES},

        {"cycles",                1000000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
        {"instructions",          1000000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
        {"cache-references",      1000000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
        {"cache-misses",             1000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
        {"branch-instructions",   1000000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
        {"branch-misses",            1000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
        {"bus-cycles",            1000000, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES},

        {"L1-dcache-load-misses", 1000000, PERF_TYPE_HW_CACHE, LOAD_MISS(PERF_COUNT_HW_CACHE_L1D)},
        {"LLC-load-misses",          1000, PERF_TYPE_HW_CACHE, LOAD_MISS(PERF_COUNT_HW_CACHE_LL)},
        {"dTLB-load-misses",         1000, PERF_TYPE_HW_CACHE, LOAD_MISS(PERF_COUNT_HW_CACHE_DTLB)},

        /* End of IDX_PREDEFINED events */

        {"rNNN",                     1000, PERF_TYPE_RAW, 0}, /* IDX_RAW */
        {"pmu/event-descriptor/",    1000, PERF_TYPE_RAW, 0}, /* IDX_PMU */

        {"mem:breakpoint",  BKPT_INTERVAL, PERF_TYPE_BREAKPOINT, 0}, /* IDX_BREAKPOINT */
        {"trace:tracepoint",            1, PERF_TYPE_TRACEPOINT, 0}, /* IDX_TRACEPOINT */

        {"kprobe:func",                 1, 0, 0}, /* IDX_KPROBE */
        {"uprobe:path",                 1, 0, 0}, /* IDX_UPROBE */
};

const char* PerfEvents::getEventName(int event_id) {
    if (event_id >= 0 && (size_t)event_id < sizeof(PerfEventType::AVAILABLE_EVENTS) / sizeof(PerfEventType)) {
        return PerfEventType::AVAILABLE_EVENTS[event_id].name;
    }
    return NULL;
}

FunctionWithCounter PerfEventType::KNOWN_FUNCTIONS[] = {
        {"malloc",   1},
        {"mmap",     2},
        {"munmap",   2},
        {"read",     3},
        {"write",    3},
        {"send",     3},
        {"recv",     3},
        {"sendto",   3},
        {"recvfrom", 3},
        {NULL}
};

char PerfEventType::probe_func[256];

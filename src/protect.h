/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PROTECT_H
#define _PROTECT_H

#include "arch.h"


class Protect {
private:
    static volatile int _protectedOperations;
    static volatile int _timesProtected;
public:
    inline Protect() {
        atomicInc(_protectedOperations, 1);
        atomicInc(_timesProtected, 1);
    }
    inline ~Protect() { atomicInc(_protectedOperations, -1); }
    static bool protectedOperation() { return _protectedOperations > 0; }
    static int timesProtected() { return _timesProtected; }
};

#endif


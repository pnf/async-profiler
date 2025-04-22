/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "engine.h"


volatile bool Engine::_enabled = false;

Error Engine::check(Arguments& args) {
    return Error::OK;
}

Error Engine::start(Arguments& args) {
    return Error::OK;
}

void Engine::stop() {
}

// MS: by default does nothing, since most methods have nothing to do with native memory
void Engine::stop_jemalloc() {
}

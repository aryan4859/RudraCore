#pragma once

#include "types.h"

namespace Rudracore::Core {
struct Task;
}

// Futexes: threads block on a 32-bit word in memory until another thread
// wakes them, with no kernel object in between. Keyed by the word's
// physical address, so threads of different processes sharing the memory
// meet too. Userspace builds its mutexes and condition variables on them
// (Kapala::Mutex): the uncontended case never enters the kernel.
namespace Rudracore::Futex {

// The thread waits on `key` (it's blocked by the caller).
void wait(Core::Task* thread, u64 key);

// Wakes up to `count` threads waiting on `key`; returns how many.
u64 wake(u64 key, u64 count);

// The thread no longer waits (woken, timed out, or ending).
void forget(Core::Task* thread);

} // namespace Rudracore::Futex

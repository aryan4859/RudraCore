#pragma once

#include "types.h"

// Kernel instrumentation: event counters, updated where things happen
// (relaxed atomics: any CPU, no lock needed) and read by kernel_counters.
namespace Rudracore::Counters {

struct All {
    u64 syscalls, interrupts, pageFaults;
    u64 switches, switchCycles;                      // context switches, and TSC cycles spent in them
    u64 lockAcquires, lockContended, lockSpinCycles; // the kernel lock: how often others held it, how long waited
    u64 ipis, shootdowns;
    u64 heapAllocs, heapCycles;                      // kernel heap allocations and their cost
};

inline All all{};

inline void add(u64& counter, u64 n = 1) { __atomic_fetch_add(&counter, n, __ATOMIC_RELAXED); }

} // namespace Rudracore::Counters

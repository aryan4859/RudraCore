#pragma once

#include "types.h"

// Kernel heap: small objects come from per-size free lists carved out of
// whole pages; anything bigger than 2 KiB gets its own pages from the PMM.
// Every block has a 16-byte header so free() knows where it came from and
// can catch bad or double frees.
//
// Diagnostics: a guard word right after each block's bytes (where there's
// room) is checked when it's freed, so writing past the end panics instead
// of corrupting the next block silently; freed small blocks are filled with
// 0xDE, so a use after free reads nonsense instead of stale data; check()
// walks every free list; report() logs it all. When the PMM runs dry, memory
// pressure is relieved (file pages dropped) and the allocation tried again
// before it fails.
namespace Rudracore::Heap {

void* alloc(usize size);

void free(void* ptr);

constexpr usize CLASS_COUNT = 7; // 32, 64 ... 2048 bytes

struct Stats {
    u64 bytesInUse; // requested sizes of live allocations
    u64 pagesUsed;  // pages taken from the PMM
    u64 peakBytes;  // most bytesInUse ever
    u64 allocations, frees, failures;
    u64 bigBlocks;  // live allocations over 2 KiB
    u64 classBlocks[CLASS_COUNT]; // live small blocks, per size class
    u64 classPages[CLASS_COUNT];  // pages carved into each size class
};

Stats stats();

// Walks every free list: true if every block on them is intact.
bool check();

// Logs the statistics (diagnostic boots, out-of-memory).
void report();

} // namespace Rudracore::Heap

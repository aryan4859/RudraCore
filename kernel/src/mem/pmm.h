#pragma once

#include "boot.h"

// Physical memory manager: hands out 4 KiB physical pages.
//
// A bitmap with one bit per page (1 = used) covers all RAM up to the highest
// usable address. The bitmap itself is stored in the first usable region big
// enough to hold it. Safe to call from any task: allocation runs with
// interrupts disabled (single CPU).
namespace Rudracore::Pmm {

struct Stats {
    u64 managedPages; // pages ever given to the allocator
    u64 freePages;
    u64 bitmapBytes;
    u64 promisedPages; // promised to programs but not taken yet (demand paging)
    u64 lowWater;      // below this many available pages, memory is under pressure
};

void init(Boot::Info const& info);

// Allocates `count` physically contiguous pages, all below `below` if it's
// not 0 (for devices that can only reach the first 4 GiB, BELOW_4G).
// Returns the physical address of the first one, or 0 if there's not enough
// memory (page 0 is never handed out, so 0 always means failure).
u64 alloc(usize count = 1, u64 below = 0);

// Same as alloc(), with the pages filled with zeros.
u64 allocZeroed(usize count = 1, u64 below = 0);

constexpr u64 BELOW_4G = 1ull << 32;

void free(u64 physical, usize count = 1);

// Gives the bootloader's memory (its page tables, stack and boot info) to the
// allocator. Only safe once the kernel runs on its own page tables and stack
// and has copied everything it needs out of the boot info.
void reclaimBootloaderMemory(Boot::Info const& info);

Stats stats();

// True if `pages` more pages may be used on a program's behalf. A reserve
// stays free for the kernel's own allocations (objects, page tables, task
// stacks), so a program that uses up memory gets OUT_OF_MEMORY instead of
// making the kernel panic. Checked before anything a system call allocates.
bool userCanUse(u64 pages);

// Commit accounting for demand paging. Memory a program reserves isn't
// allocated until it's touched, but it's promised at once: promise() takes
// it out of what userCanUse() offers, so a touch never finds RAM gone.
// allocPromised() turns one promised page into a real (zeroed) one;
// unpromise() gives back promises never used.
bool promise(u64 pages);
void unpromise(u64 pages);
u64 allocPromised();
// Frees a page allocPromised() gave, and promises it again (it wasn't used).
void freePromised(u64 page);

// Pages available for programs: free minus promised.
u64 available();

// Called when memory runs short, to give some back (Vm drops file pages a
// pager can supply again). Returns the pages freed.
using Reclaimer = u64 (*)(u64 wanted);
void setReclaimer(Reclaimer reclaimer);
// Runs the reclaimer if fewer than `pages` (plus the low-water mark) are available.
void relievePressure(u64 pages);

} // namespace Rudracore::Pmm

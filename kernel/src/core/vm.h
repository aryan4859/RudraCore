#pragma once

#include "types.h"

namespace Rudracore::Core {
struct Task;
struct Process;
struct SharedMemory;
} // namespace Rudracore::Core

// A program's address space as regions: what each range of addresses is,
// and what happens the first time it's touched.
//   Anonymous  private memory, zero-filled on first touch (demand paging):
//              memory_alloc, the stack, a program's .bss
//   Shared     a memory object's own pages: writes reach everyone who maps it
//   Copy       a memory object's pages, read in place until written; a write
//              gets the program its own copy of that page (copy-on-write).
//              Program images (from sealed boot files and apps) and
//              memory_map(MAP_COPY)
// Memory a region may need is promised when it's made (Pmm::promise) and
// charged to the program's quota, so a page fault never runs out of RAM a
// program was given; it's allocated only when touched.
//
// Pages of paged objects (memory-mapped files) come from their pager: a
// fault on one that isn't there asks for it and blocks the program until it
// arrives (SYS_MEMORY_SUPPLY). Under memory pressure those pages are dropped
// again (the pager can always supply them anew).
namespace Rudracore::Vm {

enum class Kind : u8 { Anonymous, Shared, Copy };

struct Region {
    u64 start = 0, size = 0;
    Kind kind = Kind::Anonymous;
    bool writable = false, executable = false;
    bool mayWrite = false; // may be made writable (again) with protect
    Core::SharedMemory* object = nullptr; // Shared, Copy: holds a reference
    u64 offset = 0;       // into the object (page aligned)
    u64 visible = 0;      // Copy: bytes of the object shown from `start`; zeros after them
    u64 committed = 0;    // pages promised and charged for it
    u64 privatePages = 0; // pages of its own it holds now (of those)

    u64 end() const { return start + size; }
};

struct Map {
    Region* regions = nullptr; // sorted by address, never overlapping
    u32 count = 0, capacity = 0;
};

constexpr u64 MAP_BASE = 0x100000000;          // mappings go from 4 GiB...
constexpr u64 MAP_LIMIT = 0x00007f0000000000;  // ...up to here
constexpr u32 MAX_REGIONS = 512;

enum class Fault : u8 {
    Resolved,    // mapped now: run the instruction again
    Invalid,     // no region, or not allowed (write to read-only, execute data)
    Pending,     // waiting for a pager: the task is registered, block it
    Retry,       // the pager's queue is full: try again in a moment
    OutOfMemory, // no RAM even for promised memory
};

// Each returns an Abi::Error (OK); `address` gets where the region went.
// `at` is a fixed address (0: the first free gap from MAP_BASE).
i64 mapAnonymous(Core::Process& process, u64 size, bool writable, u64 at, u64& address);
i64 mapObject(Core::Process& process, Core::SharedMemory* object, Kind kind, u64 offset, u64 size, u64 visible,
              bool writable, bool executable, u64 at, u64& address);
// Removes the region starting at `address`, freeing its private pages.
i64 unmap(Core::Process& process, u64 address);
// Makes the region at `address` read-only (or writable again, if it was made so).
i64 protect(Core::Process& process, u64 address, bool writable);

// A user page fault at `address` in `thread` (which waits, if it's Pending).
Fault fault(Core::Task& thread, u64 address, bool write, bool execute);

// Makes [address, address + length) present (and writable, if asked) before
// the kernel touches it in a system call.
Fault prepare(Core::Task& thread, u64 address, u64 length, bool write);

// Drops every region (the process is ending; its space is gone already).
void release(Core::Process& process);

// A thread ends: it no longer waits for a page.
void forgetWait(Core::Task& thread);

// handle_revoke: every other program's regions of `object` go.
void revoke(Core::SharedMemory* object, Core::Process* except);
// memory_seal: writable shared mappings of `object` become read-only.
void seal(Core::SharedMemory* object);

// A pager supplied page `index` of a paged object (`physical`, a fresh page
// now owned by the object): installs it and wakes who waited.
void supplied(Core::SharedMemory* object, u64 index, u64 physical);
// A paged object's pager is gone: its waiters wake (and fault for good).
void pagerGone(Core::SharedMemory* object);

// Memory pressure: drops pager-supplied pages until about `wanted` are
// free. Returns the pages freed.
u64 reclaim(u64 wanted);

struct Usage {
    u64 committed; // pages promised to it
    u64 resident;  // private pages it holds
    u64 shared;    // pages of objects it maps
    u32 regions;
};
Usage usage(Core::Process const& process);

// After a fault ran out of RAM: frees memory by ending the app that holds
// the most (never a system process). Returns the process to end (the
// current one, if it's the biggest app: the caller ends it), or nullptr if
// there was none. Any other is ended here.
Core::Process* outOfMemory(Core::Process* current);

} // namespace Rudracore::Vm

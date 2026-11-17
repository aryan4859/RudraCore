#include "mem/heap.h"

#include "core/counters.h"
#include "arch/x86_64/cpu.h"
#include "log.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "panic.h"

extern "C" void* memset(void* dest, int value, usize n);

namespace Rudracore::Heap {

namespace {

constexpr u32 MAGIC_USED = 0xB4A1A7ED;
constexpr u32 MAGIC_FREE = 0xF7EEB10C;
constexpr u32 GUARD = 0x6AA2D5A1; // after a block's bytes
constexpr u8 POISON = 0xDE;       // in freed small blocks
constexpr u32 BIG = 0xFF;

struct Header {
    u32 magic;
    u32 sizeClass; // index into BLOCK_SIZES, or BIG
    u32 size;      // requested size
    u32 pages;     // for BIG blocks
};
static_assert(sizeof(Header) == 16);

struct FreeBlock {
    Header header;
    FreeBlock* next;
};

constexpr usize BLOCK_SIZES[] = {32, 64, 128, 256, 512, 1024, 2048};
static_assert(sizeof(BLOCK_SIZES) / sizeof(BLOCK_SIZES[0]) == CLASS_COUNT);

FreeBlock* freeLists[CLASS_COUNT];
Stats counters{};

// Pages from the PMM; if it's dry, memory pressure is relieved first.
u64 takePages(u64 pages) {
    u64 physical = Pmm::alloc(pages);
    if (not physical) {
        Pmm::relievePressure(pages);
        physical = Pmm::alloc(pages);
    }
    return physical;
}

bool refill(usize sizeClass) {
    u64 physical = takePages(1);
    if (not physical)
        return false;
    counters.pagesUsed++;
    counters.classPages[sizeClass]++;

    auto* page = Mem::toVirtual<u8>(physical);
    usize blockSize = BLOCK_SIZES[sizeClass];
    for (usize offset = 0; offset + blockSize <= Mem::PAGE_SIZE; offset += blockSize) {
        auto* block = reinterpret_cast<FreeBlock*>(page + offset);
        block->header = {MAGIC_FREE, static_cast<u32>(sizeClass), 0, 0};
        block->next = freeLists[sizeClass];
        freeLists[sizeClass] = block;
    }
    return true;
}

// The guard word goes right after the bytes asked for, when the block has room.
u64 capacity(Header const* h) {
    return h->sizeClass == BIG ? u64{h->pages} * Mem::PAGE_SIZE : BLOCK_SIZES[h->sizeClass];
}

void setGuard(Header* h) {
    if (sizeof(Header) + h->size + sizeof(GUARD) <= capacity(h))
        __builtin_memcpy(reinterpret_cast<u8*>(h) + sizeof(Header) + h->size, &GUARD, sizeof(GUARD));
}

bool guardIntact(Header const* h) {
    if (sizeof(Header) + h->size + sizeof(GUARD) > capacity(h))
        return true;
    u32 value;
    __builtin_memcpy(&value, reinterpret_cast<u8 const*>(h) + sizeof(Header) + h->size, sizeof(value));
    return value == GUARD;
}

void used(u64 size) {
    counters.allocations++;
    counters.bytesInUse += size;
    if (counters.bytesInUse > counters.peakBytes)
        counters.peakBytes = counters.bytesInUse;
}

} // namespace

void* allocate(usize size);

// (Timed: memory allocation performance, in kernel_counters.)
void* alloc(usize size) {
    Arch::InterruptGuard guard;
    u64 started = Arch::readTsc();
    void* p = allocate(size);
    Counters::add(Counters::all.heapAllocs);
    Counters::add(Counters::all.heapCycles, Arch::readTsc() - started);
    return p;
}

void* allocate(usize size) {
    usize needed = size + sizeof(Header);

    for (usize c = 0; c < CLASS_COUNT; c++) {
        if (BLOCK_SIZES[c] < needed)
            continue;
        if (not freeLists[c] and not refill(c)) {
            counters.failures++;
            return nullptr;
        }

        FreeBlock* block = freeLists[c];
        if (block->header.magic != MAGIC_FREE)
            panic("heap: a free list is corrupted (a block was written after it was freed)");
        freeLists[c] = block->next;
        block->header = {MAGIC_USED, static_cast<u32>(c), static_cast<u32>(size), 0};
        setGuard(&block->header);
        counters.classBlocks[c]++;
        used(size);
        return reinterpret_cast<u8*>(block) + sizeof(Header);
    }

    // Big allocation: whole pages.
    u64 pages = Mem::alignUp(needed, Mem::PAGE_SIZE) / Mem::PAGE_SIZE;
    u64 physical = takePages(pages);
    if (not physical) {
        counters.failures++;
        return nullptr;
    }
    counters.pagesUsed += pages;
    counters.bigBlocks++;

    auto* header = Mem::toVirtual<Header>(physical);
    *header = {MAGIC_USED, BIG, static_cast<u32>(size), static_cast<u32>(pages)};
    setGuard(header);
    used(size);
    return reinterpret_cast<u8*>(header) + sizeof(Header);
}

void free(void* ptr) {
    if (not ptr)
        return;

    Arch::InterruptGuard guard;
    auto* header = reinterpret_cast<Header*>(static_cast<u8*>(ptr) - sizeof(Header));
    if (header->magic == MAGIC_FREE)
        panic("heap: double free");
    if (header->magic != MAGIC_USED)
        panic("heap: freeing a pointer that didn't come from the heap");
    if (header->sizeClass != BIG and header->sizeClass >= CLASS_COUNT)
        panic("heap: corrupted block header");
    if (not guardIntact(header))
        panic("heap: a block was written past its end");

    counters.bytesInUse -= header->size;
    counters.frees++;

    if (header->sizeClass == BIG) {
        u64 pages = header->pages;
        header->magic = MAGIC_FREE;
        counters.pagesUsed -= pages;
        counters.bigBlocks--;
        Pmm::free(reinterpret_cast<u64>(header) - Mem::hhdmOffset, pages);
        return;
    }

    usize c = header->sizeClass;
    auto* block = reinterpret_cast<FreeBlock*>(header);
    memset(reinterpret_cast<u8*>(block) + sizeof(FreeBlock), POISON, BLOCK_SIZES[c] - sizeof(FreeBlock));
    block->header.magic = MAGIC_FREE;
    block->next = freeLists[c];
    freeLists[c] = block;
    counters.classBlocks[c]--;
}

Stats stats() {
    Arch::InterruptGuard guard;
    return counters;
}

bool check() {
    Arch::InterruptGuard guard;
    for (usize c = 0; c < CLASS_COUNT; c++) {
        u64 limit = counters.classPages[c] * (Mem::PAGE_SIZE / BLOCK_SIZES[c]) + 1; // (a loop ends too)
        for (FreeBlock* b = freeLists[c]; b; b = b->next) {
            if (not limit-- or b->header.magic != MAGIC_FREE or b->header.sizeClass != c)
                return false;
        }
    }
    return true;
}

void report() {
    Stats s = stats();
    log("[heap] ", Bytes{s.bytesInUse}, " in use (peak ", Bytes{s.peakBytes}, ") in ", s.pagesUsed, " pages; ",
        s.allocations, " allocations, ", s.frees, " frees, ", s.failures, " failed; free lists ",
        check() ? "intact" : "CORRUPTED");
    for (usize c = 0; c < CLASS_COUNT; c++) {
        if (s.classPages[c])
            log("[heap]   ", BLOCK_SIZES[c], "-byte blocks: ", s.classBlocks[c], " in use, ", s.classPages[c],
                " page(s)");
    }
    if (s.bigBlocks)
        log("[heap]   larger: ", s.bigBlocks, " block(s)");
}

} // namespace Rudracore::Heap

// C++ allocation operators for the kernel. Allocation failure panics: kernel
// code that can recover from running out of memory calls Heap::alloc directly.

using namespace Rudracore;

static void* allocOrPanic(usize size) {
    void* ptr = Heap::alloc(size);
    if (not ptr) {
        Heap::report();
        panic("heap: out of memory");
    }
    return ptr;
}

void* operator new(usize size) { return allocOrPanic(size); }
void* operator new[](usize size) { return allocOrPanic(size); }
void operator delete(void* ptr) noexcept { Heap::free(ptr); }
void operator delete[](void* ptr) noexcept { Heap::free(ptr); }
void operator delete(void* ptr, usize) noexcept { Heap::free(ptr); }
void operator delete[](void* ptr, usize) noexcept { Heap::free(ptr); }

#include "core/shared_memory.h"

#include "arch/x86_64/iommu.h"
#include "core/channel.h"
#include "mem/heap.h"
#include "mem/pmm.h"

namespace Rudracore::Core {

namespace {

SharedMemory* pagedObjects = nullptr;

} // namespace

SharedMemory::~SharedMemory() {
    if (dmaMapped)
        Arch::Iommu::revoke(physical, size); // no device may write it once it's reused
    if (owned)
        Pmm::free(physical, size / Mem::PAGE_SIZE);
    if (paged()) {
        for (u64 i = 0; i < pageCount(); i++) {
            if (pages[i] > REQUESTED)
                Pmm::free(pages[i]);
        }
        Heap::free(pages);
        for (SharedMemory** link = &pagedObjects; *link; link = &(*link)->nextPaged) {
            if (*link == this) {
                *link = nextPaged;
                break;
            }
        }
        if (pager) {
            pager->pagerOf = nullptr;
            pager->unref(); // the pager sees PEER_CLOSED: nobody maps this anymore
        }
    }
}

SharedMemory* SharedMemory::allocate(u64 size, u64 below) {
    if (size == 0 or size > MAX_SIZE)
        return nullptr;

    u64 aligned = Mem::alignUp(size, Mem::PAGE_SIZE);
    if (not Pmm::userCanUse(aligned / Mem::PAGE_SIZE + 1)) // + the object itself
        return nullptr;
    u64 physical = Pmm::allocZeroed(aligned / Mem::PAGE_SIZE, below);
    if (not physical)
        return nullptr;

    auto* memory = new SharedMemory();
    memory->physical = physical;
    memory->size = aligned;
    memory->owned = true;
    return memory;
}

SharedMemory* SharedMemory::device(u64 physical, u64 size, Vmm::Cache cache) {
    auto* memory = new SharedMemory();
    memory->physical = Mem::alignDown(physical, Mem::PAGE_SIZE);
    memory->size = Mem::alignUp(physical + size, Mem::PAGE_SIZE) - memory->physical;
    memory->owned = false;
    memory->hardware = true;
    memory->cache = cache;
    return memory;
}

SharedMemory* SharedMemory::bootFile(u64 physical, u64 size) {
    auto* memory = new SharedMemory();
    memory->physical = physical;
    memory->size = Mem::alignUp(size, Mem::PAGE_SIZE);
    memory->readOnly = memory->sealed = true;
    return memory;
}

SharedMemory* SharedMemory::createPaged(u64 size, Endpoint* pagerEnd) {
    if (size == 0 or size > MAX_SIZE)
        return nullptr;
    u64 count = Mem::alignUp(size, Mem::PAGE_SIZE) / Mem::PAGE_SIZE;
    auto* table = static_cast<u64*>(Heap::alloc(count * sizeof(u64)));
    if (not table)
        return nullptr;
    for (u64 i = 0; i < count; i++)
        table[i] = 0;
    auto* memory = new SharedMemory();
    memory->size = count * Mem::PAGE_SIZE;
    memory->pages = table;
    memory->readOnly = true; // only the pager writes it (SYS_MEMORY_SUPPLY)
    memory->pager = pagerEnd;
    pagerEnd->ref();
    pagerEnd->pagerOf = memory;
    memory->nextPaged = pagedObjects;
    pagedObjects = memory;
    return memory;
}

SharedMemory* SharedMemory::allPaged() { return pagedObjects; }

} // namespace Rudracore::Core

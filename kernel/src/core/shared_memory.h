#pragma once

#include "core/object.h"
#include "core/quota.h"
#include "mem/memory.h"
#include "mem/vmm.h"

namespace Rudracore::Core {

struct Endpoint;

// Memory that tasks can map. Three kinds:
//   - allocated for the object: physically contiguous, freed with it
//     (SYS_MEMORY_CREATE; the only kind a device may be given, dma_address)
//   - a device's memory, such as the framebuffer, or a boot file: never freed
//   - paged: its pages come on demand from a pager program (the fs server,
//     for memory-mapped files), which is asked for each one the first time a
//     program touches it, and may be asked again after memory pressure
//     dropped it (SYS_MEMORY_CREATE_PAGED, SYS_MEMORY_SUPPLY)
struct SharedMemory : public Object {
    static constexpr u64 MAX_SIZE = 64 * 1024 * 1024;
    static constexpr u64 REQUESTED = 1; // a paged page asked for, not yet supplied

    u64 physical = 0; // contiguous kinds
    u64 size = 0;     // page aligned
    bool owned = false;
    bool hardware = false; // a device's memory (registers, the screen): apps never hold it
    bool isScreen = false; // the boot framebuffer: mapping it hands the screen to userspace
    bool readOnly = false; // mapped without write access (boot image files)
    bool sealed = false;   // contents fixed for good (SYS_MEMORY_SEAL, boot files): safe to share copy-on-write
    bool dmaMapped = false; // given to a device through the IOMMU (dma_address)
    Vmm::Cache cache = Vmm::Cache::WriteBack;

    // Paged objects only.
    u64* pages = nullptr;       // per page: physical address, 0 (absent) or REQUESTED
    Endpoint* pager = nullptr;  // requests are queued on its peer (holds a reference)
    u64 residentPages = 0;
    SharedMemory* nextPaged = nullptr; // every paged object (for reclaiming under pressure)

    SharedMemory() : Object(ObjectType::Memory) {}
    ~SharedMemory() override;

    bool paged() const { return pages != nullptr; }
    u64 pageCount() const { return size / Mem::PAGE_SIZE; }

    // The physical page at `index`, or 0 if a paged object doesn't have it yet.
    u64 pageAt(u64 index) const {
        if (not paged())
            return physical + index * Mem::PAGE_SIZE;
        return pages[index] > REQUESTED ? pages[index] : 0;
    }

    // Zeroed memory of at least `size` bytes, or nullptr. `below`: every
    // page under that physical address (Pmm::BELOW_4G), or 0.
    static SharedMemory* allocate(u64 size, u64 below = 0);

    // Wraps existing device memory.
    static SharedMemory* device(u64 physical, u64 size, Vmm::Cache cache);

    // Wraps a boot file in kernel memory (page aligned): read-only, sealed,
    // never freed. Programs start from it copy-on-write.
    static SharedMemory* bootFile(u64 physical, u64 size);

    // An empty paged object whose pager is `pager`'s peer, or nullptr.
    static SharedMemory* createPaged(u64 size, Endpoint* pager);

    // The paged objects that exist.
    static SharedMemory* allPaged();
};

} // namespace Rudracore::Core

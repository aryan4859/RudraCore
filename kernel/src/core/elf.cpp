#include "core/elf.h"

#include "core/sched.h"
#include "core/shared_memory.h"
#include "core/vm.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "rudracore/syscalls.h"

static_assert(Rudracore::Elf::USER_IMAGE_END <= Rudracore::Vm::MAP_BASE, "program images must stay below shared memory");
static_assert(Rudracore::Elf::USER_STACK_TOP - Rudracore::Elf::USER_STACK_SIZE >= Rudracore::Vm::MAP_LIMIT,
              "the stack must stay above the mappings");

extern "C" void* memcpy(void* dest, void const* src, usize n);

namespace Rudracore::Elf {

namespace {

struct Header {
    u8 ident[16];
    u16 type;
    u16 machine;
    u32 version;
    u64 entry;
    u64 programHeaderOffset;
    u64 sectionHeaderOffset;
    u32 flags;
    u16 headerSize;
    u16 programHeaderSize;
    u16 programHeaderCount;
    u16 sectionHeaderSize;
    u16 sectionHeaderCount;
    u16 sectionNameIndex;
};

struct ProgramHeader {
    u32 type;
    u32 flags;
    u64 offset;
    u64 vaddr;
    u64 paddr;
    u64 fileSize;
    u64 memorySize;
    u64 align;
};

constexpr u8 CLASS_64 = 2;
constexpr u8 LITTLE_ENDIAN = 1;
constexpr u16 TYPE_EXECUTABLE = 2;
constexpr u16 MACHINE_X86_64 = 62;
constexpr u32 SEGMENT_LOAD = 1;
constexpr u32 SEGMENT_DYNAMIC = 2;
constexpr u32 SEGMENT_INTERP = 3;
constexpr u8 VERSION_CURRENT = 1;
constexpr u16 MAX_PROGRAM_HEADERS = 64;
constexpr u32 FLAG_EXEC = 1;
constexpr u32 FLAG_WRITE = 2;

// Lowest address a program may use, so null pointers always fault.
constexpr u64 USER_MIN = 0x10000;

bool validHeader(u8 const* data, usize size, char const*& error) {
    if (size < sizeof(Header)) {
        error = "file too small";
        return false;
    }

    auto const* h = reinterpret_cast<Header const*>(data);
    if (h->ident[0] != 0x7F or h->ident[1] != 'E' or h->ident[2] != 'L' or h->ident[3] != 'F') {
        error = "not an ELF file";
        return false;
    }
    if (h->ident[4] != CLASS_64 or h->ident[5] != LITTLE_ENDIAN or h->ident[6] != VERSION_CURRENT or
        h->version != VERSION_CURRENT or h->machine != MACHINE_X86_64 or h->type != TYPE_EXECUTABLE) {
        error = "not a 64-bit x86_64 executable";
        return false;
    }
    if (h->programHeaderSize != sizeof(ProgramHeader) or h->programHeaderCount > MAX_PROGRAM_HEADERS or
        h->programHeaderOffset > size or
        h->programHeaderCount > (size - h->programHeaderOffset) / sizeof(ProgramHeader)) {
        error = "bad program header table";
        return false;
    }
    return true;
}

u64 firstPage(ProgramHeader const& ph) { return Mem::alignDown(ph.vaddr, Mem::PAGE_SIZE); }
u64 endPage(ProgramHeader const& ph) { return Mem::alignUp(ph.vaddr + ph.memorySize, Mem::PAGE_SIZE); }

// Checks every program header before anything is allocated: a static
// executable, segments inside the image area, file offsets that can be
// mapped page by page, no page both writable and executable (also when two
// segments share a page), and an entry point in executable code.
bool validSegments(ProgramHeader const* headers, u16 count, u64 size, u64 entry, char const*& error) {
    bool entryOk = false;
    for (u16 i = 0; i < count; i++) {
        ProgramHeader const& ph = headers[i];
        if (ph.type == SEGMENT_DYNAMIC or ph.type == SEGMENT_INTERP) {
            error = "dynamically linked programs aren't supported";
            return false;
        }
        if (ph.type != SEGMENT_LOAD or ph.memorySize == 0)
            continue;
        u64 end = ph.vaddr + ph.memorySize;
        if (ph.fileSize > ph.memorySize or ph.offset > size or ph.fileSize > size - ph.offset or
            end < ph.vaddr or ph.vaddr < USER_MIN or end > USER_IMAGE_END) {
            error = "segment outside of the allowed range";
            return false;
        }
        if ((ph.flags & FLAG_WRITE) and (ph.flags & FLAG_EXEC)) {
            error = "a segment is both writable and executable";
            return false;
        }
        if ((ph.vaddr - ph.offset) % Mem::PAGE_SIZE != 0) {
            error = "segment address and file offset don't line up on a page";
            return false;
        }
        for (u16 j = 0; j < i; j++) {
            ProgramHeader const& other = headers[j];
            if (other.type != SEGMENT_LOAD or other.memorySize == 0)
                continue;
            bool overlap = firstPage(ph) < endPage(other) and firstPage(other) < endPage(ph);
            if (overlap and (ph.flags & (FLAG_WRITE | FLAG_EXEC)) != (other.flags & (FLAG_WRITE | FLAG_EXEC))) {
                error = "two segments with different permissions share a page";
                return false;
            }
        }
        if ((ph.flags & FLAG_EXEC) and entry >= ph.vaddr and entry < end)
            entryOk = true;
    }
    if (not entryOk) {
        error = "the entry point isn't in executable code";
        return false;
    }
    return true;
}

bool loadSegment(Vmm::Space& space, u8 const* data, usize size, ProgramHeader const& ph, char const*& error) {
    u64 end = ph.vaddr + ph.memorySize;
    if (ph.fileSize > ph.memorySize or ph.offset > size or ph.fileSize > size - ph.offset or
        end < ph.vaddr or ph.vaddr < USER_MIN or end > USER_IMAGE_END) {
        error = "segment outside of the allowed range";
        return false;
    }

    if ((ph.flags & FLAG_WRITE) and (ph.flags & FLAG_EXEC)) {
        error = "a segment is both writable and executable";
        return false;
    }

    u32 access = Vmm::USER | Vmm::OWNED;
    if (ph.flags & FLAG_WRITE)
        access |= Vmm::WRITE;
    if (ph.flags & FLAG_EXEC)
        access |= Vmm::EXEC;

    u64 fileEnd = ph.vaddr + ph.fileSize;
    for (u64 page = Mem::alignDown(ph.vaddr, Mem::PAGE_SIZE); page < end; page += Mem::PAGE_SIZE) {
        u64 physical;
        if (not space.translate(page, physical)) {
            physical = Pmm::allocZeroed();
            if (not physical or not space.map(page, physical, Mem::PAGE_SIZE, access)) {
                if (physical)
                    Pmm::free(physical);
                error = OUT_OF_MEMORY;
                return false;
            }
        }

        // Copy the part of the file data that falls in this page; the rest
        // stays zero (that's how .bss gets cleared).
        u64 copyStart = max(page, ph.vaddr);
        u64 copyEnd = min(page + Mem::PAGE_SIZE, fileEnd);
        if (copyStart < copyEnd) {
            memcpy(Mem::toVirtual<u8>(physical) + (copyStart - page),
                   data + ph.offset + (copyStart - ph.vaddr),
                   copyEnd - copyStart);
        }
    }
    return true;
}

// True if two loadable segments share a page (allowed when their access is
// the same): then regions can't describe them, and they're copied in.
bool segmentsSharePages(ProgramHeader const* headers, u16 count) {
    for (u16 i = 0; i < count; i++) {
        if (headers[i].type != SEGMENT_LOAD or headers[i].memorySize == 0)
            continue;
        for (u16 j = 0; j < i; j++) {
            if (headers[j].type == SEGMENT_LOAD and headers[j].memorySize and
                firstPage(headers[i]) < endPage(headers[j]) and firstPage(headers[j]) < endPage(headers[i]))
                return true;
        }
    }
    return false;
}

} // namespace

bool mapRegions(Core::Task& task, Core::SharedMemory* image, usize size, Program const& program, char const*& error) {
    (void)size;
    u8 const* data = Mem::toVirtual<u8>(image->physical);
    auto const* header = reinterpret_cast<Header const*>(data);
    auto const* headers = reinterpret_cast<ProgramHeader const*>(data + header->programHeaderOffset);
    u64 at;
    for (u16 i = 0; not program.loaded and i < header->programHeaderCount; i++) {
        ProgramHeader const& ph = headers[i];
        if (ph.type != SEGMENT_LOAD or ph.memorySize == 0)
            continue;
        // Whole pages: the segment's first page starts that much before it in the file.
        u64 start = firstPage(ph), lead = ph.vaddr - start;
        if (Vm::mapObject(task, image, Vm::Kind::Copy, ph.offset - lead, endPage(ph) - start, lead + ph.fileSize,
                          ph.flags & FLAG_WRITE, ph.flags & FLAG_EXEC, start, at) != Abi::OK) {
            error = OUT_OF_MEMORY;
            return false;
        }
    }
    if (Vm::mapAnonymous(task, USER_STACK_SIZE, true, USER_STACK_TOP - USER_STACK_SIZE, at) != Abi::OK) {
        error = OUT_OF_MEMORY;
        return false;
    }
    return true;
}

bool load(Core::SharedMemory* image, usize size, Program& out, char const*& error) {
    u8 const* data = Mem::toVirtual<u8>(image->physical);
    if (size > image->size) {
        error = "file too small";
        return false;
    }
    if (not validHeader(data, size, error))
        return false;

    auto const* header = reinterpret_cast<Header const*>(data);
    if (header->entry < USER_MIN or header->entry >= Vmm::USER_END) {
        error = "entry point outside of user memory";
        return false;
    }

    auto const* phdrs = reinterpret_cast<ProgramHeader const*>(data + header->programHeaderOffset);
    if (not validSegments(phdrs, header->programHeaderCount, size, header->entry, error))
        return false;

    Vmm::Space* space = Vmm::createUserSpace();
    if (not space) {
        error = OUT_OF_MEMORY;
        return false;
    }

    auto const* headers = reinterpret_cast<ProgramHeader const*>(data + header->programHeaderOffset);

    // Programs can come from anywhere (installed apps): refuse any that
    // asks for an unreasonable amount of memory before allocating it.
    constexpr u64 MAX_PROGRAM_MEMORY = 256ull * 1024 * 1024;
    u64 total = 0;
    for (u16 i = 0; i < header->programHeaderCount; i++) {
        if (headers[i].type != SEGMENT_LOAD)
            continue;
        if (headers[i].memorySize > MAX_PROGRAM_MEMORY or total + headers[i].memorySize > MAX_PROGRAM_MEMORY) {
            error = "the program asks for too much memory";
            Vmm::destroyUserSpace(space);
            return false;
        }
        total += headers[i].memorySize;
    }

    bool loadedAny = false;
    for (u16 i = 0; i < header->programHeaderCount; i++)
        loadedAny = loadedAny or (headers[i].type == SEGMENT_LOAD and headers[i].memorySize);
    if (not loadedAny) {
        error = "no loadable segments";
        Vmm::destroyUserSpace(space);
        return false;
    }

    // Segments sharing pages: copied in now, the way programs always were.
    bool copy = segmentsSharePages(headers, header->programHeaderCount);
    if (copy) {
        // All it will take: segments (each may straddle one more page), page
        // tables, and the task's kernel stack and state.
        u64 pages = total / Mem::PAGE_SIZE + 2 * header->programHeaderCount + 16;
        if (not Pmm::userCanUse(pages)) {
            error = OUT_OF_MEMORY;
            Vmm::destroyUserSpace(space);
            return false;
        }
        for (u16 i = 0; i < header->programHeaderCount; i++) {
            if (headers[i].type != SEGMENT_LOAD or headers[i].memorySize == 0)
                continue;
            if (not loadSegment(*space, data, size, headers[i], error)) {
                Vmm::destroyUserSpace(space);
                return false;
            }
        }
    }

    out = {space, header->entry, USER_STACK_TOP, copy};
    return true;
}

} // namespace Rudracore::Elf

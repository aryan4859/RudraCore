#pragma once

#include "mem/vmm.h"

namespace Rudracore::Core {
struct Task;
struct SharedMemory;
} // namespace Rudracore::Core

namespace Rudracore::Elf {

// Where a loaded program's stack ends (it grows down from here).
constexpr u64 USER_STACK_TOP = 0x00007ffffffff000;
constexpr u64 USER_STACK_SIZE = 64 * 1024;

// A program's segments must end below this: above it are shared memory
// mappings (from 4 GiB, Task::MAP_BASE), and far above those the stack, so
// the stack has terabytes of unmapped guard below it.
constexpr u64 USER_IMAGE_END = 0x100000000;

struct Program {
    Vmm::Space* space;
    u64 entry;
    u64 stackTop;
    bool loaded; // its segments are in the space already (copied: they share pages)
};

// The error load() gives when memory runs out (compare the pointer).
inline constexpr char const OUT_OF_MEMORY[] = "out of memory";

// Checks a static x86_64 ELF executable in `image` (a sealed object: its
// contents can't change under the program) and makes its address space.
// Segments that share a page with another are copied in now; otherwise
// they're mapped later. On failure returns false and sets `error`; nothing
// is leaked.
bool load(Core::SharedMemory* image, usize size, Program& out, char const*& error);

// Gives the new task its image as regions: each segment copy-on-write from
// the image (code and constants shared by every program started from it,
// data copied when first written, .bss zero-filled on first touch), and its
// stack (on first touch, too). False (and `error`) if memory runs short.
bool mapRegions(Core::Task& task, Core::SharedMemory* image, usize size, Program const& program, char const*& error);

} // namespace Rudracore::Elf

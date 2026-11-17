#include "arch/x86_64/gdt.h"

#include "arch/x86_64/cpu.h"

namespace Rudracore::Arch::Gdt {

namespace {

struct [[gnu::packed]] Tss {
    u32 reserved0;
    u64 rsp[3];
    u64 reserved1;
    u64 ist[7];
    u64 reserved2;
    u16 reserved3;
    u16 ioMapBase;
};
static_assert(sizeof(Tss) == 104);

struct [[gnu::packed]] Pointer {
    u16 limit;
    u64 base;
};

// Flat 64-bit segments: only the access byte and the long-mode bit matter.
constexpr u64 KERNEL_CODE_DESC = 0x00af9a000000ffff;
constexpr u64 KERNEL_DATA_DESC = 0x00cf92000000ffff;
constexpr u64 USER_DATA_DESC = 0x00cff2000000ffff;
constexpr u64 USER_CODE_DESC = 0x00affa000000ffff;

constexpr usize STACK = 16 * 1024;

// One GDT for every CPU, with a TSS descriptor per CPU (each CPU loads its
// own: that's also how a CPU knows which one it is, Smp::index).
alignas(16) u64 entries[TSS / 8 + 2 * MAX_CPUS];
alignas(16) Tss tss[MAX_CPUS];
alignas(16) u8 doubleFaultStacks[MAX_CPUS][STACK];
alignas(16) u8 interruptStacks[MAX_CPUS][STACK];

// A TSS descriptor takes two GDT slots in long mode.
void setTssDescriptor(usize slot, u64 base, u32 limit) {
    entries[slot] = (limit & 0xFFFF) |
                    ((base & 0xFFFFFF) << 16) |
                    (0x89ull << 40) | // present, 64-bit available TSS
                    (u64((limit >> 16) & 0xF) << 48) |
                    (((base >> 24) & 0xFF) << 56);
    entries[slot + 1] = base >> 32;
}

} // namespace

void init() {
    entries[0] = 0;
    entries[KERNEL_CODE / 8] = KERNEL_CODE_DESC;
    entries[KERNEL_DATA / 8] = KERNEL_DATA_DESC;
    entries[USER_DATA / 8] = USER_DATA_DESC;
    entries[USER_CODE / 8] = USER_CODE_DESC;
    for (u32 cpu = 0; cpu < MAX_CPUS; cpu++) {
        tss[cpu] = {};
        tss[cpu].rsp[0] = reinterpret_cast<u64>(interruptStacks[cpu] + STACK);
        tss[cpu].ist[IST_DOUBLE_FAULT - 1] = reinterpret_cast<u64>(doubleFaultStacks[cpu] + STACK);
        tss[cpu].ioMapBase = sizeof(Tss); // no I/O permission bitmap
        setTssDescriptor(TSS / 8 + 2 * cpu, reinterpret_cast<u64>(&tss[cpu]), sizeof(Tss) - 1);
    }
    load(0);
}

void load(u32 cpu) {
    Pointer pointer{sizeof(entries) - 1, reinterpret_cast<u64>(entries)};

    // Load the GDT, reload CS with a far return, then the data segments.
    asm volatile(
        "lgdt %0\n\t"
        "pushq %1\n\t"
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n\t"
        "1:\n\t"
        "movw %w2, %%ds\n\t"
        "movw %w2, %%es\n\t"
        "movw %w2, %%ss\n\t"
        "movw %w2, %%fs\n\t"
        "movw %w2, %%gs\n\t"
        :
        : "m"(pointer), "i"(KERNEL_CODE), "r"(u64(KERNEL_DATA))
        : "rax", "memory");

    asm volatile("ltr %w0" : : "r"(u64(TSS + 16 * cpu)));
}

void setKernelStack(u64 top) {
    tss[Smp::index()].rsp[0] = top;
}

} // namespace Rudracore::Arch::Gdt

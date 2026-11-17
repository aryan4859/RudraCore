#include "arch/x86_64/protect.h"

#include "arch/x86_64/cpu.h"
#include "log.h"

namespace Rudracore::Arch::Protect {

namespace {

constexpr u64 EFER_NXE = 1ull << 11;
constexpr u64 CR0_WP = 1ull << 16;
constexpr u64 CR4_SMEP = 1ull << 20;
constexpr u64 CR4_SMAP = 1ull << 21;

u64 readCr0() {
    u64 v;
    asm volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}

u64 readCr4() {
    u64 v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

} // namespace

void init() {
    writeMsr(Msr::EFER, readMsr(Msr::EFER) | EFER_NXE); // (NX: Cpu::init made sure it's there)

    u64 cr0 = readCr0() | CR0_WP;
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

void enableSmepSmap() {
    bool smep = Cpu::features().smep, smap = Cpu::features().smap;

    u64 cr4 = readCr4() | (smep ? CR4_SMEP : 0) | (smap ? CR4_SMAP : 0);
    asm volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
    smapEnabled = smap;
    if (smap)
        asm volatile("clac" ::: "memory");

    log("[cpu]  nx on, write protect on, smep ", smep ? "on" : "off (not supported)",
        ", smap ", smap ? "on" : "off (not supported)");
}

} // namespace Rudracore::Arch::Protect

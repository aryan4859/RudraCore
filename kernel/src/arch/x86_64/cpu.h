#pragma once

#include "types.h"

namespace Rudracore::Arch {

inline u64 readCr2() {
    u64 value;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

inline u64 readCr3() {
    u64 value;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

inline void writeCr3(u64 value) {
    asm volatile("mov %0, %%cr3" : : "r"(value) : "memory");
}

inline void invalidatePage(u64 virt) {
    asm volatile("invlpg (%0)" : : "r"(virt) : "memory");
}

inline void disableInterrupts() {
    asm volatile("cli" ::: "memory");
}

inline void enableInterrupts() {
    asm volatile("sti" ::: "memory");
}

// Sleeps until the next interrupt.
inline void waitForInterrupt() {
    asm volatile("hlt" ::: "memory");
}

// Multiprocessing (smp.cpp). The kernel lock: one CPU at a time runs kernel
// code (interrupt handlers, system calls, guarded sections), while user code
// runs on every CPU at once. It's recursive, and its depth travels with the
// task that holds it across a task switch.
namespace Smp {
// Which CPU runs this (0: the boot CPU), from the TSS it loaded.
inline u32 index() {
    u16 selector;
    asm volatile("str %0" : "=r"(selector));
    return selector >= 0x28 ? (selector - 0x28u) / 16u : 0u; // (Gdt::TSS + 16 * cpu)
}
void enterKernel(); // waits for the kernel lock (taking IPIs that can't wait meanwhile)
void leaveKernel();
} // namespace Smp

// Disables interrupts and takes the kernel lock for the lifetime of the
// guard, then restores both. Nothing else runs kernel code meanwhile, on
// this CPU or any other. Guards can be nested.
struct InterruptGuard {
    u64 flags;

    InterruptGuard() {
        asm volatile("pushfq; popq %0; cli" : "=r"(flags) : : "memory");
        Smp::enterKernel();
    }

    ~InterruptGuard() {
        Smp::leaveKernel();
        if (flags & (1 << 9)) // IF was set
            asm volatile("sti" ::: "memory");
    }

    InterruptGuard(InterruptGuard const&) = delete;
    InterruptGuard& operator=(InterruptGuard const&) = delete;
};

inline u64 currentFramePointer() {
    return reinterpret_cast<u64>(__builtin_frame_address(0));
}

inline void cpuid(u32 leaf, u32 sub, u32& a, u32& b, u32& c, u32& d) {
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(sub));
}

inline u64 readTsc() {
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return u64{hi} << 32 | lo;
}

// Model-specific registers. readMsr/writeMsr fault (#GP) on an MSR the CPU
// doesn't have: use them only where CPUID promises the register, and
// Cpu::readMsrSafe otherwise.
namespace Msr {
constexpr u32 APIC_BASE = 0x1B;
constexpr u32 PLATFORM_INFO = 0xCE;       // Intel: base (non-turbo) ratio in bits 8-15
constexpr u32 MCG_CAP = 0x179, MCG_STATUS = 0x17A;
constexpr u32 PERF_STATUS = 0x198;
constexpr u32 CLOCK_MODULATION = 0x19A;
constexpr u32 MC0_CTL = 0x400;            // bank i: CTL, STATUS, ADDR, MISC at 0x400 + 4i
constexpr u32 PM_ENABLE = 0x770, HWP_CAPABILITIES = 0x771, HWP_REQUEST = 0x774;
constexpr u32 EFER = 0xC0000080;
constexpr u32 FS_BASE = 0xC0000100; // user threads' thread-local storage
} // namespace Msr

inline u64 readMsr(u32 msr) {
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return u64{hi} << 32 | lo;
}

inline void writeMsr(u32 msr, u64 value) {
    asm volatile("wrmsr" : : "c"(msr), "a"(static_cast<u32>(value)), "d"(static_cast<u32>(value >> 32)) : "memory");
}

struct Frame;

// The processor: what it can do (CPUID), checked against what RudraCore
// needs, its TSC rate, machine checks, and its power states.
namespace Cpu {

struct Features {
    char vendor[13];
    char brand[49];
    u32 family, model, stepping;
    bool intel, amd, hypervisor;
    // Required (validate() panics without them).
    bool fpu, tsc, msr, pae, cx8, cmov, fxsr, sse, sse2, nx, longMode;
    // Optional.
    bool apic, x2apic, pge, mce, mca, sse3, ssse3, sse41, sse42, avx, xsave, rdrand, rdseed;
    bool smep, smap, monitor, mwaitBreak, invariantTsc, tscDeadline, hwp, hwpEpp, pdpe1gb;
    bool clockModulation, extendedClockModulation; // software-controlled clock (thermal throttling)
    u32 mwaitSubStates;   // CPUID 5 EDX: sub-states per MWAIT C-state, 4 bits each
    u64 tscHz;            // 0 until calibrateTsc() (or if it couldn't)
    char const* tscSource;
};

// Reads CPUID and panics, naming them, if a required feature is missing.
// First thing after the console is up.
void init();
Features const& features();

// rdmsr that returns false instead of faulting on an MSR this CPU lacks.
bool readMsrSafe(u32 msr, u64& value);
bool writeMsrSafe(u32 msr, u64 value);
// For the #GP handler: true (and the frame fixed up) if the fault was readMsrSafe's.
bool recoverMsrFault(Frame& frame);

// Measures the TSC: CPUID 0x15, the hypervisor's timing leaf, the ACPI PM
// timer, else the PIT. After Acpi::init.
void calibrateTsc();

// Machine checks on (CR4.MCE), and what the banks held from before this
// boot logged and cleared.
void enableMachineChecks();
// Logs every bank with a valid error (for the #MC panic).
void reportMachineCheck();

// P-states (Intel HWP: the CPU picks its own frequency) and the C-state the
// idle loop sleeps in. Logs both.
void initPowerStates();
// Thermal throttling (the acpi server's passive cooling): caps the CPU at
// `percent` (1-100) of its performance, through HWP's maximum, else clock
// modulation. 100 lifts the cap. False if the CPU has neither.
bool setPerformanceLimit(u32 percent);

// Sleeps until the next interrupt, in the deepest chosen C-state, then
// returns with interrupts enabled.
void idle();

} // namespace Cpu

} // namespace Rudracore::Arch

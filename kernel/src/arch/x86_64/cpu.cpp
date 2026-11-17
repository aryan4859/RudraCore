#include "arch/x86_64/cpu.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/frame.h"
#include "arch/x86_64/io.h"
#include "log.h"
#include "panic.h"

// readMsrSafe / writeMsrSafe: where their instruction is, and where to go
// on instead when it faults (see recoverMsrFault).
extern "C" char const msrReadInstruction[], msrReadResume[], msrWriteInstruction[], msrWriteResume[];

namespace Rudracore::Arch::Cpu {

namespace {

constexpr u64 CR4_MCE = 1ull << 6;
constexpr u32 MCG_CTL = 0x17B;
constexpr u64 MCG_CTL_PRESENT = 1ull << 8;

Features f{};
i32 mwaitHint = -1; // -1: hlt
alignas(64) u64 volatile monitorLine = 0;

bool bit(u32 value, u32 n) { return (value >> n) & 1; }

// A small line builder: log() takes its pieces at once, the feature list
// is only known while walking it.
struct Line {
    char text[256];
    usize length = 0;
    void add(char const* s) {
        while (*s and length + 1 < sizeof(text))
            text[length++] = *s++;
        text[length] = 0;
    }
};

void readBrand() {
    u32 regs[12];
    for (u32 i = 0; i < 3; i++)
        cpuid(0x80000002 + i, 0, regs[4 * i], regs[4 * i + 1], regs[4 * i + 2], regs[4 * i + 3]);
    char const* raw = reinterpret_cast<char const*>(regs);
    usize start = 0;
    while (start < 48 and raw[start] == ' ')
        start++;
    usize n = 0;
    for (usize i = start; i < 48 and raw[i]; i++)
        f.brand[n++] = raw[i];
    while (n and f.brand[n - 1] == ' ')
        n--;
    f.brand[n] = 0;
}

void detect() {
    u32 a, b, c, d;
    cpuid(0, 0, a, b, c, d);
    u32 maxLeaf = a;
    u32 vendor[3] = {b, d, c};
    for (usize i = 0; i < 12; i++)
        f.vendor[i] = reinterpret_cast<char const*>(vendor)[i];
    f.vendor[12] = 0;
    f.intel = b == 0x756E6547 and d == 0x49656E69 and c == 0x6C65746E; // GenuineIntel
    f.amd = b == 0x68747541 and d == 0x69746E65 and c == 0x444D4163;   // AuthenticAMD

    cpuid(1, 0, a, b, c, d);
    f.stepping = a & 0xF;
    f.model = (a >> 4) & 0xF;
    f.family = (a >> 8) & 0xF;
    if (f.family == 0xF)
        f.family += (a >> 20) & 0xFF;
    if (f.family == 6 or f.family >= 0xF)
        f.model += ((a >> 16) & 0xF) << 4;
    f.fpu = bit(d, 0), f.tsc = bit(d, 4), f.msr = bit(d, 5), f.pae = bit(d, 6), f.mce = bit(d, 7);
    f.cx8 = bit(d, 8), f.apic = bit(d, 9), f.pge = bit(d, 13), f.mca = bit(d, 14), f.cmov = bit(d, 15);
    f.fxsr = bit(d, 24), f.sse = bit(d, 25), f.sse2 = bit(d, 26);
    f.sse3 = bit(c, 0), f.monitor = bit(c, 3), f.ssse3 = bit(c, 9), f.sse41 = bit(c, 19), f.sse42 = bit(c, 20);
    f.x2apic = bit(c, 21), f.tscDeadline = bit(c, 24), f.xsave = bit(c, 26), f.avx = bit(c, 28);
    f.rdrand = bit(c, 30), f.hypervisor = bit(c, 31);

    if (maxLeaf >= 5) {
        cpuid(5, 0, a, b, c, d);
        f.mwaitBreak = (c & 3) == 3; // sub-states enumerated, and interrupts break MWAIT even when masked
        f.mwaitSubStates = d;
    }
    if (maxLeaf >= 6) {
        cpuid(6, 0, a, b, c, d);
        f.hwp = bit(a, 7), f.hwpEpp = bit(a, 10);
    }
    if (maxLeaf >= 7) {
        cpuid(7, 0, a, b, c, d);
        f.smep = bit(b, 7), f.rdseed = bit(b, 18), f.smap = bit(b, 20);
    }

    cpuid(0x80000000, 0, a, b, c, d);
    u32 maxExtended = a;
    if (maxExtended >= 0x80000001) {
        cpuid(0x80000001, 0, a, b, c, d);
        f.nx = bit(d, 20), f.pdpe1gb = bit(d, 26), f.longMode = bit(d, 29);
    }
    if (maxExtended >= 0x80000004)
        readBrand();
    if (maxExtended >= 0x80000007) {
        cpuid(0x80000007, 0, a, b, c, d);
        f.invariantTsc = bit(d, 8);
    }
}

// MARK: TSC calibration

constexpr u64 PM_TIMER_HZ = 3579545, PIT_HZ = 1193182;
constexpr u64 GIVE_UP_CYCLES = 1ull << 33; // a stuck timer: a few seconds of TSC at most

// CPUID 0x15 (TSC / crystal ratio), with 0x16's base frequency when the
// crystal isn't given (Intel's TSC runs at the base frequency).
u64 fromCpuid() {
    u32 maxLeaf, b, c, d;
    cpuid(0, 0, maxLeaf, b, c, d);
    if (maxLeaf < 0x15)
        return 0;
    u32 denominator, numerator, crystal;
    cpuid(0x15, 0, denominator, numerator, crystal, d);
    if (not denominator or not numerator)
        return 0;
    if (crystal)
        return u64{crystal} * numerator / denominator;
    if (maxLeaf < 0x16)
        return 0;
    u32 baseMhz;
    cpuid(0x16, 0, baseMhz, b, c, d);
    return u64{baseMhz} * 1000000;
}

// VMware's timing leaf, also offered by VirtualBox and others: TSC kHz.
u64 fromHypervisor() {
    if (not f.hypervisor)
        return 0;
    u32 a, b, c, d;
    cpuid(0x40000000, 0, a, b, c, d);
    if (a < 0x40000010 or a > 0x400000FF)
        return 0;
    cpuid(0x40000010, 0, a, b, c, d);
    return u64{a} * 1000;
}

// 50 ms of the ACPI PM timer (3.579545 MHz, 24 or 32 bits).
u64 fromPmTimer() {
    auto const& fadt = Acpi::info().fadt;
    if (not fadt.present or not fadt.pmTimer or fadt.pmTimer > 0xFFFF)
        return 0;
    u16 port = static_cast<u16>(fadt.pmTimer);
    u32 mask = fadt.pmTimer32 ? 0xFFFFFFFF : 0xFFFFFF;
    u32 start = inl(port) & mask;
    u64 t0 = readTsc(), t1;
    u32 elapsed;
    do {
        elapsed = (inl(port) - start) & mask;
        t1 = readTsc();
        if (t1 - t0 > GIVE_UP_CYCLES)
            return 0;
    } while (elapsed < PM_TIMER_HZ / 20);
    return (t1 - t0) * PM_TIMER_HZ / elapsed;
}

// 50 ms of PIT channel 2 (one-shot, its output read through port 0x61).
u64 fromPit() {
    constexpr u16 count = PIT_HZ / 20;
    u8 saved = inb(0x61);
    outb(0x61, static_cast<u8>((saved & ~0x02) | 0x01)); // gate on, speaker off
    outb(0x43, 0xB0);                                      // channel 2, low then high byte, mode 0
    outb(0x42, static_cast<u8>(count));
    outb(0x42, static_cast<u8>(count >> 8));
    u64 t0 = readTsc(), t1;
    bool done;
    do {
        done = inb(0x61) & 0x20;
        t1 = readTsc();
    } while (not done and t1 - t0 <= GIVE_UP_CYCLES);
    outb(0x61, saved);
    return done ? (t1 - t0) * PIT_HZ / count : 0;
}

} // namespace

void init() {
    detect();
    struct Requirement {
        bool Features::* has;
        char const* name;
    };
    // What the kernel's code assumes (long mode and its page tables, rdtsc,
    // rdmsr, fxsave, NX) and what userspace is compiled for (SSE2, cmov).
    static constexpr Requirement REQUIRED[] = {
        {&Features::longMode, "long mode"}, {&Features::fpu, "fpu"},   {&Features::tsc, "tsc"},
        {&Features::msr, "msr"},            {&Features::pae, "pae"},   {&Features::cx8, "cx8"},
        {&Features::cmov, "cmov"},          {&Features::fxsr, "fxsr"}, {&Features::sse, "sse"},
        {&Features::sse2, "sse2"},          {&Features::nx, "nx (execute-disable)"},
    };
    Line missing;
    for (auto const& r : REQUIRED) {
        if (not(f.*r.has)) {
            missing.add(missing.length ? ", " : "");
            missing.add(r.name);
        }
    }

    log("[cpu]  ", f.vendor, " family ", f.family, " model ", f.model, " stepping ", f.stepping,
        f.brand[0] ? ": " : "", f.brand, f.hypervisor ? " (virtual machine)" : "");
    if (missing.length) {
        Panic::begin("unsupported processor");
        log("RudraCore needs CPU features this processor doesn't have: ", missing.text);
        Panic::end();
    }

    struct Optional {
        bool Features::* has;
        char const* name;
    };
    static constexpr Optional OPTIONAL[] = {
        {&Features::sse3, "sse3"},   {&Features::ssse3, "ssse3"},   {&Features::sse41, "sse4.1"},
        {&Features::sse42, "sse4.2"}, {&Features::avx, "avx"},       {&Features::xsave, "xsave"},
        {&Features::apic, "apic"},   {&Features::x2apic, "x2apic"}, {&Features::tscDeadline, "tsc-deadline"},
        {&Features::invariantTsc, "invariant-tsc"}, {&Features::rdrand, "rdrand"}, {&Features::rdseed, "rdseed"},
        {&Features::smep, "smep"},   {&Features::smap, "smap"},     {&Features::pge, "pge"},
        {&Features::pdpe1gb, "1g-pages"}, {&Features::mca, "mca"},  {&Features::monitor, "mwait"},
        {&Features::hwp, "hwp"},
    };
    Line have;
    for (auto const& o : OPTIONAL) {
        if (f.*o.has) {
            have.add(have.length ? " " : "");
            have.add(o.name);
        }
    }
    log("[cpu]  required features present; also: ", have.length ? have.text : "nothing else");
}

Features const& features() { return f; }

// noinline: the labels must exist exactly once.
[[gnu::noinline]] bool readMsrSafe(u32 msr, u64& value) {
    u32 lo, hi, ok;
    asm volatile("mov $1, %%esi\n"
                 ".globl msrReadInstruction\nmsrReadInstruction:\n"
                 "rdmsr\n"
                 ".globl msrReadResume\nmsrReadResume:\n"
                 : "=a"(lo), "=d"(hi), "=&S"(ok)
                 : "c"(msr));
    value = u64{hi} << 32 | lo;
    return ok;
}

[[gnu::noinline]] bool writeMsrSafe(u32 msr, u64 value) {
    u32 ok;
    asm volatile("mov $1, %%esi\n"
                 ".globl msrWriteInstruction\nmsrWriteInstruction:\n"
                 "wrmsr\n"
                 ".globl msrWriteResume\nmsrWriteResume:\n"
                 : "=&S"(ok)
                 : "c"(msr), "a"(static_cast<u32>(value)), "d"(static_cast<u32>(value >> 32))
                 : "memory");
    return ok;
}

bool recoverMsrFault(Frame& frame) {
    constexpr u64 GENERAL_PROTECTION = 13;
    if (frame.vector != GENERAL_PROTECTION or (frame.cs & 3))
        return false;
    if (frame.rip == reinterpret_cast<u64>(msrReadInstruction)) {
        frame.rip = reinterpret_cast<u64>(msrReadResume);
        frame.rax = frame.rdx = 0;
    } else if (frame.rip == reinterpret_cast<u64>(msrWriteInstruction)) {
        frame.rip = reinterpret_cast<u64>(msrWriteResume);
    } else {
        return false;
    }
    frame.rsi = 0; // the call's "ok"
    return true;
}

void calibrateTsc() {
    InterruptGuard guard;
    struct Method {
        u64 (*measure)();
        char const* name;
    };
    static constexpr Method METHODS[] = {
        {fromHypervisor, "the hypervisor"},
        {fromCpuid, "CPUID"},
        {fromPmTimer, "the ACPI PM timer"},
        {fromPit, "the PIT"},
    };
    for (auto const& m : METHODS) {
        u64 hz = m.measure();
        if (hz >= 50'000'000 and hz <= 20'000'000'000) { // anything else is a broken source
            f.tscHz = hz;
            f.tscSource = m.name;
            break;
        }
    }
    if (not f.tscHz) {
        log("[cpu]  tsc: couldn't measure its rate (no usable timer)");
        return;
    }
    log("[cpu]  tsc: ", f.tscHz / 1000000, ".", (f.tscHz / 1000) % 1000 / 100, " MHz, from ", f.tscSource,
        f.invariantTsc ? " (invariant: steady through P- and C-states)" : " (not invariant)");
}

void enableMachineChecks() {
    if (not f.mce)
        return;
    u32 banks = 0;
    u64 cap = 0;
    if (f.mca and readMsrSafe(Msr::MCG_CAP, cap)) {
        banks = cap & 0xFF;
        for (u32 i = 0; i < banks; i++) {
            u64 status;
            if (readMsrSafe(Msr::MC0_CTL + 4 * i + 1, status) and status >> 63) {
                log("[mce]  bank ", i, " held an error from before this boot: status ", Hex{status});
                writeMsrSafe(Msr::MC0_CTL + 4 * i + 1, 0);
            }
        }
        if (cap & MCG_CTL_PRESENT)
            writeMsrSafe(MCG_CTL, ~0ull);
        // Every error type reported. (Bank 0 on older Intel family 6 belongs to the firmware.)
        for (u32 i = (f.intel and f.family == 6 and f.model < 0x1A) ? 1 : 0; i < banks; i++)
            writeMsrSafe(Msr::MC0_CTL + 4 * i, ~0ull);
    }
    u64 cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    asm volatile("mov %0, %%cr4" : : "r"(cr4 | CR4_MCE) : "memory");
    if (f.mca)
        log("[mce]  machine checks on, ", banks, " error-reporting bank(s)");
    else
        log("[mce]  machine checks on (no MCA banks)");
}

void reportMachineCheck() {
    u64 cap, status;
    if (not f.mca or not readMsrSafe(Msr::MCG_CAP, cap))
        return;
    if (readMsrSafe(Msr::MCG_STATUS, status))
        log("  mcg status ", Hex{status}, (status & 4) ? " (in progress)" : "", (status & 1) ? "" : " (can't restart)");
    for (u32 i = 0; i < (cap & 0xFF); i++) {
        if (not readMsrSafe(Msr::MC0_CTL + 4 * i + 1, status) or not(status >> 63))
            continue;
        u64 address = 0, misc = 0;
        if (status & (1ull << 58))
            readMsrSafe(Msr::MC0_CTL + 4 * i + 2, address);
        if (status & (1ull << 59))
            readMsrSafe(Msr::MC0_CTL + 4 * i + 3, misc);
        log("  bank ", i, ": status ", Hex{status}, (status & (1ull << 61)) ? " uncorrected" : " corrected",
            "  addr ", Hex{address}, "  misc ", Hex{misc});
    }
}

void initPowerStates() {
    // P-states: with HWP the CPU picks its own frequency between its lowest
    // and highest, steered only by the energy-performance preference.
    if (f.hwp) {
        writeMsr(Msr::PM_ENABLE, 1); // (stays on until reset)
        u64 cap = readMsr(Msr::HWP_CAPABILITIES);
        u64 highest = cap & 0xFF, guaranteed = (cap >> 8) & 0xFF, lowest = (cap >> 24) & 0xFF;
        constexpr u64 BALANCED = 0x80;
        writeMsr(Msr::HWP_REQUEST, lowest | highest << 8 | (f.hwpEpp ? BALANCED << 24 : 0));
        log("[cpu]  p-states: Intel HWP on, ", lowest * 100, "-", highest * 100, " MHz (", guaranteed * 100,
            " guaranteed), ", f.hwpEpp ? "balanced" : "default", " preference");
    } else {
        u64 platform;
        if (f.intel and not f.hypervisor and readMsrSafe(Msr::PLATFORM_INFO, platform))
            log("[cpu]  p-states: left to the firmware (no HWP); base ", ((platform >> 8) & 0xFF) * 100, " MHz");
        else
            log("[cpu]  p-states: left to the firmware (no HWP)");
    }

    // C-states: on bare-metal Intel with MWAIT, idle sleeps in the deepest
    // of C1, C3 and C6 the CPU lists (hint (n - 1) << 4 for C-state n's
    // first sub-state). The timer is the PIT/I/O APIC, not the local APIC
    // timer, so states that stop that are fine. In a VM hlt is cheaper.
    // shortcut: no _CST (the acpi server would have to pass it on), so no
    // latency data and no C7-C10; fine for a 1 ms tick.
    if (f.intel and not f.hypervisor and f.monitor and f.mwaitBreak) {
        for (u32 n = 1; n <= 3; n++) {
            if ((f.mwaitSubStates >> (4 * n)) & 0xF)
                mwaitHint = static_cast<i32>((n - 1) << 4);
        }
    }
    static constexpr char const* NAMES[] = {"C1", "C3", "C6"};
    if (mwaitHint < 0)
        log("[cpu]  c-states: idle in C1 (hlt)");
    else
        log("[cpu]  c-states: idle in ", NAMES[mwaitHint >> 4], " (MWAIT hint ", Hex{static_cast<u64>(mwaitHint), 2}, ")");
}

void idle() {
    if (mwaitHint < 0) {
        asm volatile("sti; hlt" ::: "memory");
        return;
    }
    // Interrupts stay masked from monitor to mwait (ECX bit 0: one still
    // wakes it), so none slips in between; sti then takes it.
    asm volatile("cli; monitor" : : "a"(&monitorLine), "c"(0), "d"(0) : "memory");
    asm volatile("mwait; sti; nop" : : "a"(mwaitHint), "c"(1) : "memory");
}

} // namespace Rudracore::Arch::Cpu

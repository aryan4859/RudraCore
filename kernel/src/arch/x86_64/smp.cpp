#include "arch/x86_64/smp.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/apic.h"
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/protect.h"
#include "core/counters.h"
#include "core/sched.h"
#include "log.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "panic.h"

extern "C" u8 const apTrampolineStart[], apTrampolineEnd[], apGdt[], apGdtPointer[], apProtected[], apLong[],
    apFarTo32[], apFarTo64[], apPageTable[], apStack[], apCpu[], apEntry[];

extern "C" void* memcpy(void* dest, void const* src, usize n);

namespace Rudracore::Arch::Smp {

namespace {

constexpr u32 NOBODY = ~0u;
constexpr u64 PAGE_PRESENT_WRITABLE = 3;
constexpr u32 MSR_PAT = 0x277;

// The kernel lock: a ticket lock (CPUs get it in the order they asked),
// recursive for the CPU that holds it.
u32 nextTicket = 0, serving = 0;
u32 volatile owner = NOBODY;
u32 depth = 0;

bool volatile panicking = false;

u64 volatile online = 1; // the boot CPU
u8 apicIds[MAX_CPUS];
u32 cpuCount = 1;

// The shootdown in progress (one at a time: only the lock holder asks).
u64 volatile shootdownPending = 0; // CPUs still to flush
u64 shootdownAddress = 0, shootdownPages = 0;

u64 trampoline = 0; // the start-up page (below 1 MiB)
u64 stackTops[MAX_CPUS]; // each other CPU's first stack (its idle task's)
u32 ticksPerMs = 0;
u64 bootCr0 = 0, bootCr4 = 0, bootPat = 0;

[[noreturn]] void halt() {
    for (;;)
        asm volatile("cli; hlt");
}

void flushLocal(u64 address, u64 pages) {
    if (pages == 0 or pages > 32) {
        writeCr3(readCr3()); // everything (no mapping is global)
        return;
    }
    for (u64 i = 0; i < pages; i++)
        invalidatePage(address + i * Mem::PAGE_SIZE);
}

// While waiting for the lock: what can't wait for it.
void whileWaiting() {
    if (panicking)
        halt();
    serviceShootdown();
    asm volatile("pause");
}

void waitTsc(u64 microseconds) {
    u64 hz = Cpu::features().tscHz;
    u64 start = readTsc(), cycles = hz ? hz / 1000000 * microseconds : microseconds * 3000;
    while (readTsc() - start < cycles)
        asm volatile("pause");
}

} // namespace

void enterKernel() {
    u32 me = index();
    if (owner == me) {
        depth++;
        return;
    }
    u32 ticket = __atomic_fetch_add(&nextTicket, 1, __ATOMIC_RELAXED);
    Counters::add(Counters::all.lockAcquires);
    if (__atomic_load_n(&serving, __ATOMIC_ACQUIRE) != ticket) { // contended: someone else holds it
        u64 start = readTsc();
        while (__atomic_load_n(&serving, __ATOMIC_ACQUIRE) != ticket)
            whileWaiting();
        Counters::add(Counters::all.lockContended);
        Counters::add(Counters::all.lockSpinCycles, readTsc() - start);
    }
    owner = me;
    depth = 1;
}

void leaveKernel() {
    if (owner != index() or depth == 0)
        return;
    if (--depth == 0) {
        owner = NOBODY;
        __atomic_store_n(&serving, serving + 1, __ATOMIC_RELEASE);
    }
}

u32 kernelDepth() { return owner == index() ? depth : 0; }

void setKernelDepth(u32 d) {
    if (owner == index())
        depth = d;
}

u32 count() { return cpuCount; }
u64 onlineMask() { return online; }
u8 apicId(u32 cpu) { return cpu < MAX_CPUS ? apicIds[cpu] : 0; }

void interrupt(u32 cpu, u8 vector) {
    if (cpu != index() and (online & (1ull << cpu))) {
        Counters::add(Counters::all.ipis);
        Apic::sendIpi(apicIds[cpu], vector);
    }
}

void serviceShootdown() {
    u64 bit = 1ull << index();
    if (not(__atomic_load_n(&shootdownPending, __ATOMIC_ACQUIRE) & bit))
        return;
    flushLocal(shootdownAddress, shootdownPages);
    __atomic_fetch_and(&shootdownPending, ~bit, __ATOMIC_RELEASE);
}

void shootdown(u64 cpus, u64 address, u64 pages) {
    u64 targets = cpus & online & ~(1ull << index());
    if (not targets)
        return;
    Counters::add(Counters::all.shootdowns);
    shootdownAddress = address;
    shootdownPages = pages;
    __atomic_store_n(&shootdownPending, targets, __ATOMIC_RELEASE);
    for (u32 cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (targets & (1ull << cpu))
            Apic::sendIpi(apicIds[cpu], VECTOR_TLB);
    }
    // Each target flushes in its interrupt handler, or while it waits for
    // the kernel lock (which this CPU holds).
    while (__atomic_load_n(&shootdownPending, __ATOMIC_ACQUIRE) and not panicking)
        asm volatile("pause");
}

void flushOthers(Vmm::Space const& space, u64 address, u64 pages) {
    if (online == 1)
        return;
    shootdown(address >= Vmm::USER_END ? online : space.cpuMask, address, pages);
}

void stopOthers() {
    panicking = true;
    for (u32 cpu = 0; cpu < MAX_CPUS and cpuCount > 1; cpu++) {
        if (cpu != index() and (online & (1ull << cpu)))
            Apic::sendIpi(apicIds[cpu], VECTOR_STOP);
    }
    owner = index(); // the lock, whatever it was doing
    depth = 1000;
}

u32 timerTicksPerMs() { return ticksPerMs; }

void reserveTrampoline() {
    trampoline = Pmm::allocZeroed(1, 0x100000);
    if (not trampoline)
        log("[smp]  no free page below 1 MiB: the other CPUs can't be started");
}

// Each other CPU arrives here from ap_start.S, on its own stack.
extern "C" [[noreturn]] void apMain(u64 cpu) {
    writeCr3(Vmm::kernelSpace().root);
    Gdt::load(static_cast<u32>(cpu));
    Idt::load();
    // The boot CPU's control registers and memory types (SSE, SMEP/SMAP,
    // machine checks, and the PAT the framebuffer's write-combining needs).
    asm volatile("mov %0, %%cr0" : : "r"(bootCr0) : "memory");
    asm volatile("mov %0, %%cr4" : : "r"(bootCr4) : "memory");
    writeMsr(MSR_PAT, bootPat);
    Fpu::init();
    if (Protect::smapEnabled)
        asm volatile("clac" ::: "memory");
    Apic::initLocal(false);
    {
        InterruptGuard guard;
        Sched::initCpu(static_cast<u32>(cpu), stackTops[cpu]);
        Apic::addDestination(Apic::localId());
        if (ticksPerMs)
            Apic::startTimer(ticksPerMs, VECTOR_TIMER);
        __atomic_fetch_or(&online, 1ull << cpu, __ATOMIC_RELEASE);
    }
    Sched::idle();
}

void startOthers() {
    auto const& m = Acpi::info().madt;
    if (not Apic::initLocal(true)) {
        log("[smp]  no MADT: one CPU");
        return;
    }
    apicIds[0] = Apic::localId();
    Apic::addDestination(apicIds[0]);
    if (m.apicIdCount < 2 or not trampoline)
        return;
    if (not Cpu::features().tscHz) {
        log("[smp]  the TSC rate is unknown (no timer to measure the others' with): one CPU");
        return;
    }
    ticksPerMs = Apic::measureTimer(Cpu::features().tscHz);

    // The start-up page, with its absolute addresses filled in.
    u8* page = Mem::toVirtual<u8>(trampoline);
    memcpy(page, apTrampolineStart, static_cast<usize>(apTrampolineEnd - apTrampolineStart));
    auto at = [&](u8 const* symbol) { return page + (symbol - apTrampolineStart); };
    auto physical = [&](u8 const* symbol) { return static_cast<u32>(trampoline + (symbol - apTrampolineStart)); };
    *reinterpret_cast<u32*>(at(apGdtPointer) + 2) = physical(apGdt);
    *reinterpret_cast<u32*>(at(apFarTo32)) = physical(apProtected);
    *reinterpret_cast<u32*>(at(apFarTo64)) = physical(apLong);

    // Page tables below 4 GiB (32-bit code loads them): the kernel half,
    // plus the start-up page at its own address.
    u64 pml4 = Pmm::allocZeroed(1, Pmm::BELOW_4G), pdpt = Pmm::allocZeroed(1, Pmm::BELOW_4G);
    u64 pd = Pmm::allocZeroed(1, Pmm::BELOW_4G), pt = Pmm::allocZeroed(1, Pmm::BELOW_4G);
    if (not pml4 or not pdpt or not pd or not pt) {
        log("[smp]  no memory below 4 GiB for the start-up page tables: one CPU");
        return;
    }
    u64* kernelTop = Mem::toVirtual<u64>(Vmm::kernelSpace().root);
    u64* top = Mem::toVirtual<u64>(pml4);
    for (usize i = 256; i < 512; i++)
        top[i] = kernelTop[i];
    top[0] = pdpt | PAGE_PRESENT_WRITABLE;
    Mem::toVirtual<u64>(pdpt)[0] = pd | PAGE_PRESENT_WRITABLE;
    Mem::toVirtual<u64>(pd)[0] = pt | PAGE_PRESENT_WRITABLE;
    Mem::toVirtual<u64>(pt)[trampoline >> 12] = trampoline | PAGE_PRESENT_WRITABLE;
    *reinterpret_cast<u64*>(at(apPageTable)) = pml4;

    asm volatile("mov %%cr0, %0" : "=r"(bootCr0));
    asm volatile("mov %%cr4, %0" : "=r"(bootCr4));
    bootPat = readMsr(MSR_PAT);

    u8 self = apicIds[0];
    for (u32 i = 0; i < m.apicIdCount and cpuCount < MAX_CPUS; i++) {
        u8 id = m.apicIds[i];
        if (id == self)
            continue;
        u32 cpu = cpuCount;
        constexpr u64 STACK_PAGES = 4;
        u64 stack = Pmm::alloc(STACK_PAGES);
        if (not stack)
            break;
        stackTops[cpu] = reinterpret_cast<u64>(Mem::toVirtual<u8>(stack)) + STACK_PAGES * Mem::PAGE_SIZE;
        *reinterpret_cast<u64*>(at(apStack)) = stackTops[cpu];
        *reinterpret_cast<u64*>(at(apCpu)) = cpu;
        *reinterpret_cast<u64*>(at(apEntry)) = reinterpret_cast<u64>(&apMain);
        apicIds[cpu] = id;

        // INIT, then STARTUP twice (the classic sequence), then wait for it.
        Apic::sendInit(id);
        waitTsc(10000);
        for (int attempt = 0; attempt < 2 and not(online & (1ull << cpu)); attempt++) {
            Apic::sendStartup(id, static_cast<u8>(trampoline >> 12));
            waitTsc(200);
        }
        for (u64 waited = 0; waited < 100000 and not(__atomic_load_n(&online, __ATOMIC_ACQUIRE) & (1ull << cpu));
             waited += 100)
            waitTsc(100);
        if (__atomic_load_n(&online, __ATOMIC_ACQUIRE) & (1ull << cpu)) {
            cpuCount++;
        } else {
            log("[smp]  CPU with APIC id ", id, " didn't start");
            Pmm::free(stack, STACK_PAGES);
        }
    }
    log("[smp]  ", cpuCount, " CPU(s) running (", m.apicIdCount, " in the MADT), local APIC timers at ",
        ticksPerMs, " ticks/ms");
}

} // namespace Rudracore::Arch::Smp

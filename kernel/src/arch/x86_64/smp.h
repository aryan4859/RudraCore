#pragma once

#include "arch/x86_64/cpu.h"

namespace Rudracore::Vmm {
struct Space;
}

// Multiprocessing: the other CPUs (application processors), what each one
// knows about itself, interprocessor interrupts and TLB shootdowns.
//
// The kernel lock (cpu.h: Smp::enterKernel, InterruptGuard) serializes
// kernel code; each CPU runs its own share of the threads (Sched keeps a
// run queue per CPU). A CPU waiting for the lock still answers what can't
// wait: TLB shootdowns (the lock holder may be waiting for this one) and a
// panic's stop.
namespace Rudracore::Arch::Smp {

constexpr u32 MAX_CPUS = 16;

// Interrupt vectors the local APICs raise (above the devices', below the spurious one).
constexpr u8 VECTOR_TIMER = 0xF0;      // this CPU's local APIC timer (1 ms): preemption
constexpr u8 VECTOR_RESCHEDULE = 0xF1; // another CPU queued work here
constexpr u8 VECTOR_TLB = 0xF2;        // flush translations (see shootdown)
constexpr u8 VECTOR_STOP = 0xF3;       // a panic elsewhere: halt

// Keeps a page below 1 MiB for the other CPUs' start-up code. Right after
// Pmm::init, while low memory is still free.
void reserveTrampoline();

// Starts every other CPU the MADT lists (after the kernel is set up: the
// scheduler, the address spaces). Each one runs its own idle task and takes
// the threads its scheduler gives it. Logs how many came up.
void startOthers();

u32 count();         // CPUs online
u64 onlineMask();
u8 apicId(u32 cpu);

// Sends `vector` to CPU `cpu`.
void interrupt(u32 cpu, u8 vector);

// Makes every CPU in `cpus` (but this one) forget translations of
// [address, address + pages * 4 KiB) (pages 0: all of them), and waits
// until they have. Called with the kernel lock held.
void shootdown(u64 cpus, u64 address, u64 pages);

// The translations of `space` changed at [address, + pages): whoever else
// has it loaded forgets them (kernel addresses: every CPU).
void flushOthers(Vmm::Space const& space, u64 address, u64 pages);

// For the interrupt handler: a shootdown request for this CPU.
void serviceShootdown();

// The kernel lock's depth on this CPU (a task switch carries it).
u32 kernelDepth();
void setKernelDepth(u32 depth);

// Halts every other CPU and takes the kernel lock whatever its state (a
// panic: nothing else may run).
void stopOthers();

// The local APIC timer's rate, measured once (0: none).
u32 timerTicksPerMs();

} // namespace Rudracore::Arch::Smp

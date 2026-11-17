#include "core/random.h"
#include "arch/x86_64/idt.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/frame.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/apic.h"
#include "arch/x86_64/efi.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/protect.h"
#include "arch/x86_64/smp.h"
#include "core/device.h"
#include "core/counters.h"
#include "core/sched.h"
#include "core/syscall.h"
#include "core/vm.h"
#include "log.h"
#include "panic.h"
#include "rudracore/syscalls.h"

extern "C" u8 const interruptStubs[];

namespace Rudracore::Arch::Idt {

namespace {

struct [[gnu::packed]] Entry {
    u16 offsetLow;
    u16 selector;
    u8 ist;
    u8 attributes;
    u16 offsetMid;
    u32 offsetHigh;
    u32 reserved;
};
static_assert(sizeof(Entry) == 16);

struct [[gnu::packed]] Pointer {
    u16 limit;
    u64 base;
};

constexpr u8 INTERRUPT_GATE = 0x8E;      // present, ring 0, 64-bit interrupt gate
constexpr u8 USER_INTERRUPT_GATE = 0xEE; // same, but callable from ring 3

constexpr u64 VECTOR_BREAKPOINT = 3;
constexpr u64 VECTOR_PAGE_FAULT = 14;
constexpr u64 VECTOR_MACHINE_CHECK = 18;
constexpr u64 VECTOR_IRQ_BASE = Pic::IRQ_BASE;

alignas(16) Entry entries[256];

constexpr char const* EXCEPTION_NAMES[32] = {
    "division error",
    "debug",
    "non-maskable interrupt",
    "breakpoint",
    "overflow",
    "bound range exceeded",
    "invalid opcode",
    "device not available",
    "double fault",
    "coprocessor segment overrun",
    "invalid TSS",
    "segment not present",
    "stack-segment fault",
    "general protection fault",
    "page fault",
    "reserved",
    "x87 floating-point exception",
    "alignment check",
    "machine check",
    "SIMD floating-point exception",
    "virtualization exception",
    "control protection exception",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "hypervisor injection exception",
    "VMM communication exception",
    "security exception",
    "reserved",
};

void logRegisters(Frame const& f) {
    log("  rip ", Hex{f.rip}, "  rsp ", Hex{f.rsp}, "  rbp ", Hex{f.rbp});
    log("  rax ", Hex{f.rax}, "  rbx ", Hex{f.rbx}, "  rcx ", Hex{f.rcx});
    log("  rdx ", Hex{f.rdx}, "  rsi ", Hex{f.rsi}, "  rdi ", Hex{f.rdi});
    log("  r8  ", Hex{f.r8}, "  r9  ", Hex{f.r9}, "  r10 ", Hex{f.r10});
    log("  r11 ", Hex{f.r11}, "  r12 ", Hex{f.r12}, "  r13 ", Hex{f.r13});
    log("  r14 ", Hex{f.r14}, "  r15 ", Hex{f.r15}, "  cr3 ", Hex{readCr3()});
    log("  cs  ", Hex{f.cs}, "  ss  ", Hex{f.ss}, "  rfl ", Hex{f.rflags});
}

[[noreturn]] void exceptionPanic(Frame const& f) {
    Panic::begin("CPU exception");
    log("RudraCore caught a '", exceptionName(f.vector), "' (vector ", f.vector,
        ", error ", Hex{f.error}, ")");
    log("in ", (f.cs & 3) ? "user mode" : "kernel mode");
    if (f.vector == 8)
        log("(a fault while handling a fault: most often a kernel stack overflow into its guard page, at ",
            Hex{readCr2()}, ")");

    if (f.vector == VECTOR_MACHINE_CHECK) {
        log("(the hardware reported an error it couldn't correct: memory, cache or bus)");
        Cpu::reportMachineCheck();
    }

    if (f.vector == VECTOR_PAGE_FAULT) {
        log("");
        log("  address ", Hex{readCr2()}, " (",
            (f.error & 1) ? "protection violation" : "page not mapped", ", ",
            (f.error & 16) ? "instruction fetch" : ((f.error & 2) ? "write" : "read"), ")");
    }

    log("");
    logRegisters(f);
    Panic::backtrace(f.rbp);
    Panic::end();
}

// A user program faulted: report it (and keep what happened for whoever
// holds a handle to it), then its process ends. The kernel and the other
// programs keep running.
void logUserFault(Frame const& f) {
    auto* task = Sched::current();
    if (Core::Process* p = task->process) {
        p->faultVector = f.vector;
        p->faultRip = f.rip;
        p->faultAddress = f.vector == VECTOR_PAGE_FAULT ? readCr2() : 0;
    }
    log("[sched] ", task->name, " (thread ", task->id, ") crashed: ", exceptionName(f.vector),
        " at ", Hex{f.rip});
    if (f.vector == VECTOR_PAGE_FAULT) {
        log("[sched]   ", (f.error & 1) ? "protection violation" : "page not mapped", " on ",
            (f.error & 16) ? "instruction fetch" : ((f.error & 2) ? "write" : "read"),
            " of ", Hex{readCr2()});
    }
}

} // namespace

char const* exceptionName(u64 vector) {
    return vector < 32 ? EXCEPTION_NAMES[vector] : "interrupt";
}

void init() {
    auto stubs = reinterpret_cast<u64>(interruptStubs);
    for (usize i = 0; i < 256; i++) {
        u64 handler = stubs + i * STUB_SIZE;
        entries[i] = {
            .offsetLow = static_cast<u16>(handler),
            .selector = Gdt::KERNEL_CODE,
            .ist = i == 8 ? Gdt::IST_DOUBLE_FAULT : u8(0),
            .attributes = i == Abi::SYSCALL_VECTOR ? USER_INTERRUPT_GATE : INTERRUPT_GATE,
            .offsetMid = static_cast<u16>(handler >> 16),
            .offsetHigh = static_cast<u32>(handler >> 32),
            .reserved = 0,
        };
    }

    load();
}

void load() {
    Pointer pointer{sizeof(entries) - 1, reinterpret_cast<u64>(entries)};
    asm volatile("lidt %0" : : "m"(pointer));
}

} // namespace Rudracore::Arch::Idt

using namespace Rudracore;
using namespace Rudracore::Arch;

// After interruptDispatch, on the resumed task's stack (interrupts.S).
extern "C" void interruptLeave() { Smp::leaveKernel(); }

namespace {
constexpr u64 VECTOR_PAGE_FAULT_ID = 14;
}

// Called by interruptCommon (interrupts.S) for every interrupt, with
// interrupts disabled. Returns the frame to resume: the same one, or another
// task's when the scheduler switches. Runs holding the kernel lock (taken
// here, let go by interruptLeave), except for what the lock holder may be
// waiting for: a TLB shootdown, a panic's stop.
extern "C" Frame* interruptDispatch(Frame* frame) {
    u64 vector = frame->vector;
    if (vector == Smp::VECTOR_TLB) {
        Smp::serviceShootdown();
        Apic::localEndOfInterrupt();
        return frame;
    }
    if (vector == Smp::VECTOR_STOP)
        for (;;)
            asm volatile("cli; hlt");
    Smp::enterKernel();
    Protect::closeUserAccess();
    bool fromUser = frame->cs & 3;
    Counters::add(vector == Abi::SYSCALL_VECTOR ? Counters::all.syscalls
                  : vector == VECTOR_PAGE_FAULT_ID ? Counters::all.pageFaults
                                                   : Counters::all.interrupts);

    if (vector == Smp::VECTOR_TIMER) { // this CPU's own tick
        Apic::localEndOfInterrupt();
        return Sched::onCpuTick(frame);
    }
    if (vector == Smp::VECTOR_RESCHEDULE) { // work was queued here
        Apic::localEndOfInterrupt();
        return Sched::onReschedule(frame);
    }

    if (vector == Idt::VECTOR_BREAKPOINT and not fromUser) {
        // Not fatal: log and resume after the int3 instruction.
        log("[cpu]  breakpoint at ", Hex{frame->rip});
        return frame;
    }

    if (Cpu::recoverMsrFault(*frame))
        return frame; // readMsrSafe/writeMsrSafe probed an MSR this CPU lacks
    if (Efi::recoverFault(*frame))
        return frame; // the firmware faulted: its call fails, the kernel goes on

    // A program touched memory that isn't mapped yet: demand paging,
    // copy-on-write, a page from a pager.
    if (vector == Idt::VECTOR_PAGE_FAULT and fromUser) {
        Core::Task* task = Sched::current();
        switch (Vm::fault(*task, readCr2(), frame->error & 2, frame->error & 16)) {
        case Vm::Fault::Resolved: return frame;
        case Vm::Fault::Pending: return Sched::blockCurrent(frame); // the instruction runs again when the page is in
        case Vm::Fault::Retry: return Sched::sleepCurrent(frame, 1);
        case Vm::Fault::OutOfMemory:
            if (Core::Process* victim = Vm::outOfMemory(task->process); victim and victim != task->process)
                return frame; // memory is free again: run the instruction again
            log("[vm]   ", task->name, " (thread ", task->id, ") ran out of memory");
            return Sched::exitProcess(frame, Abi::EXIT_OUT_OF_MEMORY);
        case Vm::Fault::Invalid: break; // a real fault
        }
    }

    if (vector < 32) {
        if (fromUser and vector != Idt::VECTOR_MACHINE_CHECK) { // (#MC is the machine's, not the task's)
            Idt::logUserFault(*frame);
            return Sched::exitProcess(frame, Abi::EXIT_FAULT);
        }
        Idt::exceptionPanic(*frame);
    }

    if (vector == Idt::VECTOR_IRQ_BASE) { // timer
        Pic::endOfInterrupt(0);
        return Sched::onTimerTick(frame);
    }

    if (vector > Idt::VECTOR_IRQ_BASE and vector < Idt::VECTOR_IRQ_BASE + Core::Irq::LINES) { // pins, then MSI
        u8 irq = static_cast<u8>(vector - Idt::VECTOR_IRQ_BASE);
        if (Pic::isSpurious(irq))
            return frame;
        Random::stir(); // device interrupts arrive at unpredictable moments
        if (Core::Irq::deliver(irq)) { // a userspace driver owns this line
            Pic::endOfInterrupt(irq);
            return frame;
        }
        log("[irq]  unhandled irq ", irq);
        Pic::endOfInterrupt(irq);
        return frame;
    }

    if (vector == Apic::SPURIOUS_VECTOR)
        return frame; // the local APIC's spurious interrupt: no EOI

    if (vector == Abi::SYSCALL_VECTOR)
        return Syscall::dispatch(frame);

    if (vector == Idt::YIELD_VECTOR and not fromUser)
        return Sched::switchFrom(frame);

    log("[cpu]  unexpected interrupt vector ", vector);
    return frame;
}

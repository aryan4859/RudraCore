#pragma once

#include "arch/x86_64/frame.h"
#include "core/object.h"
#include "core/quota.h"
#include "core/vm.h"
#include "mem/vmm.h"

namespace Rudracore::Core {

struct SharedMemory;

enum class TaskState : u8 {
    Ready,
    Running,
    Sleeping,
    Blocked, // waiting on an object (channel, irq); the object holds the task
    Dead,
};

struct Process;

// A thread: what the scheduler runs. User threads belong to a process (which
// holds the address space, handles and memory); kernel tasks belong to none.
// The first thread's id is also its process's id.
struct Task {
    u64 id = 0;
    char name[32] = {};
    TaskState state = TaskState::Ready;

    // While the task isn't running: its saved CPU state (an Arch::Frame on
    // its kernel stack). Resuming the task means returning from an
    // interrupt with this frame.
    u64 savedFrame = 0;

    u64 stackPhysical = 0; // kernel stack pages (0 for the boot task's static stack)
    u64 stackTop = 0;      // also where the CPU enters the kernel from user mode

    Process* process = nullptr; // nullptr for kernel tasks (holds a reference)
    u64 fsBase = 0;             // thread-local storage: the FS segment base (IA32_FS_BASE)
    u32 cpu = 0;                // the CPU whose queue it's on (or that ran it last)
    u32 lockDepth = 0;          // the kernel lock it held when it was switched out
    u64 lastBoost = 0;          // when a wake-up last put it at the head of its queue (fairness)
    u64 cpuMs = 0; // CPU time used so far (in 1 ms timer ticks)
    u64 wakeAt = 0;
    u64 waitDeadline = 0; // while in a timed wait: when it gives up (0 = none)
    i64 exitCode = 0;

    Task* next = nullptr;       // link in the ready, sleep or zombie list
    Task* allNext = nullptr;    // link in the list of every task (Sched::allTasks)
    Task* threadNext = nullptr; // link in its process's threads

    // What a blocked thread waits for, besides channels and IRQs (which point
    // at it themselves). Each list forgets the thread when it ends.
    SharedMemory* pageWaitObject = nullptr; // a pager's page (Vm)
    u64 pageWaitIndex = 0;
    Task* pageWaitNext = nullptr;
    u64 futexKey = 0;                       // a futex (physical address of the word)
    Task* futexNext = nullptr;
    bool futexWoken = false;                // woken by futex_wake (not a timeout)
    u64 joinTarget = 0;                     // a thread of its process (join)
    Process* exitWaitTarget = nullptr;      // another process (process_wait)

    // Floating point / SSE registers while the task isn't running (FXSAVE
    // format, must be 16-byte aligned).
    alignas(16) u8 fpuState[512];

    bool isUser() const { return process != nullptr; }
};

} // namespace Rudracore::Core

#include "core/process.h"

// Preemptive round-robin scheduler with a 10 ms time slice, one per CPU.
//
// Task switches happen only on the way out of an interrupt: the interrupt
// handler returns the frame of the task to resume, and the entry code in
// interrupts.S switches to that task's stack before restoring registers.
//
// Each CPU has its own ready queues and runs its own idle task. A task that
// becomes ready goes back to the CPU it ran on, unless that one is busier
// than the least busy CPU by more than one task (then it moves); an idle CPU
// is told at once (an IPI), and a CPU with nothing to run takes work from
// the busiest. All of it runs under the kernel lock.
namespace Rudracore::Sched {

// Turns the boot context (kmain) into the boot CPU's idle task.
void init();

// The same for another CPU starting up (its stack's top: its idle task's).
void initCpu(u32 cpu, u64 stackTop);

Core::Task* spawnKernel(char const* name, void (*entry)(u64), u64 arg);

// The task starts at `entry` in user mode, with its stack at `stackTop`.
// Takes ownership of `space` and of the references in `handles`, which
// become the task's handles 1, 2, 3... (nullptr entries leave a gap).
Core::Task* spawnUser(char const* name, Vmm::Space* space, u64 entry, u64 stackTop,
                      Core::Capability const* handles = nullptr, usize handleCount = 0);

// The same in two steps: the process and its first thread exist (so
// regions can be added to its address space) but don't run until
// startTask, or are thrown away with discard (which also drops its handles
// and space). Its group is `parent`'s, or a new one.
Core::Task* createUser(char const* name, Vmm::Space* space, u64 entry, u64 stackTop,
                       Core::Capability const* handles = nullptr, usize handleCount = 0,
                       Core::Process* parent = nullptr, bool newGroup = false);
void startTask(Core::Task* task);
void discard(Core::Task* task);

// Another thread of `process`, running at `entry` with `arg` (in rdi),
// `stackTop` and its TLS base. nullptr at the thread limit or out of memory.
Core::Task* createThread(Core::Process* process, u64 entry, u64 stackTop, u64 arg, u64 fsBase);

// A thread's thread-local storage base (FS), loaded now if it's running.
void setThreadBase(Core::Task* task, u64 base);

// The current thread ends (its process too, if it was the last).
Arch::Frame* exitThread(Arch::Frame* frame, i64 code);
// The current process ends: every thread, with `code`.
Arch::Frame* exitProcess(Arch::Frame* frame, i64 code);
// Another process ends at once (killed, out of memory): every thread off
// every queue, its resources freed.
void endProcess(Core::Process* process, i64 code);

// Every task that exists (linked by Task::allNext), dead ones not yet freed included.
Core::Task* allTasks();

Core::Task* current();

u64 taskCount();

// For kernel tasks.
void yield();
void sleep(u64 milliseconds);
[[noreturn]] void exit(i64 code);

// Run by the boot task once setup is done: enables interrupts and waits.
[[noreturn]] void idle();

// Makes a Blocked task runnable again, or ends a timed wait (a Sleeping
// task) early. Interrupts must be disabled.
void wake(Core::Task* task);

// For interrupt handlers (interrupts disabled). Each returns the frame of
// the task to resume, which may be a different task.
// The PIT (1 ms, on the boot CPU): the clock, sleepers, and this CPU's slice.
Arch::Frame* onTimerTick(Arch::Frame* frame);
// Another CPU's own local APIC timer (1 ms): its slice.
Arch::Frame* onCpuTick(Arch::Frame* frame);
// A reschedule IPI: work arrived here, or the running thread was ended.
Arch::Frame* onReschedule(Arch::Frame* frame);
Arch::Frame* switchFrom(Arch::Frame* frame);
Arch::Frame* sleepCurrent(Arch::Frame* frame, u64 milliseconds);

// Blocks the current task until something calls wake() on it. The caller
// must have registered the task with the object it waits on first.
Arch::Frame* blockCurrent(Arch::Frame* frame);

// Same, but also wakes up by itself at `deadline` (milliseconds since boot).
Arch::Frame* blockCurrentUntil(Arch::Frame* frame, u64 deadline);

} // namespace Rudracore::Sched

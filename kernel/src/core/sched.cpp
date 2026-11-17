#include "core/random.h"
#include "core/sched.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/smp.h"
#include "core/channel.h"
#include "core/counters.h"
#include "core/device.h"
#include "core/futex.h"
#include "core/time.h"
#include "core/vm.h"
#include "log.h"
#include "rudracore/syscalls.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "panic.h"

extern "C" u8 kernelStackTop[]; // the boot stack, from start.S

namespace Rudracore::Sched {

using Arch::Smp::MAX_CPUS;
using Core::Task;
using Core::TaskState;

namespace {

constexpr u64 STACK_PAGES = 4; // 16 KiB kernel stack per task
constexpr u64 TIME_SLICE_MS = 10;
constexpr u64 RFLAGS_INTERRUPTS_ENABLED = 0x202;

// Two ready queues per CPU: system tasks (kernel tasks, init and what it
// starts) always run before apps, and a ready system task preempts an app
// at the next tick. So an app that spins can slow other apps (round-robin
// among them) but never the drivers, servers or the desktop.
struct Queue {
    Task* head = nullptr;
    Task* tail = nullptr;
};

struct Cpu {
    Task* current = nullptr;
    Task* idle = nullptr;
    Queue ready[2]; // 0: system, 1: apps
    u32 queued = 0;
    u64 sliceStart = 0;
    u64 loadedFsBase = 0; // what its IA32_FS_BASE holds now
};
Cpu cpus[MAX_CPUS];

Cpu& here() { return cpus[Arch::Smp::index()]; }

Core::Privilege privilegeOf(Task const* t) {
    return t->process ? t->process->privilege : Core::Privilege::System;
}

u32 queueOf(Task const* t) { return privilegeOf(t) == Core::Privilege::App ? 1 : 0; }

Task* sleeping = nullptr;
Task* zombies = nullptr;
Task* everyTask = nullptr; // linked by allNext

u64 nextId = 0;
u64 liveTasks = 0;

bool online(u32 c) { return Arch::Smp::onlineMask() & (1ull << c); }

u32 load(u32 c) { return cpus[c].queued + (cpus[c].current != cpus[c].idle ? 1 : 0); }

bool runningAnywhere(Task const* t) {
    for (auto const& c : cpus) {
        if (c.current == t)
            return true;
    }
    return false;
}

// Where a ready task goes: back where it ran (its cache is warm there),
// unless another CPU is less busy by more than one task.
u32 placeFor(Task const* t) {
    u32 best = online(t->cpu) ? t->cpu : 0;
    for (u32 c = 0; c < MAX_CPUS; c++) {
        if (online(c) and load(c) + 1 < load(best))
            best = c;
    }
    return best;
}

void enqueueOn(u32 c, Task* t, bool front) {
    Queue& q = cpus[c].ready[queueOf(t)];
    t->cpu = c;
    if (front) {
        t->next = q.head;
        q.head = t;
        if (not q.tail)
            q.tail = t;
    } else {
        t->next = nullptr;
        if (q.tail)
            q.tail->next = t;
        else
            q.head = t;
        q.tail = t;
    }
    cpus[c].queued++;
    // Another CPU learns at once if it's idle, or running an app while a system task waits.
    u32 me = Arch::Smp::index();
    if (c != me and (cpus[c].current == cpus[c].idle or
                     (queueOf(t) == 0 and cpus[c].current and privilegeOf(cpus[c].current) == Core::Privilege::App)))
        Arch::Smp::interrupt(c, Arch::Smp::VECTOR_RESCHEDULE);
}

void makeReady(Task* t, bool front) { enqueueOn(placeFor(t), t, front); }

Task* takeFrom(u32 c, u32 queue) {
    Queue& q = cpus[c].ready[queue];
    Task* t = q.head;
    if (not t)
        return nullptr;
    q.head = t->next;
    if (not q.head)
        q.tail = nullptr;
    t->next = nullptr;
    cpus[c].queued--;
    return t;
}

// This CPU's next task: its own queues, else work from the busiest CPU.
Task* dequeue() {
    u32 me = Arch::Smp::index();
    for (u32 queue = 0; queue < 2; queue++) {
        if (Task* t = takeFrom(me, queue))
            return t;
    }
    u32 busiest = me;
    for (u32 c = 0; c < MAX_CPUS; c++) {
        if (online(c) and cpus[c].queued > cpus[busiest].queued)
            busiest = c;
    }
    for (u32 queue = 0; busiest != me and queue < 2; queue++) {
        if (Task* t = takeFrom(busiest, queue)) {
            t->cpu = me; // (it moves here)
            return t;
        }
    }
    return nullptr;
}

void wakeSleepers(u64 now) {
    Task** link = &sleeping;
    while (*link) {
        Task* t = *link;
        if (t->wakeAt <= now) {
            *link = t->next;
            t->state = TaskState::Ready;
            makeReady(t, false);
        } else {
            link = &t->next;
        }
    }
}

// Kernel stacks live in their own area of the kernel half, one slot each,
// with an unmapped guard page below the stack: an overflow faults (and the
// double-fault handler, on its own stack, reports it) instead of silently
// overwriting whatever memory comes next.
constexpr u64 STACK_AREA = 0xffffff0000000000;
constexpr u64 STACK_SLOT = (STACK_PAGES + 1) * Mem::PAGE_SIZE;
constexpr u64 MAX_STACKS = 4096;
u64 stackSlots[MAX_STACKS / 64]; // bit set = slot in use

// Maps `physical` as a guarded kernel stack. Returns its top, or 0.
u64 mapKernelStack(u64 physical) {
    for (u64 slot = 0; slot < MAX_STACKS; slot++) {
        if (stackSlots[slot / 64] & (1ull << (slot % 64)))
            continue;
        u64 base = STACK_AREA + slot * STACK_SLOT + Mem::PAGE_SIZE; // the page below stays unmapped
        if (not Vmm::kernelSpace().map(base, physical, STACK_PAGES * Mem::PAGE_SIZE, Vmm::READ | Vmm::WRITE))
            return 0;
        stackSlots[slot / 64] |= 1ull << (slot % 64);
        return base + STACK_PAGES * Mem::PAGE_SIZE;
    }
    return 0;
}

void unmapKernelStack(u64 top) {
    u64 slot = (top - STACK_AREA) / STACK_SLOT - 1;
    Vmm::kernelSpace().unmap(top - STACK_PAGES * Mem::PAGE_SIZE, STACK_PAGES * Mem::PAGE_SIZE);
    stackSlots[slot / 64] &= ~(1ull << (slot % 64));
}

// Frees a dead (or never started) thread. The last thread of a process
// takes its resources with it: by then nothing runs in its address space.
void destroy(Task* t) {
    for (Task** link = &everyTask; *link; link = &(*link)->allNext) {
        if (*link == t) {
            *link = t->allNext;
            break;
        }
    }
    if (Core::Process* p = t->process) {
        for (Task** link = &p->threads; *link; link = &(*link)->threadNext) {
            if (*link == t) {
                *link = t->threadNext;
                break;
            }
        }
        if (not p->threads)
            p->releaseResources();
        p->unref();
    }
    if (t->stackPhysical) {
        unmapKernelStack(t->stackTop);
        Pmm::free(t->stackPhysical, STACK_PAGES);
    }
    delete t;
}

// Off the ready queues and the sleep list, wherever it is.
void unqueue(Task* t) {
    for (auto& c : cpus) {
        for (Queue& q : c.ready) {
            Task* previous = nullptr;
            for (Task* each = q.head; each; previous = each, each = each->next) {
                if (each != t)
                    continue;
                (previous ? previous->next : q.head) = t->next;
                if (q.tail == t)
                    q.tail = previous;
                c.queued--;
                break;
            }
        }
    }
    for (Task** link = &sleeping; *link; link = &(*link)->next) {
        if (*link == t) {
            *link = t->next;
            break;
        }
    }
}

// A thread ends: nothing may keep pointing at it as a waiter, and its
// process learns (join, and its exit when it's the last).
void markDead(Task* t, i64 code) {
    Vm::forgetWait(*t);
    Futex::forget(t);
    t->joinTarget = 0;
    t->exitWaitTarget = nullptr;
    if (Core::Process* p = t->process) {
        for (auto& slot : p->handles) {
            Core::Object* object = slot.cap.object;
            if (object and object->type == Core::ObjectType::Channel and
                static_cast<Core::Endpoint*>(object)->waiter == t)
                static_cast<Core::Endpoint*>(object)->waiter = nullptr;
            if (object and object->type == Core::ObjectType::Irq and static_cast<Core::Irq*>(object)->waiter == t)
                static_cast<Core::Irq*>(object)->waiter = nullptr;
        }
    }
    t->exitCode = code;
    t->state = TaskState::Dead;
    Proc::threadEnded(t, code);
}

// Every thread of `p` but the one running here ends now. One running on
// another CPU is marked dead and that CPU told: it leaves it at once (it
// can't be freed while that CPU is on its stack).
void endOtherThreads(Core::Process* p, i64 code) {
    if (not p->exited) {
        p->exited = true; // (before its threads end: their codes don't become its code)
        p->exitCode = code;
        Proc::wakeExitWaiters(p);
    }
    for (Task* t = p->threads; t;) {
        Task* next = t->threadNext;
        if (t != here().current and t->state != TaskState::Dead) {
            if (runningAnywhere(t)) {
                markDead(t, code);
                Arch::Smp::interrupt(t->cpu, Arch::Smp::VECTOR_RESCHEDULE);
            } else {
                unqueue(t);
                markDead(t, code);
                liveTasks--;
                destroy(t); // (may free p's resources: it was the last)
            }
        }
        t = next;
    }
}

// Dead tasks can't free their own kernel stack while running on it, so they
// wait in the zombie list until no CPU is on it. (`leaving`: the task this
// CPU is switching away from, whose stack it's still on. Other CPUs finish
// their switch before they let go of the kernel lock.)
void reapZombies(Task const* leaving = nullptr) {
    Task** link = &zombies;
    while (*link) {
        Task* t = *link;
        if (t == leaving or runningAnywhere(t)) {
            link = &t->next;
            continue;
        }
        *link = t->next;
        destroy(t);
    }
}

Task* newTask(char const* name) {
    u64 stack = Pmm::alloc(STACK_PAGES);
    if (not stack)
        return nullptr;
    u64 top = mapKernelStack(stack);
    if (not top) {
        Pmm::free(stack, STACK_PAGES);
        return nullptr;
    }

    Task* t = new Task{};
    t->id = nextId++;
    for (usize i = 0; name[i] and i + 1 < sizeof(t->name); i++)
        t->name[i] = name[i];
    Arch::Fpu::initState(t->fpuState);
    t->stackPhysical = stack;
    t->stackTop = top;
    t->cpu = Arch::Smp::index();
    return t;
}

// The first "interrupt return" into a new task uses this frame.
Arch::Frame* initialFrame(Task* t) {
    auto* frame = reinterpret_cast<Arch::Frame*>(t->stackTop - sizeof(Arch::Frame));
    *frame = {};
    frame->rflags = RFLAGS_INTERRUPTS_ENABLED;
    t->savedFrame = reinterpret_cast<u64>(frame);
    return frame;
}

void start(Task* t) {
    Arch::InterruptGuard guard;
    t->allNext = everyTask;
    everyTask = t;
    liveTasks++;
    makeReady(t, false);
}

// Kernel tasks begin here, so returning from `entry` ends the task cleanly.
void kernelTaskStart(void (*entry)(u64), u64 arg) {
    entry(arg);
    exit(0);
}

void kernelSwitch() {
    asm volatile("int %0" : : "i"(Arch::Idt::YIELD_VECTOR) : "memory");
}

Task* makeIdle(u64 stackTop) {
    auto* idle = new Task{};
    idle->id = nextId++;
    char const name[] = "idle";
    for (usize i = 0; i < sizeof(name); i++)
        idle->name[i] = name[i];
    idle->state = TaskState::Running;
    idle->stackTop = stackTop;
    idle->cpu = Arch::Smp::index();
    Arch::Fpu::initState(idle->fpuState);
    return idle;
}

// This CPU's 1 ms: CPU time, the time limit, and the time slice.
Arch::Frame* sliceTick(Arch::Frame* frame) {
    Cpu& cpu = here();
    Task* current = cpu.current;
    if (current != cpu.idle)
        current->cpuMs++; // the 1 ms tick lands on whoever is running
    if (Core::Process* p = current->process) {
        p->cpuMs++;
        if (p->cpuLimitMs and p->cpuMs > p->cpuLimitMs and not p->exited) {
            log("[sched] ", p->name, " (process ", p->id, ") used up its CPU time limit (", p->cpuLimitMs, " ms)");
            return exitProcess(frame, Abi::EXIT_CPU_LIMIT);
        }
    }
    bool waiting = cpu.queued;
    bool othersWaiting = false;
    for (u32 c = 0; not waiting and c < MAX_CPUS; c++)
        othersWaiting = othersWaiting or (online(c) and cpus[c].queued > 1);
    if (not waiting and not(current == cpu.idle and othersWaiting))
        return frame;
    bool appPreempted = privilegeOf(current) == Core::Privilege::App and cpu.ready[0].head;
    if (current == cpu.idle or appPreempted or Time::now() - cpu.sliceStart >= TIME_SLICE_MS)
        return switchFrom(frame);
    return frame;
}

} // namespace

void init() {
    Cpu& cpu = here();
    cpu.idle = cpu.current = makeIdle(reinterpret_cast<u64>(kernelStackTop));
    liveTasks = 1;
    Vmm::kernelSpace().cpuMask |= 1; // (the boot CPU runs on it)
}

void initCpu(u32 index, u64 stackTop) {
    Cpu& cpu = cpus[index];
    cpu.idle = cpu.current = makeIdle(stackTop);
    cpu.sliceStart = Time::now();
    liveTasks++;
    Vmm::kernelSpace().cpuMask |= 1ull << index;
}

Task* spawnKernel(char const* name, void (*entry)(u64), u64 arg) {
    Task* t = newTask(name);
    if (not t)
        return nullptr;

    Arch::Frame* frame = initialFrame(t);
    frame->rip = reinterpret_cast<u64>(&kernelTaskStart);
    frame->rdi = reinterpret_cast<u64>(entry);
    frame->rsi = arg;
    frame->cs = Arch::Gdt::KERNEL_CODE;
    frame->ss = Arch::Gdt::KERNEL_DATA;

    // Start below the frame, as if kernelTaskStart had been called: the ABI
    // expects rsp % 16 == 8 on function entry, with a return address there.
    u64 rsp = reinterpret_cast<u64>(frame) - 8;
    *reinterpret_cast<u64*>(rsp) = 0;
    frame->rsp = rsp;

    start(t);
    return t;
}

Task* spawnUser(char const* name, Vmm::Space* space, u64 entry, u64 stackTop,
                Core::Capability const* handles, usize handleCount) {
    Task* t = createUser(name, space, entry, stackTop, handles, handleCount);
    if (t)
        start(t);
    return t;
}

void startTask(Task* t) { start(t); }

void setThreadBase(Task* t, u64 base) {
    Arch::InterruptGuard guard;
    t->fsBase = base;
    if (t == here().current) {
        Arch::writeMsr(Arch::Msr::FS_BASE, base);
        here().loadedFsBase = base;
    }
}

void discard(Task* t) {
    Arch::InterruptGuard guard;
    if (t->process)
        t->process->liveThreads = 0;
    destroy(t); // (its process goes with it: it was the only thread)
}

Task* createUser(char const* name, Vmm::Space* space, u64 entry, u64 stackTop, Core::Capability const* handles,
                 usize handleCount, Core::Process* parent, bool newGroup) {
    Task* t = newTask(name);
    if (not t) {
        Vmm::destroyUserSpace(space);
        for (usize i = 0; i < handleCount; i++) {
            if (handles[i].object)
                handles[i].object->unref();
        }
        return nullptr;
    }

    Core::Process* p = Proc::create(name, space, parent, newGroup);
    p->id = t->id; // (a process's id is its first thread's)
    if (not p->group)
        p->group = p->id;
    // Half of RAM per program: shortcut, a fixed share; per-program limits set by init could come later.
    p->quota = new Core::Quota(Pmm::stats().managedPages / 2);
    for (usize i = 0; i < handleCount and i + 1 < Core::Process::MAX_HANDLES; i++)
        p->handles[i + 1].cap = handles[i];
    p->ref();
    p->threads = t;
    p->liveThreads = 1;
    t->process = p;

    Arch::Frame* frame = initialFrame(t);
    frame->rip = entry;
    frame->rsp = stackTop;
    frame->cs = Arch::Gdt::USER_CODE;
    frame->ss = Arch::Gdt::USER_DATA;
    return t;
}

Task* createThread(Core::Process* p, u64 entry, u64 stackTop, u64 arg, u64 fsBase) {
    Arch::InterruptGuard guard;
    if (p->exited or p->liveThreads >= p->threadLimit)
        return nullptr;
    Task* t = newTask(p->name);
    if (not t)
        return nullptr;
    p->ref();
    t->process = p;
    t->threadNext = p->threads;
    p->threads = t;
    p->liveThreads++;
    t->fsBase = fsBase;

    Arch::Frame* frame = initialFrame(t);
    frame->rip = entry;
    frame->rsp = stackTop;
    frame->rdi = arg;
    frame->cs = Arch::Gdt::USER_CODE;
    frame->ss = Arch::Gdt::USER_DATA;
    start(t);
    return t;
}

Arch::Frame* exitThread(Arch::Frame* frame, i64 code) {
    Task* current = here().current;
    if (current == here().idle)
        panic("sched: the idle task can't exit");
    bool last = current->process and current->process->liveThreads == 1;
    markDead(current, code);
    if (last)
        log("[sched] ", current->name, " (process ", current->process->id, ") exited with code ",
            current->process->exitCode);
    return switchFrom(frame);
}

Arch::Frame* exitProcess(Arch::Frame* frame, i64 code) {
    Task* current = here().current;
    if (current == here().idle)
        panic("sched: the idle task can't exit");
    Core::Process* p = current->process;
    if (p) {
        endOtherThreads(p, code);
        log("[sched] ", p->name, " (process ", p->id, ") exited with code ", p->exitCode);
    }
    markDead(current, code);
    return switchFrom(frame);
}

void endProcess(Core::Process* p, i64 code) {
    Arch::InterruptGuard guard;
    if (here().current->process == p)
        panic("sched: endProcess on the current process (use exitProcess)");
    if (p->exited and not p->liveThreads)
        return;
    p->ref(); // (its last thread may free it)
    endOtherThreads(p, code);
    log("[sched] ", p->name, " (process ", p->id, ") was ended, code ", p->exitCode);
    p->unref();
}

Task* allTasks() {
    return everyTask;
}

Task* current() {
    return here().current;
}

u64 taskCount() {
    Arch::InterruptGuard guard;
    return liveTasks;
}

void yield() {
    kernelSwitch();
}

void sleep(u64 milliseconds) {
    Arch::InterruptGuard guard;
    here().current->wakeAt = Time::now() + milliseconds;
    here().current->state = TaskState::Sleeping;
    kernelSwitch();
}

void exit(i64 code) {
    Arch::disableInterrupts();
    Arch::Smp::enterKernel();
    Task* current = here().current;
    if (current == here().idle)
        panic("sched: the idle task can't exit");
    current->exitCode = code;
    current->state = TaskState::Dead;
    log("[sched] ", current->name, " (task ", current->id, ") finished");
    Arch::Smp::leaveKernel();
    kernelSwitch();
    panic("sched: a dead task was resumed");
}

void idle() {
    for (;;)
        Arch::Cpu::idle();
}

Arch::Frame* switchFrom(Arch::Frame* frame) {
    u64 started = Arch::readTsc(); // (context-switch profiling)
    Cpu& cpu = here();
    u32 me = Arch::Smp::index();
    Task* prev = cpu.current;
    prev->savedFrame = reinterpret_cast<u64>(frame);
    Arch::Fpu::save(prev->fpuState);
    // The kernel lock it held below this interrupt (a kernel task inside a
    // guard) goes with it; this interrupt's own level stays with the CPU.
    prev->lockDepth = Arch::Smp::kernelDepth() - 1;

    switch (prev->state) {
    case TaskState::Running:
        prev->state = TaskState::Ready;
        if (prev != cpu.idle)
            enqueueOn(me, prev, false); // (here: a preempted task stays on its CPU)
        break;
    case TaskState::Sleeping:
        prev->next = sleeping;
        sleeping = prev;
        break;
    case TaskState::Dead:
        prev->next = zombies;
        zombies = prev;
        liveTasks--;
        break;
    case TaskState::Blocked: // the object it waits on will wake it
    case TaskState::Ready:
        break;
    }

    Task* next = dequeue();
    if (not next)
        next = cpu.idle;

    next->state = TaskState::Running;
    cpu.current = next;
    cpu.sliceStart = Time::now();
    reapZombies(prev);

    // Interrupts from user mode must land on this task's kernel stack.
    Arch::Gdt::setKernelStack(next->stackTop);
    Arch::Fpu::restore(next->fpuState);

    Vmm::Space const& from = prev->process and prev->process->space ? *prev->process->space : Vmm::kernelSpace();
    Vmm::Space const& space = next->process and next->process->space ? *next->process->space : Vmm::kernelSpace();
    if (&from != &space or Arch::readCr3() != space.root) {
        from.cpuMask &= ~(1ull << me); // (shootdowns of it no longer need this CPU)
        space.cpuMask |= 1ull << me;
        space.activate();
    }
    // Thread-local storage: each thread's FS base.
    if (next->fsBase != cpu.loadedFsBase) {
        Arch::writeMsr(Arch::Msr::FS_BASE, next->fsBase);
        cpu.loadedFsBase = next->fsBase;
    }
    Arch::Smp::setKernelDepth(next->lockDepth + 1);

    Counters::add(Counters::all.switches);
    Counters::add(Counters::all.switchCycles, Arch::readTsc() - started);
    return reinterpret_cast<Arch::Frame*>(next->savedFrame);
}

Arch::Frame* onTimerTick(Arch::Frame* frame) {
    Time::tick();
    Random::stir();
    reapZombies(); // free a finished task's memory now, even if nothing else is ready to run
    wakeSleepers(Time::now());
    return sliceTick(frame);
}

Arch::Frame* onCpuTick(Arch::Frame* frame) {
    return sliceTick(frame);
}

Arch::Frame* onReschedule(Arch::Frame* frame) {
    Cpu& cpu = here();
    if (cpu.current->state == TaskState::Dead or cpu.current == cpu.idle or
        (privilegeOf(cpu.current) == Core::Privilege::App and cpu.ready[0].head))
        return switchFrom(frame);
    return frame;
}

// A task woken by a message or an interrupt runs next, ahead of tasks that
// were preempted: it's waiting on something that just happened (a reply, a
// key press), so running it right away keeps IPC fast and input responsive.
// Fairness: that head start is given at most once per time slice, so a
// pair of tasks waking each other in a tight loop can't keep the others on
// their CPU waiting forever.
void wake(Task* task) {
    if (task->state == TaskState::Sleeping) {
        // A timed wait ending early: take it off the sleep list.
        for (Task** link = &sleeping; *link; link = &(*link)->next) {
            if (*link == task) {
                *link = task->next;
                break;
            }
        }
    } else if (task->state != TaskState::Blocked) {
        return;
    }
    task->state = TaskState::Ready;
    u64 now = Time::now();
    bool boost = now - task->lastBoost >= TIME_SLICE_MS or task->lastBoost == 0;
    if (boost)
        task->lastBoost = now ? now : 1;
    makeReady(task, boost);
}

Arch::Frame* blockCurrentUntil(Arch::Frame* frame, u64 deadline) {
    if (here().current == here().idle)
        panic("sched: the idle task can't block");
    here().current->wakeAt = deadline;
    here().current->state = TaskState::Sleeping;
    return switchFrom(frame);
}

Arch::Frame* blockCurrent(Arch::Frame* frame) {
    if (here().current == here().idle)
        panic("sched: the idle task can't block");
    here().current->state = TaskState::Blocked;
    return switchFrom(frame);
}

Arch::Frame* sleepCurrent(Arch::Frame* frame, u64 milliseconds) {
    here().current->wakeAt = Time::now() + milliseconds;
    here().current->state = TaskState::Sleeping;
    return switchFrom(frame);
}

} // namespace Rudracore::Sched

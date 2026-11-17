#include "core/process.h"

#include "core/channel.h"
#include "core/device.h"
#include "core/sched.h"
#include "log.h"

namespace Rudracore::Core {

static_assert(Process::MAX_HANDLES <= 256, "a handle's slot is its low 8 bits");

u64 Process::addHandle(Capability cap) {
    for (u64 slot = 1; slot < MAX_HANDLES; slot++) {
        if (not handles[slot].cap.object) {
            handles[slot].cap = cap;
            return (handles[slot].generation << 8) | slot;
        }
    }
    return 0;
}

Capability* Process::handle(u64 h) {
    u64 slot = h & 0xFF;
    if (slot == 0 or slot >= MAX_HANDLES or not handles[slot].cap.object or handles[slot].generation != h >> 8)
        return nullptr;
    return &handles[slot].cap;
}

Capability Process::takeHandle(u64 h) {
    Capability* cap = handle(h);
    if (not cap)
        return {};
    Capability taken = *cap;
    *cap = {};
    handles[h & 0xFF].generation++;
    return taken;
}

void Process::releaseResources() {
    if (released)
        return;
    released = true;
    for (auto& slot : handles) {
        if (Object* object = slot.cap.object) {
            object->unref();
            slot.cap = {};
        }
    }
    if (events) {
        events->unref();
        events = nullptr;
    }

    // Tear down the address space before dropping the mapped objects, so
    // their memory is never still mapped when it gets freed.
    if (space) {
        Vmm::destroyUserSpace(space);
        space = nullptr;
    }
    Vm::release(*this); // its regions: promises and quota back, objects let go

    if (quota) {
        quota->unref();
        quota = nullptr;
    }
}

u64 Process::cpuTime() const { return cpuMs; }

ProcessObject::~ProcessObject() { process->unref(); }

} // namespace Rudracore::Core

namespace Rudracore::Proc {

using Core::Process;
using Core::Task;

namespace {

Process* processes = nullptr;

} // namespace

void forget(Process* p) {
    for (Process** link = &processes; *link; link = &(*link)->allNext) {
        if (*link == p) {
            *link = p->allNext;
            return;
        }
    }
}

Process* all() { return processes; }

Process* find(u64 id) {
    for (Process* p = processes; p; p = p->allNext) {
        if (p->id == id)
            return p;
    }
    return nullptr;
}

Process* create(char const* name, Vmm::Space* space, Process* parent, bool newGroup) {
    auto* p = new Process{};
    for (usize i = 0; name[i] and i + 1 < sizeof(p->name); i++)
        p->name[i] = name[i];
    p->space = space;
    p->parent = parent ? parent->id : 0;
    p->group = parent and not newGroup ? parent->group : 0; // (0: its own, set with its id)
    p->allNext = processes;
    processes = p;
    return p;
}

void wakeExitWaiters(Process* p) {
    for (Task* t = Sched::allTasks(); t; t = t->allNext) {
        if (t->exitWaitTarget == p) {
            t->exitWaitTarget = nullptr;
            Sched::wake(t);
        }
    }
}

void threadEnded(Task* thread, i64 code) {
    Process* p = thread->process;
    if (not p)
        return;
    // Its exit code, for join (the oldest is dropped when the list is full).
    p->finished[p->finishedNext] = {thread->id, code};
    p->finishedNext = (p->finishedNext + 1) % Process::FINISHED;
    for (Task* t = p->threads; t; t = t->threadNext) {
        if (t->joinTarget == thread->id) {
            t->joinTarget = 0;
            Sched::wake(t);
        }
    }
    if (p->liveThreads and --p->liveThreads == 0 and not p->exited) {
        p->exited = true;
        p->exitCode = code;
        wakeExitWaiters(p);
    }
}

bool takeFinished(Process* p, u64 thread, i64& code) {
    for (auto& f : p->finished) {
        if (f.thread == thread) {
            code = f.code;
            f = {};
            return true;
        }
    }
    return false;
}

} // namespace Rudracore::Proc

namespace Rudracore::Core {

void Process::unref() {
    if (--refs)
        return;
    releaseResources();
    Proc::forget(this);
    delete this;
}

} // namespace Rudracore::Core

#pragma once

#include "core/object.h"
#include "core/quota.h"
#include "core/vm.h"
#include "mem/vmm.h"

namespace Rudracore::Core {

struct Task;
struct Endpoint;

// Who a process is, which bounds what it may hold and do:
//   Root    init (started by the kernel)
//   System  what init starts: drivers, servers, KamalShell, boot checks
//   App     what anything else starts: built-in and installed apps
// Only Root and System processes may start programs, and an App never holds
// hardware (devices, IRQs, I/O ports, device memory).
enum class Privilege : u8 {
    App,
    System,
    Root,
};

// A running program: its address space, handles, memory, and threads.
//
// Lifetime: it lives while it has threads or something refers to it (a
// process handle). When its last thread ends it has exited: its exit code is
// fixed, waiters wake, and once that thread is gone its resources (handles,
// memory, address space) are released. The struct stays while handles to it
// remain, so its exit code can still be read.
struct Process {
    static constexpr usize MAX_HANDLES = 64;
    static constexpr usize FINISHED = 16; // exit codes of ended threads kept for join

    u64 id = 0;
    char name[32] = {};
    Privilege privilege = Privilege::App;
    u64 group = 0;               // process group: the id of the group's first process
    u64 parent = 0;              // the id of the process that started it (0: the kernel)

    Vmm::Space* space = nullptr;
    Quota* quota = nullptr;      // the memory and objects it may hold (holds a reference)
    Vm::Map vm;                  // its address space's regions

    // A handle's value is (generation << 8) | slot; the generation counts
    // how often the slot was freed, so a stale value never matches.
    struct HandleSlot {
        Capability cap;
        u64 generation = 0;
    };
    HandleSlot handles[MAX_HANDLES] = {}; // slot 0 is never used

    Task* threads = nullptr;     // linked by Task::threadNext (all, dead ones too until reaped)
    u32 liveThreads = 0;
    u32 refs = 0;                // threads (alive or not yet reaped) + process handles
    bool exited = false;         // its last thread ended
    bool released = false;       // its resources are gone
    i64 exitCode = 0;
    u64 cpuMs = 0;               // CPU time of its ended threads (live ones count their own)

    // Resource limits (process_limit): lowered by itself or whoever holds a
    // handle to it, never raised.
    u32 threadLimit = 64;
    u64 cpuLimitMs = 0;          // 0: none

    Endpoint* events = nullptr;  // where its events go (process_events; holds a reference)

    // When a thread faulted and ended it (EXIT_FAULT): what happened.
    u64 faultVector = 0, faultAddress = 0, faultRip = 0;

    struct Finished {
        u64 thread = 0;
        i64 code = 0;
    };
    Finished finished[FINISHED] = {}; // ended threads not joined yet (oldest dropped when full)
    u32 finishedNext = 0;

    Process* allNext = nullptr;  // every process (Proc::all)

    // Takes over the capability's reference. Returns the handle, or 0 if the
    // table is full.
    u64 addHandle(Capability cap);

    // The capability behind a handle (no reference added; revoked ones
    // included), or nullptr if the handle isn't open.
    Capability* handle(u64 h);

    // Removes the handle and returns its capability (and reference) to the
    // caller; an empty one if the handle isn't open.
    Capability takeHandle(u64 h);

    // Drops every handle and region, and the address space. Run once no
    // thread of it can run anymore.
    void releaseResources();

    // CPU time of all its threads, ended and running.
    u64 cpuTime() const;

    void ref() { refs++; }
    void unref();
};

// A handle to a process (spawn with SPAWN_HANDLE): wait for it, signal it,
// limit it. Holds a reference, so its exit code outlives it.
struct ProcessObject : public Object {
    Process* process;

    explicit ProcessObject(Process* p) : Object(ObjectType::Process), process(p) { p->ref(); }
    ~ProcessObject() override;
};

} // namespace Rudracore::Core

// Processes as a whole: their list, exits and groups.
namespace Rudracore::Proc {

Core::Process* all();
Core::Process* find(u64 id);

// A new process (no threads yet), registered. Its group is its parent's,
// or its own when `newGroup`.
Core::Process* create(char const* name, Vmm::Space* space, Core::Process* parent, bool newGroup);

// A thread of it ended with `code` (its last one: the process has exited
// with that code, unless it was already ending with another).
void threadEnded(Core::Task* thread, i64 code);

// Whoever waits for it (process_wait) wakes.
void wakeExitWaiters(Core::Process* process);

// A finished thread's exit code (and forgets it), if it's kept.
bool takeFinished(Core::Process* process, u64 thread, i64& code);

// Off the list (it's being freed).
void forget(Core::Process* process);

} // namespace Rudracore::Proc

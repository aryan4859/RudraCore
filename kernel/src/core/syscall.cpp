#include "core/syscall.h"

#include "arch/x86_64/io.h"
#include "arch/x86_64/acpi.h"
#include "arch/x86_64/apic.h"
#include "arch/x86_64/efi.h"
#include "arch/x86_64/iommu.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/protect.h"
#include "core/channel.h"
#include "core/device.h"
#include "core/programs.h"
#include "core/random.h"
#include "core/sched.h"
#include "core/shared_memory.h"
#include "core/time.h"
#include "display.h"
#include "log.h"
#include "mem/heap.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "rudracore/syscalls.h"
#include "config.h"

#define RUDRACORE_FAULT_TEST_DMA (RUDRACORE_FAULT_TEST == 4)

extern "C" void* memcpy(void* dest, void const* src, usize n);
extern "C" void* memset(void* dest, int value, usize n);

namespace Rudracore::Syscall {

using Core::Object;
using Core::ObjectType;
using Core::Task;

namespace {

constexpr u64 MAX_LOG_LENGTH = 1024;
constexpr u64 MAX_SPAWN_HANDLES = 8;
constexpr u64 INT80_LENGTH = 2; // `int $0x80` is 2 bytes: CD 80

// Longest wait a program may ask for (about 34 years): keeps now + timeout
// from wrapping around.
constexpr u64 MAX_TIMEOUT_MS = 1ull << 40;

// The only ways the kernel touches user memory. The range must already be
// checked (Call::userMemory). With SMAP, user pages are reachable only here.
void fromUser(void* to, u64 from, u64 length) {
    Arch::Protect::UserAccess open;
    memcpy(to, reinterpret_cast<void const*>(from), length);
}

void toUser(u64 to, void const* from, u64 length) {
    Arch::Protect::UserAccess open;
    memcpy(reinterpret_cast<void*>(to), from, length);
}

// Text from a program that goes into the kernel log: control characters
// (newlines, terminal escapes) would let it forge log lines.
void makePrintable(char* text, u64 length) {
    for (u64 i = 0; i < length; i++) {
        if (static_cast<u8>(text[i]) < 0x20 or text[i] == 0x7F)
            text[i] = '?';
    }
}

// Everything a system call needs: the caller and its saved registers.
struct Call {
    Arch::Frame* frame;
    Task* task;

    u64 arg0() const { return frame->rdi; }
    u64 arg1() const { return frame->rsi; }
    u64 arg2() const { return frame->rdx; }
    u64 arg3() const { return frame->r10; }
    u64 arg4() const { return frame->r8; }

    Arch::Frame* result(i64 value) const {
        frame->rax = static_cast<u64>(value);
        return frame;
    }

    // Puts the task to sleep until it's woken, then runs the same system
    // call again from the start: rax and the arguments are still in the
    // frame, so rewinding rip over `int $0x80` is all it takes. When it
    // runs again the call finds what it was waiting for (or an error).
    Arch::Frame* blockAndRetry() const {
        frame->rip -= INT80_LENGTH;
        return Sched::blockCurrent(frame);
    }

    // A range of the caller's memory the call may read (or write): made
    // present now (demand paging, copy-on-write). If a page has to come
    // from a pager first, it's false and the whole call runs again once
    // the page is there (dispatch sees `wait`).
    bool userMemory(u64 address, u64 length, bool writable = false) const {
        if (length == 0)
            return address + length >= address and address <= Vmm::USER_END;
        switch (Vm::prepare(*task, address, length, writable)) {
        case Vm::Fault::Resolved: return true;
        case Vm::Fault::Pending: wait = Wait::Pager; return false;
        case Vm::Fault::Retry: wait = Wait::Moment; return false;
        case Vm::Fault::OutOfMemory: wait = Wait::OutOfMemory; return false;
        case Vm::Fault::Invalid: return false;
        }
        return false;
    }

    enum class Wait : u8 { None, Pager, Moment, OutOfMemory };
    mutable Wait wait = Wait::None;

    // A live handle (open, not revoked) that has all of `rights`;
    // otherwise sets `error`.
    Core::Capability* capability(u64 handle, u32 rights, i64& error) const {
        Core::Capability* cap = task->handle(handle);
        if (not cap) {
            error = Abi::BAD_HANDLE;
            return nullptr;
        }
        if (cap->revoked()) {
            error = Abi::REVOKED;
            return nullptr;
        }
        if ((cap->rights & rights) != rights) {
            error = Abi::ACCESS_DENIED;
            return nullptr;
        }
        return cap;
    }

    // The object behind a live handle of the right type with all of
    // `rights`; otherwise sets `error`.
    template <typename T>
    T* lookup(u64 handle, ObjectType type, u32 rights, i64& error) const {
        Core::Capability* cap = capability(handle, 0, error);
        if (not cap)
            return nullptr;
        if (cap->object->type != type) {
            error = Abi::WRONG_TYPE;
            return nullptr;
        }
        if ((cap->rights & rights) != rights) {
            error = Abi::ACCESS_DENIED;
            return nullptr;
        }
        return static_cast<T*>(cap->object);
    }

    // Checks handles about to be moved to a new program: live, no
    // duplicates, none equal to `except`, and with RIGHT_TRANSFER if asked.
    i64 checkMovable(Abi::Handle const* handles, u64 count, bool needTransfer, Abi::Handle except) const {
        for (u64 i = 0; i < count; i++) {
            i64 error = 0;
            if (handles[i] == except)
                return Abi::BAD_HANDLE;
            if (not capability(handles[i], needTransfer ? Abi::RIGHT_TRANSFER : 0, error))
                return error;
            for (u64 j = 0; j < i; j++) {
                if (handles[j] == handles[i])
                    return Abi::INVALID_ARGUMENT;
            }
        }
        return Abi::OK;
    }
};

// A running task waits on nothing: clears it as the waiter of any channel
// it holds (a registration left behind when a wait ended early).
void forgetWaits(Task* task) {
    for (auto& slot : task->handles) {
        Object* object = slot.cap.object;
        if (object and object->type == ObjectType::Channel and static_cast<Core::Endpoint*>(object)->waiter == task)
            static_cast<Core::Endpoint*>(object)->waiter = nullptr;
    }
}

// Hardware: devices, interrupt lines, I/O ports, and device memory (a
// device's registers, the screen). Apps never hold any.
bool isHardware(Object const* object) {
    switch (object->type) {
    case ObjectType::Irq:
    case ObjectType::IoPorts:
    case ObjectType::PciDevice:
    case ObjectType::Firmware: return true;
    case ObjectType::Memory: return static_cast<Core::SharedMemory const*>(object)->hardware;
    case ObjectType::Channel: return false;
    }
    return true;
}

// What a new program started by `parent` is: init's programs are system
// services, everything else is an app.
Core::Privilege childPrivilege(Task const* parent) {
    return parent->privilege == Core::Privilege::Root ? Core::Privilege::System : Core::Privilege::App;
}

// Resource limits by privilege: an app may hold a quarter of RAM and 256
// kernel objects; system services half and 1024 (Sched::spawnUser's defaults).
void setPrivilege(Task* task, Core::Privilege privilege) {
    task->privilege = privilege;
    if (privilege == Core::Privilege::App) {
        task->quota->limit = Pmm::stats().managedPages / 4;
        task->quota->objectLimit = Core::Quota::APP_OBJECT_LIMIT;
    }
}

// Before handles move to a new app: none may be hardware.
i64 checkNoHardware(Call const& c, Abi::Handle const* handles, u64 count) {
    for (u64 i = 0; i < count; i++) {
        if (isHardware(c.task->handle(handles[i])->object))
            return Abi::ACCESS_DENIED;
    }
    return Abi::OK;
}

// Rights a new object of each kind starts with, in the handle that made it.
constexpr u32 CHANNEL_RIGHTS = Abi::RIGHT_READ | Abi::RIGHT_WRITE | Abi::RIGHT_TRANSFER | Abi::RIGHT_DUPLICATE |
                               Abi::RIGHT_REVOKE;
constexpr u32 MEMORY_RIGHTS = CHANNEL_RIGHTS;
// Boot files are one object shared by every program that opens them: no
// writing, and nobody may revoke everyone else's copy.
constexpr u32 FILE_RIGHTS = Abi::RIGHT_READ | Abi::RIGHT_TRANSFER | Abi::RIGHT_DUPLICATE;
// A device's registers stay with the driver that mapped them.
constexpr u32 REGISTER_RIGHTS = Abi::RIGHT_READ | Abi::RIGHT_WRITE;

// MARK: Tasks

Arch::Frame* sysLog(Call const& c) {
    u64 address = c.arg0();
    u64 length = c.arg1();

    if (length > MAX_LOG_LENGTH)
        return c.result(Abi::INVALID_ARGUMENT);

    // Never trust a pointer from userspace: it must be user memory that is
    // actually mapped in the caller's own address space.
    if (not c.userMemory(address, length))
        return c.result(Abi::BAD_ADDRESS);

    char text[MAX_LOG_LENGTH];
    fromUser(text, address, length);
    // Drop a trailing newline; log() adds its own.
    if (length > 0 and text[length - 1] == '\n')
        length--;
    makePrintable(text, length);

    log("[", c.task->name, "] ", Str{text, length});
    return c.result(Abi::OK);
}

Arch::Frame* sysSpawn(Call const& c) {
    u64 nameAddress = c.arg0();
    u64 nameLength = c.arg1();
    u64 handlesAddress = c.arg2();
    u64 handleCount = c.arg3();

    char name[32];
    if (c.task->privilege == Core::Privilege::App)
        return c.result(Abi::ACCESS_DENIED); // apps can't start programs
    if (nameLength == 0 or nameLength >= sizeof(name) or handleCount > MAX_SPAWN_HANDLES)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(nameAddress, nameLength) or
        not c.userMemory(handlesAddress, handleCount * sizeof(Abi::Handle)))
        return c.result(Abi::BAD_ADDRESS);

    fromUser(name, nameAddress, nameLength);
    name[nameLength] = '\0';

    // No such program: fail before taking any handle, so the caller still
    // has them (e.g. to start an installed app instead).
    if (not Programs::exists(name, nameLength))
        return c.result(Abi::NOT_FOUND);

    // Check every handle before moving any, so a bad one changes nothing.
    // Boot-image programs are part of the system: RIGHT_TRANSFER isn't needed.
    Abi::Handle handles[MAX_SPAWN_HANDLES];
    fromUser(handles, handlesAddress, handleCount * sizeof(Abi::Handle));
    if (i64 bad = c.checkMovable(handles, handleCount, false, Abi::NO_HANDLE))
        return c.result(bad);
    Core::Privilege privilege = childPrivilege(c.task);
    if (privilege == Core::Privilege::App)
        if (i64 bad = checkNoHardware(c, handles, handleCount))
            return c.result(bad);

    Core::Capability objects[MAX_SPAWN_HANDLES];
    for (u64 i = 0; i < handleCount; i++)
        objects[i] = c.task->takeHandle(handles[i]);

    Abi::Error code = Abi::OK;
    char const* error = nullptr;
    Task* child = Programs::start(name, nameLength, objects, handleCount, code, error);
    if (not child) {
        log("[sched] ", c.task->name, " can't start ", static_cast<char const*>(name), ": ", error);
        return c.result(code);
    }
    setPrivilege(child, privilege);

    log("[sched] ", c.task->name, " started ", child->name, " as task ", child->id,
        " with ", handleCount, " handle(s)");
    return c.result(static_cast<i64>(child->id));
}

Arch::Frame* sysSpawnImage(Call const& c) {
    Abi::SpawnImage request;
    if (c.task->privilege == Core::Privilege::App)
        return c.result(Abi::ACCESS_DENIED);
    if (not c.userMemory(c.arg0(), sizeof(request)))
        return c.result(Abi::BAD_ADDRESS);
    fromUser(&request, c.arg0(), sizeof(request));
    request.name[sizeof(request.name) - 1] = '\0';
    u64 nameLength = 0;
    while (request.name[nameLength])
        nameLength++;
    makePrintable(request.name, nameLength);
    if (request.handleCount > MAX_SPAWN_HANDLES or request.name[0] == '\0')
        return c.result(Abi::INVALID_ARGUMENT);

    i64 error = 0;
    auto* memory = c.lookup<Core::SharedMemory>(request.memory, ObjectType::Memory, Abi::RIGHT_READ, error);
    if (not memory)
        return c.result(error);
    if (memory->hardware or memory->paged() or request.size == 0 or request.size > memory->size)
        return c.result(Abi::INVALID_ARGUMENT);
    // The app runs from its image copy-on-write, so the image must never
    // change: a sealed one is used as it is, any other is copied (and the
    // copy sealed) first. The copy is charged to the caller.
    Core::SharedMemory* image = memory;
    if (not memory->sealed) {
        u64 pages = Mem::alignUp(request.size, Mem::PAGE_SIZE) / Mem::PAGE_SIZE;
        if (not c.task->quota->chargeObjects(1))
            return c.result(Abi::OUT_OF_MEMORY);
        if (not c.task->quota->charge(pages)) {
            c.task->quota->refundObjects(1);
            return c.result(Abi::OUT_OF_MEMORY);
        }
        image = Core::SharedMemory::allocate(request.size);
        if (not image) {
            c.task->quota->refund(pages);
            c.task->quota->refundObjects(1);
            return c.result(Abi::OUT_OF_MEMORY);
        }
        image->chargeTo(c.task->quota, pages);
        memcpy(Mem::toVirtual<u8>(image->physical), Mem::toVirtual<u8>(memory->physical), request.size);
        image->readOnly = image->sealed = true;
    } else {
        image->ref();
    }

    // Check every handle before moving any, so a bad one changes nothing.
    // An installed app is untrusted code: each handle needs RIGHT_TRANSFER.
    i64 bad = c.checkMovable(request.handles, request.handleCount, true, request.memory);
    if (not bad)
        bad = checkNoHardware(c, request.handles, request.handleCount); // installed apps are always apps
    if (bad) {
        image->unref();
        return c.result(bad);
    }
    Core::Capability objects[MAX_SPAWN_HANDLES];
    for (u64 i = 0; i < request.handleCount; i++)
        objects[i] = c.task->takeHandle(request.handles[i]);

    Abi::Error code = Abi::OK;
    char const* why = nullptr;
    Task* child = Programs::startImage(request.name, image, request.size, objects, request.handleCount, code, why);
    image->unref(); // (the app's regions hold their own references)
    if (not child) {
        log("[sched] ", c.task->name, " can't start the app ", static_cast<char const*>(request.name), ": ", why);
        return c.result(code);
    }
    setPrivilege(child, Core::Privilege::App);
    log("[sched] ", c.task->name, " started the app ", child->name, " as task ", child->id, " with ",
        request.handleCount, " handle(s)");
    return c.result(static_cast<i64>(child->id));
}

Arch::Frame* sysSystemInfo(Call const& c, Boot::Info const& boot) {
    u64 address = c.arg0();
    if (not c.userMemory(address, sizeof(Abi::SystemInfo), true))
        return c.result(Abi::BAD_ADDRESS);

    auto stats = Pmm::stats();
    Abi::SystemInfo info;
    memset(&info, 0, sizeof(info)); // padding too: no stale kernel stack bytes reach the program
    info.uptimeMs = Time::now();
    info.totalMemory = stats.managedPages * Mem::PAGE_SIZE;
    info.freeMemory = stats.freePages * Mem::PAGE_SIZE;
    info.taskCount = Sched::taskCount();
    info.timeOfDay = Time::timeOfDay();
    info.unixTime = Time::unixTime();
    info.bootMode = boot.mode;
    if (c.task->privilege != Core::Privilege::App)
        info.acpiRsdp = boot.acpiRsdp;
    if (boot.hasFramebuffer) {
        auto const& fb = boot.framebuffer;
        info.screenWidth = fb.width;
        info.screenHeight = fb.height;
        info.screenPitch = fb.pitch;
        info.redShift = fb.redShift;
        info.greenShift = fb.greenShift;
        info.blueShift = fb.blueShift;
    }
    toUser(address, &info, sizeof(info));
    return c.result(Abi::OK);
}

// Every task's name, CPU time and memory (per-process accounting).
Arch::Frame* sysTaskList(Call const& c) {
    u64 capacity = c.arg1();
    if (capacity > 1024)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(c.arg0(), capacity * sizeof(Abi::TaskInfo), true))
        return c.result(Abi::BAD_ADDRESS);
    u64 count = 0;
    for (Task* t = Sched::allTasks(); t; t = t->allNext) {
        if (t->state == Core::TaskState::Dead)
            continue;
        if (count < capacity) {
            Abi::TaskInfo info;
            memset(&info, 0, sizeof(info));
            info.id = t->id;
            for (usize i = 0; i + 1 < sizeof(info.name) and t->name[i]; i++)
                info.name[i] = t->name[i];
            info.privilege = t->privilege == Core::Privilege::Root     ? Abi::TASK_ROOT
                             : t->privilege == Core::Privilege::System ? Abi::TASK_SYSTEM
                                                                       : Abi::TASK_APP;
            info.state = t->state == Core::TaskState::Running ? Abi::TASK_RUNNING
                         : t->state == Core::TaskState::Ready ? Abi::TASK_READY
                                                              : Abi::TASK_WAITING;
            info.cpuMs = t->cpuMs;
            Vm::Usage u = Vm::usage(*t);
            info.regions = u.regions;
            info.residentBytes = u.resident * Mem::PAGE_SIZE;
            info.committedBytes = u.committed * Mem::PAGE_SIZE;
            info.sharedBytes = u.shared * Mem::PAGE_SIZE;
            toUser(c.arg0() + count * sizeof(info), &info, sizeof(info));
        }
        count++;
    }
    return c.result(static_cast<i64>(count));
}

Arch::Frame* sysKernelStats(Call const& c) {
    if (not c.userMemory(c.arg0(), sizeof(Abi::KernelStats), true))
        return c.result(Abi::BAD_ADDRESS);
    Heap::Stats heap = Heap::stats();
    Abi::KernelStats s;
    memset(&s, 0, sizeof(s));
    s.heapBytes = heap.bytesInUse;
    s.heapPeakBytes = heap.peakBytes;
    s.heapPages = heap.pagesUsed;
    s.heapAllocations = heap.allocations;
    s.heapFailures = heap.failures;
    s.pageTablePages = Vmm::tablePages();
    s.promisedBytes = Pmm::stats().promisedPages * Mem::PAGE_SIZE;
    for (Core::SharedMemory* o = Core::SharedMemory::allPaged(); o; o = o->nextPaged)
        s.fileBytes += o->residentPages * Mem::PAGE_SIZE;
    toUser(c.arg0(), &s, sizeof(s));
    return c.result(Abi::OK);
}

Arch::Frame* sysRandom(Call const& c) {
    u64 address = c.arg0(), length = c.arg1();
    if (length > 256)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(address, length, true))
        return c.result(Abi::BAD_ADDRESS);
    u8 bytes[256];
    if (not Random::fill(bytes, length))
        return c.result(Abi::IO_ERROR); // the generator failed its health tests
    toUser(address, bytes, length);
    memset(bytes, 0, sizeof(bytes)); // no copy stays behind on the kernel stack
    asm volatile("" : : "r"(bytes) : "memory");
    return c.result(Abi::OK);
}

// A data file from the boot image, shared read-only by everyone who opens it.
Arch::Frame* sysFileOpen(Call const& c) {
    char name[32];
    u64 length = c.arg1();
    if (length == 0 or length >= sizeof(name))
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(c.arg0(), length))
        return c.result(Abi::BAD_ADDRESS);
    fromUser(name, c.arg0(), length);
    name[length] = '\0';
    Core::SharedMemory* memory = Programs::file(name);
    if (not memory)
        return c.result(Abi::NOT_FOUND);
    memory->ref();
    u64 handle = c.task->addHandle({memory, FILE_RIGHTS, memory->epoch});
    if (not handle) {
        memory->unref();
        return c.result(Abi::NO_SPACE);
    }
    return c.result(static_cast<i64>(handle));
}

// MARK: Handles and channels

Arch::Frame* sysHandleClose(Call const& c) {
    Object* object = c.task->takeHandle(c.arg0()).object;
    if (not object)
        return c.result(Abi::BAD_HANDLE);
    // The endpoint may live on (other handles): it must not keep naming this task.
    if (object->type == ObjectType::Channel and static_cast<Core::Endpoint*>(object)->waiter == c.task)
        static_cast<Core::Endpoint*>(object)->waiter = nullptr;
    object->unref();
    return c.result(Abi::OK);
}

Arch::Frame* sysHandleDuplicate(Call const& c) {
    i64 error = 0;
    Core::Capability* cap = c.capability(c.arg0(), Abi::RIGHT_DUPLICATE, error);
    if (not cap)
        return c.result(error);
    Core::Capability copy{cap->object, cap->rights & static_cast<u32>(c.arg1()), cap->epoch};
    copy.object->ref();
    u64 handle = c.task->addHandle(copy);
    if (not handle) {
        copy.object->unref();
        return c.result(Abi::NO_SPACE);
    }
    return c.result(static_cast<i64>(handle));
}

Arch::Frame* sysHandleRestrict(Call const& c) {
    i64 error = 0;
    Core::Capability* cap = c.capability(c.arg0(), 0, error);
    if (not cap)
        return c.result(error);
    cap->rights &= static_cast<u32>(c.arg1());
    return c.result(Abi::OK);
}

Arch::Frame* sysHandleRights(Call const& c) {
    i64 error = 0;
    Core::Capability* cap = c.capability(c.arg0(), 0, error);
    if (not cap)
        return c.result(error);
    return c.result(cap->rights);
}

// Cuts off every other handle to the object: their epoch no longer matches.
// Then removes what they already got out of it: other programs' mappings of
// revoked memory, and tasks blocked on it are woken (to see REVOKED).
Arch::Frame* sysHandleRevoke(Call const& c) {
    i64 error = 0;
    Core::Capability* cap = c.capability(c.arg0(), Abi::RIGHT_REVOKE, error);
    if (not cap)
        return c.result(error);
    Object* object = cap->object;
    object->epoch++;
    cap->epoch = object->epoch;

    switch (object->type) {
    case ObjectType::Channel:
        static_cast<Core::Endpoint*>(object)->wakeWaiter();
        break;
    case ObjectType::Irq:
        if (Task* waiter = static_cast<Core::Irq*>(object)->waiter) {
            static_cast<Core::Irq*>(object)->waiter = nullptr;
            Sched::wake(waiter);
        }
        break;
    case ObjectType::Memory:
        Vm::revoke(static_cast<Core::SharedMemory*>(object), c.task);
        break;
    case ObjectType::IoPorts:
    case ObjectType::PciDevice:
    case ObjectType::Firmware:
        break;
    }
    return c.result(Abi::OK);
}

Arch::Frame* sysChannelCreate(Call const& c) {
    u64 address = c.arg0();
    if (not c.userMemory(address, 2 * sizeof(Abi::Handle), true))
        return c.result(Abi::BAD_ADDRESS);
    // Two endpoints, each a little over one page of kernel heap.
    if (not Pmm::userCanUse(2 * (sizeof(Core::Endpoint) / Mem::PAGE_SIZE + 1)))
        return c.result(Abi::OUT_OF_MEMORY);
    if (not c.task->quota->chargeObjects(2))
        return c.result(Abi::OUT_OF_MEMORY);

    Core::Endpoint *a, *b;
    Core::Endpoint::createPair(a, b);
    a->chargeTo(c.task->quota, 0);
    b->chargeTo(c.task->quota, 0);
    u64 ha = c.task->addHandle({a, CHANNEL_RIGHTS, 0});
    u64 hb = ha ? c.task->addHandle({b, CHANNEL_RIGHTS, 0}) : 0;
    if (not hb) {
        if (ha)
            c.task->takeHandle(ha);
        a->unref();
        b->unref();
        return c.result(Abi::NO_SPACE);
    }

    Abi::Handle out[2] = {ha, hb};
    toUser(address, out, sizeof(out));
    return c.result(Abi::OK);
}

Arch::Frame* sysChannelSend(Call const& c) {
    i64 error = 0;
    auto* endpoint = c.lookup<Core::Endpoint>(c.arg0(), ObjectType::Channel, Abi::RIGHT_WRITE, error);
    if (not endpoint)
        return c.result(error);

    u64 address = c.arg1();
    u64 length = c.arg2();
    u64 attach = c.arg3();

    if (length > Abi::MAX_MESSAGE_SIZE)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(address, length))
        return c.result(Abi::BAD_ADDRESS);
    if (attach == c.arg0())
        return c.result(Abi::BAD_HANDLE);
    // The attached handle travels with its rights, so it must be live and
    // allowed to move.
    if (attach != Abi::NO_HANDLE and not c.capability(attach, Abi::RIGHT_TRANSFER, error))
        return c.result(error);

    Core::Endpoint* peer = endpoint->peer;
    if (not peer)
        return c.result(Abi::PEER_CLOSED);
    if (peer->full())
        return c.result(Abi::QUEUE_FULL);

    // Objects in a queue hold references, so a cycle of them (an endpoint in
    // its own queue, two endpoints in each other's) could never be freed.
    // Refuse every way to start one: sending the receiving endpoint into its
    // own queue, an endpoint that already holds channels or IRQs in its
    // queue, or an IRQ bound to a channel.
    if (Object* object = attach != Abi::NO_HANDLE ? c.task->handle(attach)->object : nullptr) {
        if (object == peer)
            return c.result(Abi::INVALID_ARGUMENT);
        if (object->type == ObjectType::Channel and static_cast<Core::Endpoint*>(object)->holdsLinks())
            return c.result(Abi::INVALID_ARGUMENT);
        if (object->type == ObjectType::Irq and static_cast<Core::Irq*>(object)->bound)
            return c.result(Abi::INVALID_ARGUMENT);
    }

    Core::Message message;
    fromUser(message.data, address, length);
    message.size = static_cast<u32>(length);
    message.attached = attach != Abi::NO_HANDLE ? c.task->takeHandle(attach) : Core::Capability{};
    peer->push(message);
    return c.result(Abi::OK);
}

Arch::Frame* sysChannelRecv(Call const& c) {
    i64 error = 0;
    auto* endpoint = c.lookup<Core::Endpoint>(c.arg0(), ObjectType::Channel, Abi::RIGHT_READ, error);
    if (not endpoint)
        return c.result(error);

    u64 buffer = c.arg1();
    u64 capacity = c.arg2();
    u64 handleOut = c.arg3();
    u64 flags = c.arg4();

    if (endpoint->empty()) {
        if (not endpoint->peer)
            return c.result(Abi::PEER_CLOSED);
        if (flags & Abi::RECV_NONBLOCK)
            return c.result(Abi::WOULD_BLOCK);
        if (endpoint->waiter and endpoint->waiter != c.task)
            return c.result(Abi::INVALID_ARGUMENT); // one receiver at a time
        endpoint->waiter = c.task;
        return c.blockAndRetry();
    }

    Core::Message& message = endpoint->front();
    if (message.size > capacity)
        return c.result(Abi::BUFFER_TOO_SMALL);
    if (not c.userMemory(buffer, message.size, true))
        return c.result(Abi::BAD_ADDRESS);
    if (handleOut and not c.userMemory(handleOut, sizeof(Abi::Handle), true))
        return c.result(Abi::BAD_ADDRESS);

    // Install an attached handle first: if the table is full, the message
    // stays queued and nothing is lost.
    // A handle revoked on the way is dropped, like one the receiver didn't
    // ask for.
    u64 received = Abi::NO_HANDLE;
    Core::Capability& attached = message.attached;
    bool refused = attached.object and c.task->privilege == Core::Privilege::App and isHardware(attached.object);
    if (attached.object and handleOut and not attached.revoked() and not refused) {
        received = c.task->addHandle(attached);
        if (not received)
            return c.result(Abi::NO_SPACE);
    } else if (attached.object) {
        attached.object->unref();
    }

    toUser(buffer, message.data, message.size);
    if (handleOut)
        toUser(handleOut, &received, sizeof(received));

    i64 size = message.size;
    endpoint->pop();
    return c.result(size);
}

// Waits for any of several endpoints. Like recv, a wait that blocks runs
// again from the start when woken; task->waitDeadline remembers the
// deadline across those runs (and is cleared whenever the call returns).
Arch::Frame* sysWait(Call const& c) {
    u64 address = c.arg0();
    u64 count = c.arg1();
    u64 timeout = c.arg2();
    Task* task = c.task;

    auto finish = [&](i64 result, Core::Endpoint* const* endpoints, u64 n) {
        for (u64 i = 0; i < n; i++) {
            if (endpoints[i]->waiter == task)
                endpoints[i]->waiter = nullptr;
        }
        task->waitDeadline = 0;
        return c.result(result);
    };

    if (count == 0 or count > Abi::MAX_WAIT)
        return finish(Abi::INVALID_ARGUMENT, nullptr, 0);
    if (not c.userMemory(address, count * sizeof(Abi::Handle)))
        return finish(Abi::BAD_ADDRESS, nullptr, 0);

    Abi::Handle handles[Abi::MAX_WAIT];
    fromUser(handles, address, count * sizeof(Abi::Handle));
    if (timeout != Abi::WAIT_FOREVER and timeout > MAX_TIMEOUT_MS)
        timeout = MAX_TIMEOUT_MS;

    Core::Endpoint* endpoints[Abi::MAX_WAIT];
    for (u64 i = 0; i < count; i++) {
        i64 error = 0;
        endpoints[i] = c.lookup<Core::Endpoint>(handles[i], ObjectType::Channel, Abi::RIGHT_READ, error);
        if (not endpoints[i]) {
            // A handle revoked while this task waited: endpoints after it
            // may still name the task as their waiter.
            forgetWaits(task);
            return finish(error, endpoints, i);
        }
        if (endpoints[i]->waiter and endpoints[i]->waiter != task)
            return finish(Abi::INVALID_ARGUMENT, endpoints, i); // one waiter per endpoint
    }

    for (u64 i = 0; i < count; i++) {
        if (not endpoints[i]->empty() or not endpoints[i]->peer)
            return finish(static_cast<i64>(i), endpoints, count);
    }

    u64 now = Time::now();
    if (timeout == 0 or (task->waitDeadline and now >= task->waitDeadline))
        return finish(Abi::TIMED_OUT, endpoints, count);

    for (u64 i = 0; i < count; i++)
        endpoints[i]->waiter = task;

    c.frame->rip -= INT80_LENGTH; // run the call again when woken
    if (timeout == Abi::WAIT_FOREVER)
        return Sched::blockCurrent(c.frame);
    if (not task->waitDeadline)
        task->waitDeadline = now + timeout;
    return Sched::blockCurrentUntil(c.frame, task->waitDeadline);
}

// MARK: Memory

// Any region: shared memory, private memory, a mapped file.
Arch::Frame* sysMemoryUnmap(Call const& c) {
    return c.result(Vm::unmap(*c.task, c.arg0()));
}

Arch::Frame* sysMemoryCreate(Call const& c) {
    if (c.arg0() == 0 or c.arg0() > Core::SharedMemory::MAX_SIZE or (c.arg1() & ~Abi::MEMORY_BELOW_4G))
        return c.result(Abi::INVALID_ARGUMENT);
    u64 pages = Mem::alignUp(c.arg0(), Mem::PAGE_SIZE) / Mem::PAGE_SIZE;
    Core::Quota& quota = *c.task->quota;
    if (not quota.chargeObjects(1))
        return c.result(Abi::OUT_OF_MEMORY);
    if (not quota.charge(pages)) {
        quota.refundObjects(1);
        return c.result(Abi::OUT_OF_MEMORY);
    }
    auto* memory = Core::SharedMemory::allocate(c.arg0(), (c.arg1() & Abi::MEMORY_BELOW_4G) ? Pmm::BELOW_4G : 0);
    if (not memory) {
        quota.refund(pages);
        quota.refundObjects(1);
        return c.result(Abi::OUT_OF_MEMORY);
    }
    memory->chargeTo(&quota, pages);

    u64 handle = c.task->addHandle({memory, MEMORY_RIGHTS, 0});
    if (not handle) {
        memory->unref();
        return c.result(Abi::NO_SPACE);
    }
    return c.result(static_cast<i64>(handle));
}

// (Handle memory, u64 flags): shared, or with MAP_COPY a private
// copy-on-write view; MAP_READ_ONLY maps it read-only even with RIGHT_WRITE.
Arch::Frame* sysMemoryMap(Call const& c) {
    i64 error = 0;
    auto* memory = c.lookup<Core::SharedMemory>(c.arg0(), ObjectType::Memory, Abi::RIGHT_READ, error);
    if (not memory)
        return c.result(error);
    u64 flags = c.arg1();
    if (flags & ~(Abi::MAP_COPY | Abi::MAP_READ_ONLY))
        return c.result(Abi::INVALID_ARGUMENT);
    bool copy = flags & Abi::MAP_COPY;
    if (copy and memory->hardware)
        return c.result(Abi::INVALID_ARGUMENT); // (a device's registers have no "copy")
    // A shared mapping writes the object: only with RIGHT_WRITE, and never a
    // read-only or sealed object. A copy writes only its own pages.
    bool writable = not(flags & Abi::MAP_READ_ONLY) and
                    (copy or (not memory->readOnly and not memory->sealed and
                              (c.task->handle(c.arg0())->rights & Abi::RIGHT_WRITE)));
    u64 address = 0;
    i64 result = Vm::mapObject(*c.task, memory, copy ? Vm::Kind::Copy : Vm::Kind::Shared, 0, memory->size,
                               memory->size, writable, false, 0, address);
    if (result != Abi::OK)
        return c.result(result);
    if (memory->isScreen)
        Display::handOverToUserspace();
    return c.result(static_cast<i64>(address));
}

// Private memory: zero-filled pages owned by the task, allocated as they're
// first touched (promised now, so a touch never runs out). Freed with
// memory_unmap or when the task ends.
Arch::Frame* sysMemoryAlloc(Call const& c) {
    constexpr u64 MAX_ALLOC = 256 * 1024 * 1024;
    u64 size = Mem::alignUp(c.arg0(), Mem::PAGE_SIZE);
    if (size == 0 or size > MAX_ALLOC)
        return c.result(Abi::INVALID_ARGUMENT);
    // Page tables for it, which aren't promised: from the reserve's margin.
    u64 pages = size / Mem::PAGE_SIZE;
    if (not Pmm::userCanUse(pages / 512 + 3))
        return c.result(Abi::OUT_OF_MEMORY);
    u64 address = 0;
    i64 result = Vm::mapAnonymous(*c.task, size, true, 0, address);
    return c.result(result == Abi::OK ? static_cast<i64>(address) : result);
}

// (address, u64 writable): a region becomes read-only (or writable again).
Arch::Frame* sysMemoryProtect(Call const& c) {
    if (c.arg1() > 1)
        return c.result(Abi::INVALID_ARGUMENT);
    return c.result(Vm::protect(*c.task, c.arg0(), c.arg1()));
}

// Seals a memory object: its contents never change again, for anyone.
// Writable shared mappings (everywhere) become read-only. Who receives a
// sealed object can check its contents once and trust them (MEMORY_SEALED).
// Needs RIGHT_WRITE (it's a change to the object) and RIGHT_REVOKE (it takes
// writing away from everyone else).
Arch::Frame* sysMemorySeal(Call const& c) {
    i64 error = 0;
    auto* memory = c.lookup<Core::SharedMemory>(c.arg0(), ObjectType::Memory, Abi::RIGHT_WRITE | Abi::RIGHT_REVOKE,
                                                error);
    if (not memory)
        return c.result(error);
    if (memory->hardware or memory->dmaMapped or memory->paged())
        return c.result(Abi::INVALID_ARGUMENT); // (a device could still write it)
    Vm::seal(memory);
    memory->readOnly = true;
    return c.result(Abi::OK);
}

// (Handle memory, MemoryInfo* out): its size and what it is.
Arch::Frame* sysMemoryInfo(Call const& c) {
    i64 error = 0;
    auto* memory = c.lookup<Core::SharedMemory>(c.arg0(), ObjectType::Memory, Abi::RIGHT_READ, error);
    if (not memory)
        return c.result(error);
    if (not c.userMemory(c.arg1(), sizeof(Abi::MemoryInfo), true))
        return c.result(Abi::BAD_ADDRESS);
    Abi::MemoryInfo info{};
    info.size = memory->size;
    info.flags = (memory->sealed ? Abi::MEMORY_SEALED : 0) | (memory->readOnly ? Abi::MEMORY_READ_ONLY : 0) |
                 (memory->paged() ? Abi::MEMORY_PAGED : 0);
    toUser(c.arg1(), &info, sizeof(info));
    return c.result(Abi::OK);
}

// (u64 size, Handle pager): a paged object. `pager` is one end of a channel
// (it moves to the kernel); page requests arrive at its peer, and the pager
// answers each with memory_supply.
Arch::Frame* sysMemoryCreatePaged(Call const& c) {
    i64 error = 0;
    if (c.arg0() == 0 or c.arg0() > Core::SharedMemory::MAX_SIZE)
        return c.result(Abi::INVALID_ARGUMENT);
    auto* end = c.lookup<Core::Endpoint>(c.arg1(), ObjectType::Channel, Abi::RIGHT_WRITE, error);
    if (not end)
        return c.result(error);
    if (end->pagerOf or not end->peer or end->waiter)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not Pmm::userCanUse(c.arg0() / Mem::PAGE_SIZE / 512 + 1) or not c.task->quota->chargeObjects(1))
        return c.result(Abi::OUT_OF_MEMORY);
    auto* memory = Core::SharedMemory::createPaged(c.arg0(), end);
    if (not memory) {
        c.task->quota->refundObjects(1);
        return c.result(Abi::OUT_OF_MEMORY);
    }
    memory->chargeTo(c.task->quota, 0);
    u64 handle = c.task->addHandle({memory, MEMORY_RIGHTS & ~Abi::RIGHT_WRITE, 0});
    if (not handle) {
        memory->unref();
        return c.result(Abi::NO_SPACE);
    }
    c.task->takeHandle(c.arg1()).object->unref(); // the kernel's reference (createPaged's) keeps it
    return c.result(static_cast<i64>(handle));
}

// (Handle pager end, u64 offset, void const* data, u64 length): the pager
// answers a request, a page at a time; pages already there are left as
// they are. Called on the pager's own end of the channel.
Arch::Frame* sysMemorySupply(Call const& c) {
    i64 error = 0;
    auto* end = c.lookup<Core::Endpoint>(c.arg0(), ObjectType::Channel, Abi::RIGHT_READ, error);
    if (not end)
        return c.result(error);
    Core::SharedMemory* memory = end->peer ? end->peer->pagerOf : nullptr;
    u64 offset = c.arg1(), length = c.arg3();
    if (not memory or offset % Mem::PAGE_SIZE or length % Mem::PAGE_SIZE or length == 0 or offset > memory->size or
        length > memory->size - offset)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not c.userMemory(c.arg2(), length))
        return c.result(Abi::BAD_ADDRESS);
    for (u64 at = 0; at < length; at += Mem::PAGE_SIZE) {
        u64 index = (offset + at) / Mem::PAGE_SIZE;
        if (memory->pageAt(index))
            continue;
        // A file's pages are a cache: when memory is short they come out of
        // other files first (reclaim), then this one gives up.
        if (not Pmm::userCanUse(1))
            return c.result(Abi::OUT_OF_MEMORY);
        u64 page = Pmm::alloc();
        if (not page)
            return c.result(Abi::OUT_OF_MEMORY);
        fromUser(Mem::toVirtual(page), c.arg2() + at, Mem::PAGE_SIZE);
        Vm::supplied(memory, index, page);
    }
    return c.result(Abi::OK);
}

// MARK: Devices

Arch::Frame* sysIrqWait(Call const& c) {
    i64 error = 0;
    auto* irq = c.lookup<Core::Irq>(c.arg0(), ObjectType::Irq, Abi::RIGHT_READ, error);
    if (not irq)
        return c.result(error);

    if (irq->pending) {
        irq->pending = false; // the line stays masked until the next wait
        return c.result(Abi::OK);
    }

    // The driver has finished with the last interrupt: let the next one in.
    irq->waiter = c.task;
    irq->unmask();
    return c.blockAndRetry();
}

Arch::Frame* sysIrqBind(Call const& c) {
    i64 error = 0;
    auto* irq = c.lookup<Core::Irq>(c.arg0(), ObjectType::Irq, Abi::RIGHT_READ, error);
    if (not irq)
        return c.result(error);
    auto* endpoint = c.lookup<Core::Endpoint>(c.arg1(), ObjectType::Channel, Abi::RIGHT_WRITE, error);
    if (not endpoint)
        return c.result(error);

    irq->bind(endpoint, c.arg2());
    return c.result(Abi::OK);
}

Arch::Frame* sysIrqAck(Call const& c) {
    i64 error = 0;
    auto* irq = c.lookup<Core::Irq>(c.arg0(), ObjectType::Irq, Abi::RIGHT_READ, error);
    if (not irq)
        return c.result(error);
    irq->acknowledge();
    return c.result(Abi::OK);
}

Arch::Frame* sysPortIn(Call const& c) {
    i64 error = 0;
    auto* ports = c.lookup<Core::IoPorts>(c.arg0(), ObjectType::IoPorts, Abi::RIGHT_READ, error);
    if (not ports)
        return c.result(error);

    u64 port = c.arg1();
    if (port > 0xFFFF or not ports->contains(static_cast<u16>(port)))
        return c.result(Abi::INVALID_ARGUMENT);
    return c.result(Arch::inb(static_cast<u16>(port)));
}

Arch::Frame* sysPortOut(Call const& c) {
    i64 error = 0;
    auto* ports = c.lookup<Core::IoPorts>(c.arg0(), ObjectType::IoPorts, Abi::RIGHT_WRITE, error);
    if (not ports)
        return c.result(error);

    u64 port = c.arg1();
    if (port > 0xFFFF or not ports->contains(static_cast<u16>(port)) or c.arg2() > 0xFF)
        return c.result(Abi::INVALID_ARGUMENT);
    Arch::outb(static_cast<u16>(port), static_cast<u8>(c.arg2()));
    return c.result(Abi::OK);
}

Arch::Frame* sysDeviceInfo(Call const& c) {
    i64 error = 0;
    auto* device = c.lookup<Core::PciDevice>(c.arg0(), ObjectType::PciDevice, Abi::RIGHT_READ, error);
    if (not device)
        return c.result(error);
    if (not c.userMemory(c.arg1(), sizeof(Abi::DeviceInfo), true))
        return c.result(Abi::BAD_ADDRESS);

    Abi::DeviceInfo info{};
    info.vendor = device->vendor;
    info.device = device->device;
    info.classCode = device->classCode;
    info.subclass = device->subclass;
    info.progIf = device->progIf;
    info.irqLine = device->irqLine;
    for (int i = 0; i < 6; i++)
        info.barSize[i] = device->bars[i].io ? 0 : device->bars[i].size;
    toUser(c.arg1(), &info, sizeof(info));
    return c.result(Abi::OK);
}

Arch::Frame* sysDeviceBar(Call const& c) {
    i64 error = 0;
    auto* device = c.lookup<Core::PciDevice>(c.arg0(), ObjectType::PciDevice, Abi::RIGHT_MMIO, error);
    if (not device)
        return c.result(error);
    u64 index = c.arg1();
    if (index > 5 or device->bars[index].io or not device->bars[index].size or
        device->bars[index].size > Core::SharedMemory::MAX_SIZE)
        return c.result(Abi::INVALID_ARGUMENT);

    auto const& bar = device->bars[index];
    auto* memory = Core::SharedMemory::device(bar.address, bar.size, Vmm::Cache::Uncached);
    u64 handle = c.task->addHandle({memory, REGISTER_RIGHTS, 0});
    if (not handle) {
        memory->unref();
        return c.result(Abi::NO_SPACE);
    }
    device->enable();
    return c.result(static_cast<i64>(handle));
}

// The device's message-signalled interrupt, as an IRQ handle. Programming
// it is the kernel's job (vector, destination, remapping entry); the driver
// only gets the handle. Needs RIGHT_MMIO: it's control of the device.
Arch::Frame* sysDeviceMsi(Call const& c) {
    i64 error = 0;
    auto* device = c.lookup<Core::PciDevice>(c.arg0(), ObjectType::PciDevice, Abi::RIGHT_MMIO, error);
    if (not device)
        return c.result(error);
    auto* irq = Core::Irq::forDevice(device->address, error);
    if (not irq)
        return c.result(error);
    u64 handle = c.task->addHandle({irq, Abi::RIGHT_READ, 0});
    if (not handle) {
        irq->unref();
        return c.result(Abi::NO_SPACE);
    }
    log("[pci]  ", device->address.bus, ":", device->address.device, ".", device->address.function, " interrupts by ",
        irq->msi.msix ? "MSI-X" : "MSI", " (vector ", Arch::Pic::IRQ_BASE + irq->line,
        Arch::Iommu::remapsInterrupts() ? ", through its own VT-d remapping entry)" : ")");
    return c.result(static_cast<i64>(handle));
}

// Port I/O of 1, 2 or 4 bytes (ACPI registers are often 16 or 32 bits wide).
Arch::Frame* sysPortWide(Call const& c, bool write) {
    i64 error = 0;
    auto* ports = c.lookup<Core::IoPorts>(c.arg0(), ObjectType::IoPorts, write ? Abi::RIGHT_WRITE : Abi::RIGHT_READ,
                                          error);
    if (not ports)
        return c.result(error);
    u64 port = c.arg1(), width = c.arg2();
    if (port > 0xFFFF or (width != 1 and width != 2 and width != 4) or port + width - 1 > 0xFFFF)
        return c.result(Abi::INVALID_ARGUMENT);
    for (u64 p = port; p < port + width; p++) {
        if (not ports->contains(static_cast<u16>(p)))
            return c.result(Abi::INVALID_ARGUMENT);
    }
    auto at = static_cast<u16>(port);
    if (not write) {
        if (width == 1)
            return c.result(Arch::inb(at));
        if (width == 2)
            return c.result(Arch::inw(at));
        u32 value;
        asm volatile("inl %1, %0" : "=a"(value) : "Nd"(at));
        return c.result(value);
    }
    u64 value = c.arg3();
    if (width == 1)
        Arch::outb(at, static_cast<u8>(value));
    else if (width == 2)
        Arch::outw(at, static_cast<u16>(value));
    else
        asm volatile("outl %0, %1" : : "a"(static_cast<u32>(value)), "Nd"(at));
    return c.result(Abi::OK);
}

// Physical memory for firmware code: never RAM the kernel hands out, the
// kernel and its modules, the loader's memory or the screen.
Arch::Frame* sysFirmwareMemory(Call const& c, Boot::Info const& boot) {
    i64 error = 0;
    if (not c.lookup<Core::Firmware>(c.arg0(), ObjectType::Firmware, Abi::RIGHT_READ, error))
        return c.result(error);
    u64 physical = c.arg1(), size = c.arg2();
    if (size == 0 or size > Core::SharedMemory::MAX_SIZE or physical + size < physical or physical + size > (1ull << 52))
        return c.result(Abi::INVALID_ARGUMENT);
    u64 start = Mem::alignDown(physical, Mem::PAGE_SIZE), end = Mem::alignUp(physical + size, Mem::PAGE_SIZE);
    bool tables = false;
    for (usize i = 0; i < boot.regionCount; i++) {
        auto const& r = boot.regions[i];
        if (r.base >= end or r.base + r.length <= start)
            continue;
        if (r.type == Boot::RegionType::AcpiReclaimable or r.type == Boot::RegionType::AcpiNvs)
            tables = true;
        else if (r.type != Boot::RegionType::Reserved and r.type != Boot::RegionType::ReservedMapped and
                 r.type != Boot::RegionType::EfiRuntime and
                 r.type != Boot::RegionType::EfiRuntimeMmio) // (both were "reserved" before Shool v4: AML may use them)
            return c.result(Abi::ACCESS_DENIED); // RAM, kernel, loader or screen memory
    }
    auto* memory = Core::SharedMemory::device(start, end - start,
                                              tables ? Vmm::Cache::WriteBack : Vmm::Cache::Uncached);
    u64 handle = c.task->addHandle({memory, Abi::RIGHT_READ | Abi::RIGHT_WRITE, 0});
    if (not handle) {
        memory->unref();
        return c.result(Abi::NO_SPACE);
    }
    return c.result(static_cast<i64>(handle));
}

// PCI configuration space for firmware code (segment 0).
Arch::Frame* sysFirmwarePci(Call const& c) {
    bool write = c.arg2() & Abi::PCI_WRITE;
    i64 error = 0;
    if (not c.lookup<Core::Firmware>(c.arg0(), ObjectType::Firmware, write ? Abi::RIGHT_WRITE : Abi::RIGHT_READ, error))
        return c.result(error);
    u64 address = c.arg1(), width = c.arg2() & 0xFF;
    u8 offset = static_cast<u8>(address);
    if (address >> 24 or (width != 1 and width != 2 and width != 4) or offset % width)
        return c.result(Abi::INVALID_ARGUMENT);
    Arch::Pci::Address a{static_cast<u8>(address >> 16), static_cast<u8>((address >> 11) & 31),
                         static_cast<u8>((address >> 8) & 7)};
    u8 aligned = offset & 0xFC;
    u32 dword = Arch::Pci::read32(a, aligned);
    u32 shift = 8 * (offset & 3), mask = width == 4 ? ~0u : ((1u << (8 * width)) - 1) << shift;
    if (not write)
        return c.result((dword & mask) >> shift);
    // shortcut: 1- and 2-byte writes are read-modify-write of the dword, which a
    // write-1-to-clear register beside them would feel; AML rarely does that.
    dword = (dword & ~mask) | ((static_cast<u32>(c.arg3()) << shift) & mask);
    Arch::Pci::write32(a, aligned, dword);
    return c.result(Abi::OK);
}

// The acpi server's interrupt routing: PCI routes, then the switch to the APICs.
Arch::Frame* sysFirmwareInterrupts(Call const& c) {
    i64 error = 0;
    if (not c.lookup<Core::Firmware>(c.arg0(), ObjectType::Firmware, Abi::RIGHT_WRITE, error))
        return c.result(error);
    if (c.arg1() == Abi::INTERRUPTS_ROUTE) {
        Arch::Apic::Route route{static_cast<u32>(c.arg2()), static_cast<u8>(c.arg3() & 0xFF),
                                bool(c.arg3() & (1 << 8)), bool(c.arg3() & (1 << 9))};
        if (c.arg2() > 0xFFFF or (c.arg3() & 0xFF) > 0xFF or not Arch::Apic::addRoute(route))
            return c.result(Abi::INVALID_ARGUMENT);
        return c.result(Abi::OK);
    }
    if (c.arg1() == Abi::INTERRUPTS_APIC)
        return c.result(Arch::Apic::enable() ? Abi::OK : Abi::IO_ERROR);
    return c.result(Abi::INVALID_ARGUMENT);
}

// The acpi server's passive cooling: a cap on the CPU's performance.
Arch::Frame* sysFirmwarePerformance(Call const& c) {
    i64 error = 0;
    if (not c.lookup<Core::Firmware>(c.arg0(), ObjectType::Firmware, Abi::RIGHT_WRITE, error))
        return c.result(error);
    if (c.arg1() < 1 or c.arg1() > 100)
        return c.result(Abi::INVALID_ARGUMENT);
    if (not Arch::Cpu::setPerformanceLimit(static_cast<u32>(c.arg1())))
        return c.result(Abi::NOT_FOUND);
    if (c.arg1() == 100)
        log("[cpu]  thermal: performance cap lifted");
    else
        log("[cpu]  thermal: performance capped at ", c.arg1(), "%");
    return c.result(Abi::OK);
}

// Turns the machine off or restarts it (ACPI). Not for apps.
Arch::Frame* sysPower(Call const& c) {
    if (c.task->privilege == Core::Privilege::App)
        return c.result(Abi::ACCESS_DENIED);
    if (c.arg0() == Abi::POWER_RESTART)
        Arch::Acpi::reboot();
    if (c.arg0() != Abi::POWER_OFF)
        return c.result(Abi::INVALID_ARGUMENT);
    Arch::Acpi::powerOff();
    return c.result(Abi::IO_ERROR); // (still running: it couldn't)
}

Arch::Frame* sysBootComplete(Call const& c) {
    if (c.task->privilege == Core::Privilege::App)
        return c.result(Abi::ACCESS_DENIED);
    static i64 outcome = 1; // (once per boot: later calls get the same answer)
    if (outcome == 1) {
        char const* why = nullptr;
        if (not Arch::Efi::available()) {
            log("[boot] the system is up (no boot-attempt counter on this boot: no UEFI runtime services)");
            outcome = Abi::NOT_FOUND;
        } else if (Arch::Efi::clearBootCount(why)) {
            log("[boot] the system is up: boot-attempt counter cleared");
            outcome = Abi::OK;
        } else {
            log("[boot] the system is up, but the boot-attempt counter stays: ", why);
            outcome = Abi::IO_ERROR;
        }
    }
    return c.result(outcome);
}

Arch::Frame* sysDmaAddress(Call const& c) {
    i64 error = 0;
    auto* device = c.lookup<Core::PciDevice>(c.arg0(), ObjectType::PciDevice, Abi::RIGHT_DMA, error);
    if (not device)
        return c.result(error);
    // The device will write it: the driver must be allowed to write it too.
    auto* memory = c.lookup<Core::SharedMemory>(c.arg1(), ObjectType::Memory, Abi::RIGHT_WRITE, error);
    if (not memory)
        return c.result(error);
    if (not memory->owned)
        return c.result(Abi::INVALID_ARGUMENT); // device memory, not RAM
    // With VT-d, the device gets exactly this memory and nothing else.
    // (FAULT_TEST=dma skips this, so the IOMMU must block the driver's DMA.)
    if (Arch::Iommu::enabled() and not RUDRACORE_FAULT_TEST_DMA) {
        if (not Arch::Iommu::allow(device->address, memory->physical, memory->size))
            return c.result(Abi::OUT_OF_MEMORY);
        memory->dmaMapped = true;
    }
    return c.result(static_cast<i64>(memory->physical));
}

Boot::Info const* bootInfo = nullptr;

} // namespace

void init(Boot::Info const& info) {
    bootInfo = &info;
}

namespace {

Arch::Frame* run(Call const& c);

} // namespace

Arch::Frame* dispatch(Arch::Frame* frame) {
    Call c{frame, Sched::current()};
    if (not c.task->isUser())
        return c.result(Abi::UNKNOWN_SYSCALL); // kernel tasks use Sched directly
    u64 number = frame->rax;
    Arch::Frame* next = run(c);
    if (c.wait == Call::Wait::None)
        return next;

    // A buffer the call needed wasn't there yet: the call runs again, from
    // the start, once it can be (its result so far is dropped).
    auto again = [&] {
        frame->rax = number;
        frame->rip -= INT80_LENGTH;
    };
    switch (c.wait) {
    case Call::Wait::Pager:
        again();
        return Sched::blockCurrent(frame);
    case Call::Wait::Moment:
        again();
        return Sched::sleepCurrent(frame, 1);
    case Call::Wait::OutOfMemory:
        if (Task* victim = Vm::outOfMemory(c.task)) {
            if (victim == c.task)
                return Sched::exitCurrent(frame, -1);
            again(); // another app's memory is free now
            return frame;
        }
        frame->rax = static_cast<u64>(Abi::OUT_OF_MEMORY);
        return frame;
    case Call::Wait::None:
        break;
    }
    return next;
}

namespace {

Arch::Frame* run(Call const& c) {
    Arch::Frame* frame = c.frame;
    switch (frame->rax) {
    case Abi::SYS_LOG: return sysLog(c);
    case Abi::SYS_EXIT: return Sched::exitCurrent(frame, static_cast<i64>(c.arg0()));
    case Abi::SYS_YIELD:
        c.result(Abi::OK);
        return Sched::switchFrom(frame);
    case Abi::SYS_SLEEP:
        c.result(Abi::OK);
        return Sched::sleepCurrent(frame, min(c.arg0(), MAX_TIMEOUT_MS));
    case Abi::SYS_TASK_ID: return c.result(static_cast<i64>(c.task->id));
    case Abi::SYS_TIME: return c.result(static_cast<i64>(Time::now()));
    case Abi::SYS_SPAWN: return sysSpawn(c);
    case Abi::SYS_SPAWN_IMAGE: return sysSpawnImage(c);
    case Abi::SYS_SYSTEM_INFO: return sysSystemInfo(c, *bootInfo);
    case Abi::SYS_RANDOM: return sysRandom(c);
    case Abi::SYS_FILE_OPEN: return sysFileOpen(c);

    case Abi::SYS_HANDLE_CLOSE: return sysHandleClose(c);
    case Abi::SYS_CHANNEL_CREATE: return sysChannelCreate(c);
    case Abi::SYS_CHANNEL_SEND: return sysChannelSend(c);
    case Abi::SYS_CHANNEL_RECV: return sysChannelRecv(c);
    case Abi::SYS_WAIT: return sysWait(c);
    case Abi::SYS_HANDLE_DUPLICATE: return sysHandleDuplicate(c);
    case Abi::SYS_HANDLE_RESTRICT: return sysHandleRestrict(c);
    case Abi::SYS_HANDLE_REVOKE: return sysHandleRevoke(c);
    case Abi::SYS_HANDLE_RIGHTS: return sysHandleRights(c);

    case Abi::SYS_MEMORY_CREATE: return sysMemoryCreate(c);
    case Abi::SYS_MEMORY_MAP: return sysMemoryMap(c);
    case Abi::SYS_MEMORY_ALLOC: return sysMemoryAlloc(c);
    case Abi::SYS_MEMORY_UNMAP: return sysMemoryUnmap(c);
    case Abi::SYS_MEMORY_PROTECT: return sysMemoryProtect(c);
    case Abi::SYS_MEMORY_SEAL: return sysMemorySeal(c);
    case Abi::SYS_MEMORY_INFO: return sysMemoryInfo(c);
    case Abi::SYS_MEMORY_CREATE_PAGED: return sysMemoryCreatePaged(c);
    case Abi::SYS_MEMORY_SUPPLY: return sysMemorySupply(c);

    case Abi::SYS_IRQ_WAIT: return sysIrqWait(c);
    case Abi::SYS_PORT_IN: return sysPortIn(c);
    case Abi::SYS_PORT_OUT: return sysPortOut(c);
    case Abi::SYS_IRQ_BIND: return sysIrqBind(c);
    case Abi::SYS_IRQ_ACK: return sysIrqAck(c);
    case Abi::SYS_DEVICE_INFO: return sysDeviceInfo(c);
    case Abi::SYS_DEVICE_BAR: return sysDeviceBar(c);
    case Abi::SYS_DMA_ADDRESS: return sysDmaAddress(c);
    case Abi::SYS_POWER: return sysPower(c);
    case Abi::SYS_FIRMWARE_MEMORY: return sysFirmwareMemory(c, *bootInfo);
    case Abi::SYS_FIRMWARE_PCI: return sysFirmwarePci(c);
    case Abi::SYS_PORT_IN_WIDE: return sysPortWide(c, false);
    case Abi::SYS_PORT_OUT_WIDE: return sysPortWide(c, true);
    case Abi::SYS_FIRMWARE_INTERRUPTS: return sysFirmwareInterrupts(c);
    case Abi::SYS_DEVICE_MSI: return sysDeviceMsi(c);
    case Abi::SYS_BOOT_COMPLETE: return sysBootComplete(c);
    case Abi::SYS_FIRMWARE_PERFORMANCE: return sysFirmwarePerformance(c);
    case Abi::SYS_TASK_LIST: return sysTaskList(c);
    case Abi::SYS_KERNEL_STATS: return sysKernelStats(c);

    default: return c.result(Abi::UNKNOWN_SYSCALL);
    }
}

} // namespace

} // namespace Rudracore::Syscall

#include "core/vm.h"

#include "core/channel.h"
#include "core/sched.h"
#include "core/shared_memory.h"
#include "log.h"
#include "mem/heap.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "rudracore/syscalls.h"

extern "C" void* memcpy(void* dest, void const* src, usize n);

namespace Rudracore::Vm {

using Core::Process;
using Core::SharedMemory;
using Core::Task;

namespace {

constexpr u64 PAGE = Mem::PAGE_SIZE;

Task* waiters = nullptr; // threads whose fault waits for a pager (linked by Task::pageWaitNext)

Region* find(Map& m, u64 address) {
    u32 lo = 0, hi = m.count;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        Region& r = m.regions[mid];
        if (address < r.start)
            hi = mid;
        else if (address >= r.end())
            lo = mid + 1;
        else
            return &r;
    }
    return nullptr;
}

bool overlaps(Map const& m, u64 start, u64 end) {
    for (u32 i = 0; i < m.count; i++) {
        if (m.regions[i].start < end and start < m.regions[i].end())
            return true;
    }
    return false;
}

// The first gap that fits `size` in [MAP_BASE, MAP_LIMIT), with an unmapped
// guard page after every region (so running off the end of one faults).
u64 findGap(Map const& m, u64 size) {
    u64 candidate = MAP_BASE;
    for (u32 i = 0; i < m.count; i++) {
        Region const& r = m.regions[i];
        if (r.end() + PAGE <= candidate)
            continue;
        if (r.start >= candidate + size + PAGE)
            break;
        candidate = r.end() + PAGE;
    }
    return candidate + size <= MAP_LIMIT and candidate + size > candidate ? candidate : 0;
}

i64 insert(Map& m, Region const& region) {
    if (m.count == m.capacity) {
        if (m.capacity >= MAX_REGIONS)
            return Abi::NO_SPACE;
        u32 capacity = m.capacity ? m.capacity * 2 : 16;
        auto* grown = static_cast<Region*>(Heap::alloc(capacity * sizeof(Region)));
        if (not grown)
            return Abi::OUT_OF_MEMORY;
        for (u32 i = 0; i < m.count; i++)
            grown[i] = m.regions[i];
        Heap::free(m.regions);
        m.regions = grown;
        m.capacity = capacity;
    }
    u32 at = m.count;
    while (at > 0 and m.regions[at - 1].start > region.start) {
        m.regions[at] = m.regions[at - 1];
        at--;
    }
    m.regions[at] = region;
    m.count++;
    return Abi::OK;
}

void removeAt(Map& m, u32 index) {
    for (u32 i = index; i + 1 < m.count; i++)
        m.regions[i] = m.regions[i + 1];
    m.count--;
}

bool commit(Process& t, u64 pages) {
    if (not pages)
        return true;
    if (not t.quota->charge(pages))
        return false;
    if (not Pmm::promise(pages)) {
        t.quota->refund(pages);
        return false;
    }
    return true;
}

// What a region gave back: promises it never used, and its quota.
void uncommit(Process& t, Region const& r) {
    Pmm::unpromise(r.committed - r.privatePages);
    if (t.quota)
        t.quota->refund(r.committed);
}

u32 access(Region const& r, bool privatePage) {
    u32 a = Vmm::USER;
    if (r.writable and (privatePage or r.kind == Kind::Shared))
        a |= Vmm::WRITE;
    if (r.executable)
        a |= Vmm::EXEC;
    if (privatePage)
        a |= Vmm::OWNED;
    return a;
}

// Maps a contiguous object's pages at once (device memory, buffers): no
// faults for them later.
bool mapEagerly(Process& t, Region const& r) {
    SharedMemory* o = r.object;
    if (not t.space->map(r.start, o->physical + r.offset, r.size, access(r, false), o->cache)) {
        t.space->unmap(r.start, r.size);
        return false;
    }
    return true;
}

// Takes the region's pages out of the address space, frees its own, and
// gives back what it held.
void tearDown(Process& t, Region& r) {
    if (r.kind == Kind::Shared) {
        t.space->unmap(r.start, r.size); // the object's pages: never the task's to free
    } else {
        for (u64 page = r.start; page < r.end(); page += PAGE) {
            u64 phys;
            bool owned;
            if (t.space->take(page, phys, owned) and owned)
                Pmm::free(phys);
        }
    }
    uncommit(t, r);
    if (r.object)
        r.object->unref();
}

} // namespace

void forgetWait(Task& t) {
    for (Task** link = &waiters; *link; link = &(*link)->pageWaitNext) {
        if (*link == &t) {
            *link = t.pageWaitNext;
            break;
        }
    }
    t.pageWaitObject = nullptr;
    t.pageWaitNext = nullptr;
}

namespace {

// A page a paged object doesn't have: asked of its pager (once), and the
// thread waits for it.
Fault request(Task& t, SharedMemory* o, u64 index) {
    Core::Endpoint* pagerEnd = o->pager ? o->pager->peer : nullptr;
    if (not pagerEnd)
        return Fault::Invalid; // its pager is gone: the page can never come
    if (o->pages[index] != SharedMemory::REQUESTED) {
        if (pagerEnd->full())
            return Fault::Retry;
        Core::Message m{};
        Abi::PageRequest pageRequest{index * PAGE, PAGE};
        memcpy(m.data, &pageRequest, sizeof(pageRequest));
        m.size = sizeof(pageRequest);
        pagerEnd->push(m);
        o->pages[index] = SharedMemory::REQUESTED;
    }
    forgetWait(t);
    t.pageWaitObject = o;
    t.pageWaitIndex = index;
    t.pageWaitNext = waiters;
    waiters = &t;
    return Fault::Pending;
}

// A fresh private page at `page`: zeros, or a copy of `from`'s first `bytes`.
Fault privatePage(Process& t, Region& r, u64 page, u64 from, u64 bytes) {
    u64 fresh = Pmm::allocPromised();
    if (not fresh)
        return Fault::OutOfMemory;
    if (bytes)
        memcpy(Mem::toVirtual(fresh), Mem::toVirtual(from), bytes);
    u64 old;
    bool owned;
    t.space->take(page, old, owned); // (a read-only object page being copied)
    if (not t.space->map(page, fresh, PAGE, access(r, true))) {
        Pmm::freePromised(fresh);
        return Fault::OutOfMemory;
    }
    r.privatePages++;
    return Fault::Resolved;
}

} // namespace

i64 mapAnonymous(Process& t, u64 size, bool writable, u64 at, u64& address) {
    size = Mem::alignUp(size, PAGE);
    if (size == 0 or size < PAGE)
        return Abi::INVALID_ARGUMENT;
    address = at ? at : findGap(t.vm, size);
    if (not address or (at and overlaps(t.vm, at, at + size)))
        return Abi::NO_SPACE;
    u64 pages = size / PAGE;
    if (not commit(t, pages))
        return Abi::OUT_OF_MEMORY;
    Region r;
    r.start = address;
    r.size = size;
    r.kind = Kind::Anonymous;
    r.writable = r.mayWrite = writable;
    r.committed = pages;
    if (i64 error = insert(t.vm, r)) {
        uncommit(t, r);
        return error;
    }
    return Abi::OK;
}

i64 mapObject(Process& t, SharedMemory* o, Kind kind, u64 offset, u64 size, u64 visible, bool writable,
              bool executable, u64 at, u64& address) {
    size = Mem::alignUp(size, PAGE);
    if (size == 0 or (writable and executable) or offset % PAGE or offset > o->size)
        return Abi::INVALID_ARGUMENT;
    if (kind == Kind::Shared and size > o->size - offset)
        return Abi::INVALID_ARGUMENT;
    if (kind == Kind::Copy) {
        visible = min(min(visible, size), o->size - offset);
    }
    // Copy: pages it may need of its own (all, if it's writable; else the
    // zero-filled ones past what the object shows).
    u64 pages = size / PAGE;
    u64 committed = kind == Kind::Shared ? 0 : writable ? pages : pages - visible / PAGE;
    address = at ? at : findGap(t.vm, size);
    if (not address or (at and overlaps(t.vm, at, at + size)))
        return Abi::NO_SPACE;
    if (not commit(t, committed))
        return Abi::OUT_OF_MEMORY;
    Region r;
    r.start = address;
    r.size = size;
    r.kind = kind;
    r.writable = r.mayWrite = writable;
    r.executable = executable;
    r.object = o;
    r.offset = offset;
    r.visible = visible;
    r.committed = committed;
    if (i64 error = insert(t.vm, r)) {
        uncommit(t, r);
        return error;
    }
    o->ref();
    if (kind == Kind::Shared and not o->paged() and not mapEagerly(t, *find(t.vm, address))) {
        unmap(t, address);
        return Abi::OUT_OF_MEMORY;
    }
    return Abi::OK;
}

i64 unmap(Process& t, u64 address) {
    Region* r = find(t.vm, address);
    if (not r or r->start != address)
        return Abi::NOT_FOUND;
    tearDown(t, *r);
    removeAt(t.vm, static_cast<u32>(r - t.vm.regions));
    return Abi::OK;
}

i64 protect(Process& t, u64 address, bool writable) {
    Region* r = find(t.vm, address);
    if (not r or r->start != address)
        return Abi::NOT_FOUND;
    if (writable == r->writable)
        return Abi::OK;
    // Becoming writable again needs what it was made with: a page of its own
    // promised for every page, or a writable object (not sealed since).
    if (writable and not r->mayWrite)
        return Abi::ACCESS_DENIED;
    r->writable = writable;
    if (r->kind == Kind::Shared) {
        t.space->unmap(r->start, r->size);
        if (not r->object->paged() and not mapEagerly(t, *r))
            return Abi::OUT_OF_MEMORY;
        return Abi::OK;
    }
    for (u64 page = r->start; page < r->end(); page += PAGE) {
        u64 phys;
        bool owned;
        if (not t.space->take(page, phys, owned) or not owned)
            continue; // (an object's page in a Copy region: faulted in again as needed)
        if (not t.space->map(page, phys, PAGE, access(*r, true))) {
            Pmm::freePromised(phys); // (can't happen: its page table is there)
            r->privatePages--;
        }
    }
    return Abi::OK;
}

Fault fault(Task& thread, u64 address, bool write, bool execute) {
    if (not thread.process or not thread.process->space or address >= Vmm::USER_END)
        return Fault::Invalid;
    Process& t = *thread.process;
    Region* r = find(t.vm, address);
    if (not r or (write and not r->writable) or (execute and not r->executable))
        return Fault::Invalid;
    u64 page = Mem::alignDown(address, PAGE);
    u64 index = (page - r->start) / PAGE;
    u64 phys;
    bool writable;
    bool present = t.space->query(page, phys, writable);
    if (present and (not write or writable))
        return Fault::Resolved; // (mapped meanwhile, or a stale translation)

    switch (r->kind) {
    case Kind::Anonymous:
        if (present)
            return Fault::Invalid; // (its pages are always mapped as the region allows)
        return privatePage(t, *r, page, 0, 0);

    case Kind::Shared: {
        u64 objectIndex = r->offset / PAGE + index;
        u64 p = r->object->pageAt(objectIndex);
        if (not p)
            return request(thread, r->object, objectIndex);
        if (not t.space->map(page, p, PAGE, access(*r, false), r->object->cache))
            return Fault::OutOfMemory;
        return Fault::Resolved;
    }

    case Kind::Copy: {
        u64 byte = index * PAGE;
        if (byte >= r->visible)
            return privatePage(t, *r, page, 0, 0); // past the object's data: zeros (.bss)
        u64 objectIndex = r->offset / PAGE + index;
        u64 p = r->object->pageAt(objectIndex);
        if (not p)
            return request(thread, r->object, objectIndex);
        bool partial = byte + PAGE > r->visible;
        if (write or partial) // its own page: a copy (with zeros after the data, if partial)
            return privatePage(t, *r, page, p, partial ? r->visible - byte : PAGE);
        if (not t.space->map(page, p, PAGE, access(*r, false)))
            return Fault::OutOfMemory;
        return Fault::Resolved;
    }
    }
    return Fault::Invalid;
}

Fault prepare(Task& thread, u64 address, u64 length, bool write) {
    u64 end = address + length;
    if (end < address or end > Vmm::USER_END or not thread.process)
        return Fault::Invalid;
    for (u64 page = Mem::alignDown(address, PAGE); page < end; page += PAGE) {
        u64 phys;
        bool writable;
        if (thread.process->space->query(page, phys, writable) and (not write or writable))
            continue; // (also pages mapped outside any region: an image loaded the old way)
        Fault f = fault(thread, page, write, false);
        if (f != Fault::Resolved)
            return f;
    }
    return Fault::Resolved;
}

void release(Process& t) {
    // The space is gone already, with every page it owned: only accounting
    // and the objects' references are left.
    for (u32 i = 0; i < t.vm.count; i++) {
        uncommit(t, t.vm.regions[i]);
        if (t.vm.regions[i].object)
            t.vm.regions[i].object->unref();
    }
    Heap::free(t.vm.regions);
    t.vm = {};
}

void revoke(SharedMemory* object, Process* except) {
    for (Process* t = Proc::all(); t; t = t->allNext) {
        if (t == except or not t->space)
            continue;
        for (u32 i = t->vm.count; i-- > 0;) {
            if (t->vm.regions[i].object == object) {
                tearDown(*t, t->vm.regions[i]);
                removeAt(t->vm, i);
            }
        }
    }
}

void seal(SharedMemory* object) {
    object->sealed = true;
    for (Process* t = Proc::all(); t; t = t->allNext) {
        if (not t->space)
            continue;
        for (u32 i = 0; i < t->vm.count; i++) {
            Region& r = t->vm.regions[i];
            if (r.object != object or r.kind != Kind::Shared or not r.writable)
                continue;
            r.writable = false;
            r.mayWrite = false;
            t->space->unmap(r.start, r.size);
            if (not object->paged())
                mapEagerly(*t, r); // (read-only now; no new page tables needed)
        }
    }
}

void supplied(SharedMemory* object, u64 index, u64 physical) {
    object->pages[index] = physical;
    object->residentPages++;
    for (Task** link = &waiters; *link;) {
        Task* t = *link;
        if (t->pageWaitObject == object and t->pageWaitIndex == index) {
            *link = t->pageWaitNext;
            t->pageWaitObject = nullptr;
            t->pageWaitNext = nullptr;
            Sched::wake(t);
        } else {
            link = &t->pageWaitNext;
        }
    }
}

void pagerGone(SharedMemory* object) {
    for (u64 i = 0; i < object->pageCount(); i++) {
        if (object->pages[i] == SharedMemory::REQUESTED)
            object->pages[i] = 0;
    }
    for (Task** link = &waiters; *link;) {
        Task* t = *link;
        if (t->pageWaitObject == object) {
            *link = t->pageWaitNext;
            t->pageWaitObject = nullptr;
            t->pageWaitNext = nullptr;
            Sched::wake(t); // it faults again, and that fault is for good
        } else {
            link = &t->pageWaitNext;
        }
    }
}

// shortcut: pages are dropped in object order, not least recently used;
// track the accessed bits when this shows up under real load.
u64 reclaim(u64 wanted) {
    u64 freed = 0;
    for (SharedMemory* o = SharedMemory::allPaged(); o and freed < wanted; o = o->nextPaged) {
        for (u64 index = 0; index < o->pageCount() and freed < wanted; index++) {
            u64 p = o->pages[index];
            if (p <= SharedMemory::REQUESTED)
                continue;
            // Wherever it's mapped (as itself: a Copy region's own copies stay).
            for (Process* t = Proc::all(); t; t = t->allNext) {
                for (u32 i = 0; t->space and i < t->vm.count; i++) {
                    Region const& r = t->vm.regions[i];
                    u64 first = r.offset / PAGE;
                    if (r.object != o or index < first or index - first >= r.size / PAGE)
                        continue;
                    u64 at = r.start + (index - first) * PAGE, phys;
                    bool writable, owned;
                    if (t->space->query(at, phys, writable) and phys == p)
                        t->space->take(at, phys, owned);
                }
            }
            Pmm::free(p);
            o->pages[index] = 0;
            o->residentPages--;
            freed++;
        }
    }
    if (freed)
        log("[vm]   memory pressure: dropped ", freed, " file page(s) (their pager can supply them again)");
    return freed;
}

Usage usage(Process const& t) {
    Usage u{};
    for (u32 i = 0; i < t.vm.count; i++) {
        Region const& r = t.vm.regions[i];
        u.committed += r.committed;
        u.resident += r.privatePages;
        if (r.kind == Kind::Shared)
            u.shared += r.size / PAGE;
    }
    u.regions = t.vm.count;
    return u;
}

Process* outOfMemory(Process* current) {
    Process* victim = nullptr;
    u64 most = 0;
    for (Process* t = Proc::all(); t; t = t->allNext) {
        if (t->privilege != Core::Privilege::App or t->exited or not t->space)
            continue;
        Usage u = usage(*t);
        if (not victim or u.committed + u.resident > most) {
            victim = t;
            most = u.committed + u.resident;
        }
    }
    if (not victim)
        return nullptr;
    log("[vm]   out of memory: ending ", victim->name, " (process ", victim->id, ", the app holding the most: ",
        Bytes{most * PAGE}, ")");
    if (victim != current)
        Sched::endProcess(victim, Abi::EXIT_OUT_OF_MEMORY);
    return victim;
}

} // namespace Rudracore::Vm

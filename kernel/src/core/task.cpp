#include "core/channel.h"
#include "core/device.h"
#include "core/sched.h"

namespace Rudracore::Core {

static_assert(Task::MAX_HANDLES <= 256, "a handle's slot is its low 8 bits");

u64 Task::addHandle(Capability cap) {
    for (u64 slot = 1; slot < MAX_HANDLES; slot++) {
        if (not handles[slot].cap.object) {
            handles[slot].cap = cap;
            return (handles[slot].generation << 8) | slot;
        }
    }
    return 0;
}

Capability* Task::handle(u64 h) {
    u64 slot = h & 0xFF;
    if (slot == 0 or slot >= MAX_HANDLES or not handles[slot].cap.object or handles[slot].generation != h >> 8)
        return nullptr;
    return &handles[slot].cap;
}

Capability Task::takeHandle(u64 h) {
    Capability* cap = handle(h);
    if (not cap)
        return {};
    Capability taken = *cap;
    *cap = {};
    handles[h & 0xFF].generation++;
    return taken;
}

void Task::releaseResources() {
    for (auto& slot : handles) {
        if (Object* object = slot.cap.object) {
            // An endpoint may outlive this handle (another reference holds
            // it): it must not keep pointing at this task as its waiter.
            if (object->type == ObjectType::Channel) {
                auto* endpoint = static_cast<Endpoint*>(object);
                if (endpoint->waiter == this)
                    endpoint->waiter = nullptr;
            }
            if (object->type == ObjectType::Irq and static_cast<Irq*>(object)->waiter == this)
                static_cast<Irq*>(object)->waiter = nullptr; // (a task ended while it waited)
            object->unref();
            slot.cap = {};
        }
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

} // namespace Rudracore::Core

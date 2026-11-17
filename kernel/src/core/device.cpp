#include "core/device.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/pic.h"
#include "core/channel.h"
#include "core/sched.h"
#include "panic.h"
#include "rudracore/syscalls.h"

extern "C" void* memcpy(void* dest, void const* src, usize n);

namespace Rudracore::Core {

namespace {

Irq* owners[Irq::LINES] = {};

bool same(Arch::Pci::Address a, Arch::Pci::Address b) {
    return a.bus == b.bus and a.device == b.device and a.function == b.function;
}

} // namespace

Irq::Irq(u8 line) : Object(ObjectType::Irq), line(line) {
    if (line >= LINES or owners[line])
        panic("irq: line out of range or already owned");
    owners[line] = this;
}

Irq* Irq::forDevice(Arch::Pci::Address device, i64& error) {
    Arch::InterruptGuard guard;
    u8 line = 0;
    for (u8 l = FIRST_MSI; l < LINES; l++) {
        if (owners[l] and same(owners[l]->msi.device, device)) {
            error = Abi::ALREADY_EXISTS;
            return nullptr;
        }
        if (not owners[l] and not line)
            line = l;
    }
    if (not line) {
        error = Abi::NO_SPACE;
        return nullptr;
    }
    auto* irq = new Irq(line);
    // VT-d entries 0-127 are the I/O APIC's pins; MSI lines use 128 + line.
    if (not Arch::Msi::enable(device, static_cast<u8>(Arch::Pic::IRQ_BASE + line), 128u + line, irq->msi)) {
        irq->unref();
        error = Abi::NOT_FOUND;
        return nullptr;
    }
    irq->mask(); // until the driver binds or waits
    return irq;
}

Irq::~Irq() {
    mask();
    if (line >= FIRST_MSI)
        Arch::Msi::disable(msi);
    owners[line] = nullptr;
    if (bound)
        bound->unref();
    if (waiter)
        Sched::wake(waiter); // can't happen today: a blocked task holds a handle
}

bool Irq::notify() {
    Endpoint* peer = bound ? bound->peer : nullptr;
    if (not peer or peer->full())
        return false;

    Message message{};
    Abi::IrqMessage payload{cookie};
    memcpy(message.data, &payload, sizeof(payload));
    message.size = sizeof(payload);
    message.attached = {};
    peer->push(message);
    return true;
}

bool Irq::owned(u8 line) { return line < LINES and owners[line]; }

void Irq::mask() {
    masked = true;
    if (line < FIRST_MSI)
        Arch::Pic::mask(line);
    else
        Arch::Msi::setMasked(msi, true);
}

void Irq::unmask() {
    masked = false;
    if (line < FIRST_MSI)
        Arch::Pic::unmask(line);
    else
        Arch::Msi::setMasked(msi, false);
}

bool Irq::deliver(u8 line) {
    Irq* irq = line < LINES ? owners[line] : nullptr;
    if (not irq)
        return false;

    if (irq->masked) { // a message the device couldn't hold back: keep it for later
        irq->pending = true;
        return true;
    }
    irq->mask();
    if (irq->bound) {
        irq->pending = not irq->notify();
        return true;
    }

    irq->pending = true;
    if (Task* t = irq->waiter) {
        irq->waiter = nullptr;
        Sched::wake(t);
    }
    return true;
}

void Irq::bind(Endpoint* endpoint, u64 newCookie) {
    endpoint->ref();
    if (bound)
        bound->unref();
    bound = endpoint;
    cookie = newCookie;
    pending = false;
    unmask();
}

void Irq::acknowledge() {
    // A notification that couldn't be queued earlier goes out now, and the
    // line stays masked until that one is acknowledged too.
    if (pending and bound) {
        pending = not notify();
        if (not pending)
            return;
    }
    unmask();
}

PciDevice::PciDevice(Arch::Pci::Address a) : Object(ObjectType::PciDevice), address(a) {
    u32 id = Arch::Pci::read32(a, 0x00);
    u32 classes = Arch::Pci::read32(a, 0x08);
    vendor = static_cast<u16>(id);
    device = static_cast<u16>(id >> 16);
    classCode = static_cast<u8>(classes >> 24);
    subclass = static_cast<u8>(classes >> 16);
    progIf = static_cast<u8>(classes >> 8);
    irqLine = static_cast<u8>(Arch::Pci::read32(a, 0x3C));

    for (u8 i = 0; i < 6; i++) {
        bars[i] = Arch::Pci::readBar(a, i);
        bool wide = not bars[i].io and bars[i].address and
                    ((Arch::Pci::read32(a, static_cast<u8>(0x10 + i * 4)) >> 1) & 3) == 2;
        if (wide)
            i++; // the next register holds this BAR's upper half
    }
}

void PciDevice::enable() {
    u16 command = Arch::Pci::read16(address, 0x04);
    Arch::Pci::write16(address, 0x04, command | 0x2 | 0x4); // memory space, bus master
}

PciDevice* PciDevice::find(u8 wantClass, u8 wantSubclass, u8 wantProgIf) {
    Arch::Pci::Address found{};
    bool any = false;
    Arch::Pci::forEach([&](Arch::Pci::Address a) {
        u32 classes = Arch::Pci::read32(a, 0x08);
        if (not any and (classes >> 8) == ((u32{wantClass} << 16) | (u32{wantSubclass} << 8) | wantProgIf)) {
            found = a;
            any = true;
        }
    });
    return any ? new PciDevice(found) : nullptr;
}

PciDevice* PciDevice::findById(u16 vendor, u16 const* devices, usize count) {
    Arch::Pci::Address found{};
    bool any = false;
    Arch::Pci::forEach([&](Arch::Pci::Address a) {
        u32 id = Arch::Pci::read32(a, 0x00);
        if (any or (id & 0xFFFF) != vendor)
            return;
        for (usize i = 0; i < count; i++) {
            if ((id >> 16) == devices[i]) {
                found = a;
                any = true;
            }
        }
    });
    return any ? new PciDevice(found) : nullptr;
}

} // namespace Rudracore::Core

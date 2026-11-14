// acpi: the ACPI server. Runs the firmware's AML (with uACPI, vendored in
// third_party/uacpi) in userspace, where it can reach only what its handles
// allow: physical memory that isn't RAM, the I/O ports the kernel and the
// drivers don't own, and PCI configuration space.
//
// Handles from init:
//   1: firmware (non-RAM physical memory, PCI configuration)
//   2: firmware I/O ports
//   3: a channel to KamalShell (protocol/power.h: battery, AC, temperature)
//   4: the SCI interrupt (ACPI events), when it has a line of its own
//
// Today it loads the namespace and reports what the AML says: \_S5 (the
// soft-off sleep type, evaluated rather than pattern-matched), the PCI root
// bridge's _PRT (interrupt routing), and the battery, AC adapter, power
// button and thermal zone devices. Then it moves the machine to the APICs:
// \_PIC(1), every PCI interrupt resolved through _PRT, the kernel told.
// Events: the SCI runs uACPI's event handling (fixed events, GPEs); the
// power button turns the machine off. Battery, AC adapter and thermal zone
// readings (_BIX/_BIF, _BST, _PSR, _TMP, _CRT), through an embedded
// controller driver where the AML needs one. Next: sleep states.

#include <kapala/channel.h>
#include <kapala/heap.h>
#include <kapala/protocol/power.h>
#include <kapala/sys.h>
#include <kapala/text.h>

#include <uacpi/kernel_api.h>
#include <uacpi/event.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/opregion.h>
#include <uacpi/resources.h>
#include <uacpi/sleep.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

using namespace Kapala;

namespace {

constexpr Sys::Handle FIRMWARE = 1;
constexpr Sys::Handle PORTS = 2;
constexpr Sys::Handle SHELL = 3;
constexpr Sys::Handle SCI = 4;

namespace Power = Protocol::Power;

// The SCI handler uACPI installs, and its context.
uacpi_interrupt_handler sciHandler = nullptr;
uacpi_handle sciContext = nullptr;
unsigned powerButtonPresses = 0;
bool powerButton = false; // pressed, not yet acted on

struct Work {
    uacpi_work_handler handler;
    uacpi_handle context;
};
Work work[32];
unsigned long workCount = 0;

void runWork() {
    while (workCount) {
        Work w = work[0];
        for (unsigned long i = 1; i < workCount; i++)
            work[i - 1] = work[i];
        workCount--;
        w.handler(w.context); // (may queue more)
    }
}
constexpr unsigned long PAGE = 4096;

// MARK: Mappings (cached: a program may hold only 32, and uACPI maps often)

struct Mapping {
    unsigned long physical = 0, size = 0; // page aligned
    unsigned char* address = nullptr;
    long handle = 0;
    int uses = 0;
};
Mapping mappings[24];

void* mapPhysical(unsigned long physical, unsigned long length) {
    for (Mapping& m : mappings) {
        if (m.address and physical >= m.physical and physical + length <= m.physical + m.size) {
            m.uses++;
            return m.address + (physical - m.physical);
        }
    }
    Mapping* slot = nullptr;
    for (Mapping& m : mappings) {
        if (not m.address) {
            slot = &m;
            break;
        }
    }
    if (not slot) { // all taken: let go of one nobody uses
        for (Mapping& m : mappings) {
            if (m.uses == 0) {
                Sys::memoryUnmap(m.address);
                Sys::close(static_cast<Sys::Handle>(m.handle));
                m = Mapping{};
                slot = &m;
                break;
            }
        }
    }
    if (not slot)
        return UACPI_MAP_FAILED;
    unsigned long start = physical & ~(PAGE - 1), end = (physical + length + PAGE - 1) & ~(PAGE - 1);
    long handle = Sys::firmwareMemory(FIRMWARE, start, end - start);
    if (handle < 0)
        return UACPI_MAP_FAILED;
    auto* address = static_cast<unsigned char*>(Sys::memoryMap(static_cast<Sys::Handle>(handle)));
    if (not address) {
        Sys::close(static_cast<Sys::Handle>(handle));
        return UACPI_MAP_FAILED;
    }
    *slot = {start, end - start, address, handle, 1};
    return address + (physical - start);
}

void unmapPhysical(void* address) {
    auto* p = static_cast<unsigned char*>(address);
    for (Mapping& m : mappings) {
        if (m.address and p >= m.address and p < m.address + m.size and m.uses > 0) {
            m.uses--; // (kept mapped for the next time)
            return;
        }
    }
}

// MARK: Reporting

struct Counter {
    unsigned long n = 0;
};

uacpi_iteration_decision count(void* user, uacpi_namespace_node*, uacpi_u32) {
    static_cast<Counter*>(user)->n++;
    return UACPI_ITERATION_DECISION_CONTINUE;
}

uacpi_iteration_decision firstNode(void* user, uacpi_namespace_node* node, uacpi_u32) {
    *static_cast<uacpi_namespace_node**>(user) = node;
    return UACPI_ITERATION_DECISION_BREAK;
}

unsigned long devices(char const* hid) {
    Counter c;
    uacpi_find_devices(hid, count, &c);
    return c.n;
}

void report() {
    Counter objects;
    uacpi_namespace_for_each_child_simple(uacpi_namespace_root(), count, &objects);

    // \_S5: Package { SLP_TYPa, SLP_TYPb, ... }
    Text<200> s5;
    uacpi_object* package = nullptr;
    uacpi_object_array items{};
    uacpi_u64 a = 0, b = 0;
    if (uacpi_eval_simple_package(nullptr, "\\_S5", &package) == UACPI_STATUS_OK and
        uacpi_object_get_package(package, &items) == UACPI_STATUS_OK and items.count >= 2 and
        uacpi_object_get_integer(items.objects[0], &a) == UACPI_STATUS_OK and
        uacpi_object_get_integer(items.objects[1], &b) == UACPI_STATUS_OK)
        s5.add("\\_S5 evaluated: SLP_TYPa ").add(a).add(", SLP_TYPb ").add(b);
    else
        s5.add("\\_S5: none (this machine can't be soft-powered-off through ACPI)");
    uacpi_object_unref(package);

    // _PRT of the PCI root bridge (PCI Express or plain PCI)
    Text<200> prt;
    uacpi_namespace_node* root = nullptr;
    uacpi_find_devices("PNP0A08", firstNode, &root);
    if (not root)
        uacpi_find_devices("PNP0A03", firstNode, &root);
    uacpi_pci_routing_table* table = nullptr;
    if (root and uacpi_get_pci_routing_table(root, &table) == UACPI_STATUS_OK) {
        unsigned long links = 0;
        for (uacpi_size i = 0; i < table->num_entries; i++)
            links += table->entries[i].source != nullptr;
        prt.add("_PRT of the PCI root: ").add(static_cast<unsigned long>(table->num_entries)).add(" entries (")
            .add(links).add(" through link devices, ").add(static_cast<unsigned long>(table->num_entries) - links)
            .add(" fixed)");
        if (table->num_entries) {
            auto const& e = table->entries[0];
            prt.add("; e.g. device ").add(static_cast<unsigned long>(e.address >> 16)).add(" pin ")
                .add(static_cast<unsigned long>(e.pin));
            if (e.source)
                prt.add(" -> a link device");
            else
                prt.add(" -> GSI ").add(static_cast<unsigned long>(e.index));
        }
        uacpi_free_pci_routing_table(table);
    } else {
        prt.add("_PRT: no PCI root bridge routing found");
    }

    Counter thermal;
    uacpi_namespace_for_each_child(uacpi_namespace_root(), count, nullptr, UACPI_OBJECT_THERMAL_ZONE_BIT,
                                   UACPI_MAX_DEPTH_ANY, &thermal);

    Text<200> t;
    t.add("acpi: AML namespace loaded: ").add(objects.n).add(" objects");
    Sys::log(t.cstr());
    Sys::log(s5.cstr());
    Sys::log(prt.cstr());
    Text<200> d;
    d.add("devices: ").add(devices("PNP0C0A")).add(" battery, ").add(devices("ACPI0003")).add(" AC adapter, ")
        .add(devices("PNP0C0C")).add(" power button, ").add(thermal.n).add(" thermal zone(s)");
    Sys::log(d.cstr());
}

// MARK: Interrupt routing: the PICs -> the APICs

struct Link {
    unsigned long gsi = 0;
    bool level = true, activeLow = true, found = false; // (PCI's defaults)
};

uacpi_iteration_decision linkIrq(void* user, uacpi_resource* r) {
    auto* link = static_cast<Link*>(user);
    if (r->type == UACPI_RESOURCE_TYPE_EXTENDED_IRQ and r->extended_irq.num_irqs) {
        *link = {r->extended_irq.irqs[0], r->extended_irq.triggering == UACPI_TRIGGERING_LEVEL,
                 r->extended_irq.polarity == UACPI_POLARITY_ACTIVE_LOW, true};
        return UACPI_ITERATION_DECISION_BREAK;
    }
    if (r->type == UACPI_RESOURCE_TYPE_IRQ and r->irq.num_irqs) {
        *link = {r->irq.irqs[0], r->irq.triggering == UACPI_TRIGGERING_LEVEL,
                 r->irq.polarity == UACPI_POLARITY_ACTIVE_LOW, true};
        return UACPI_ITERATION_DECISION_BREAK;
    }
    return UACPI_ITERATION_DECISION_CONTINUE;
}

unsigned long pci(unsigned bus, unsigned device, unsigned function, unsigned offset, unsigned width) {
    long v = Sys::firmwarePciRead(FIRMWARE, bus << 16 | device << 11 | function << 8 | offset, width);
    return v < 0 ? ~0ul : static_cast<unsigned long>(v);
}

// Tells the firmware we use the I/O APIC (\_PIC(1)), works out where each
// PCI function's interrupt pin arrives (_PRT, through link devices' _CRS),
// hands those routes to the kernel and asks it to switch. Bus 0 only.
void routeInterrupts() {
    if (uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC) != UACPI_STATUS_OK) {
        Sys::log("acpi: \\_PIC(1) failed: staying on the 8259 PICs");
        return;
    }
    uacpi_namespace_node* root = nullptr;
    uacpi_find_devices("PNP0A08", firstNode, &root);
    if (not root)
        uacpi_find_devices("PNP0A03", firstNode, &root);
    uacpi_pci_routing_table* table = nullptr;
    if (not root or uacpi_get_pci_routing_table(root, &table) != UACPI_STATUS_OK) {
        Sys::log("acpi: no _PRT for the PCI root: staying on the 8259 PICs");
        return;
    }
    unsigned long routed = 0;
    bool failed = false;
    for (unsigned device = 0; device < 32 and not failed; device++) {
        bool multifunction = pci(0, device, 0, 0x0E, 1) & 0x80;
        for (unsigned function = 0; function < (multifunction ? 8u : 1u) and not failed; function++) {
            if ((pci(0, device, function, 0, 2) & 0xFFFF) == 0xFFFF)
                continue;
            unsigned long pin = pci(0, device, function, 0x3D, 1), line = pci(0, device, function, 0x3C, 1);
            if (pin < 1 or pin > 4 or line >= 16)
                continue; // no interrupt, or none the firmware gave a line
            Link link;
            for (uacpi_size i = 0; i < table->num_entries and not link.found; i++) {
                auto const& e = table->entries[i];
                if ((e.address >> 16) != device or e.pin != pin - 1)
                    continue;
                if (e.source) {
                    uacpi_resources* resources = nullptr;
                    if (uacpi_get_current_resources(e.source, &resources) == UACPI_STATUS_OK) {
                        uacpi_for_each_resource(resources, linkIrq, &link);
                        uacpi_free_resources(resources);
                    }
                } else {
                    link = {e.index, true, true, true};
                }
            }
            long r = link.found ? Sys::firmwareInterrupts(FIRMWARE, Sys::INTERRUPTS_ROUTE, link.gsi,
                                                          line | (link.level ? 1ul << 8 : 0) | (link.activeLow ? 1ul << 9 : 0))
                                : -1;
            if (r < 0) {
                Text<120> t;
                t.add("acpi: PCI 0:").add(static_cast<unsigned long>(device)).add(".").add(static_cast<unsigned long>(function))
                    .add(" pin ").add(pin).add(": no route: staying on the 8259 PICs");
                Sys::log(t.cstr());
                failed = true;
            }
            routed++;
        }
    }
    uacpi_free_pci_routing_table(table);
    if (failed)
        return;
    long r = Sys::firmwareInterrupts(FIRMWARE, Sys::INTERRUPTS_APIC);
    Text<120> t;
    t.add("acpi: ").add(routed).add(" PCI interrupt(s) routed by _PRT; ")
        .add(r == Sys::OK ? "the kernel switched to the APICs" : "the kernel stayed on the 8259 PICs");
    Sys::log(t.cstr());
}

// MARK: Events

uacpi_interrupt_ret onPowerButton(uacpi_handle) {
    powerButton = true;
    return UACPI_INTERRUPT_HANDLED;
}

// A power button that's a device (PNP0C0C) signals with Notify(0x80).
uacpi_status onButtonNotify(uacpi_handle, uacpi_namespace_node*, uacpi_u64 value) {
    if (value == 0x80)
        powerButton = true;
    return UACPI_STATUS_OK;
}

uacpi_iteration_decision watchButton(void*, uacpi_namespace_node* node, uacpi_u32) {
    uacpi_install_notify_handler(node, onButtonNotify, nullptr);
    return UACPI_ITERATION_DECISION_CONTINUE;
}

// MARK: Embedded controller (ACPI 6.5 section 12): two ports, a byte protocol

struct Ec {
    unsigned data = 0, command = 0;
    int ports = 0;
} ec;

constexpr unsigned EC_OBF = 1, EC_IBF = 2, EC_READ = 0x80, EC_WRITE = 0x81;

bool ecWait(bool outputFull) {
    for (int i = 0; i < 100000; i++) {
        long status = Sys::portInWide(PORTS, ec.command, 1);
        if (status < 0)
            return false;
        if (outputFull ? (status & EC_OBF) : not(status & EC_IBF))
            return true;
    }
    return false; // (a stuck controller: the AML gets an error, nothing hangs)
}

uacpi_status ecHandler(uacpi_region_op op, uacpi_handle data) {
    if (op == UACPI_REGION_OP_ATTACH or op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    if (op != UACPI_REGION_OP_READ and op != UACPI_REGION_OP_WRITE)
        return UACPI_STATUS_UNIMPLEMENTED;
    auto* rw = static_cast<uacpi_region_rw_data*>(data);
    if (rw->byte_width != 1 or rw->offset > 0xFF)
        return UACPI_STATUS_INVALID_ARGUMENT;
    bool read = op == UACPI_REGION_OP_READ;
    if (not ecWait(false) or Sys::portOutWide(PORTS, ec.command, 1, read ? EC_READ : EC_WRITE) < 0 or
        not ecWait(false) or Sys::portOutWide(PORTS, ec.data, 1, rw->offset) < 0)
        return UACPI_STATUS_HARDWARE_TIMEOUT;
    if (read) {
        if (not ecWait(true))
            return UACPI_STATUS_HARDWARE_TIMEOUT;
        rw->value = static_cast<unsigned long>(Sys::portInWide(PORTS, ec.data, 1)) & 0xFF;
    } else if (not ecWait(false) or Sys::portOutWide(PORTS, ec.data, 1, rw->value & 0xFF) < 0) {
        return UACPI_STATUS_HARDWARE_TIMEOUT;
    }
    return UACPI_STATUS_OK;
}

uacpi_iteration_decision ecPort(void*, uacpi_resource* r) {
    unsigned port = r->type == UACPI_RESOURCE_TYPE_IO         ? r->io.minimum
                    : r->type == UACPI_RESOURCE_TYPE_FIXED_IO ? r->fixed_io.address
                                                              : 0x10000;
    if (port <= 0xFFFF) {
        if (ec.ports == 0)
            ec.data = port; // the data port comes first
        else
            ec.command = port;
        if (++ec.ports == 2)
            return UACPI_ITERATION_DECISION_BREAK;
    }
    return UACPI_ITERATION_DECISION_CONTINUE;
}

uacpi_iteration_decision setUpEc(void*, uacpi_namespace_node* node, uacpi_u32) {
    uacpi_resources* resources = nullptr;
    if (uacpi_get_current_resources(node, &resources) != UACPI_STATUS_OK)
        return UACPI_ITERATION_DECISION_CONTINUE;
    uacpi_for_each_resource(resources, ecPort, nullptr);
    uacpi_free_resources(resources);
    if (ec.ports == 2 and uacpi_install_address_space_handler(node, UACPI_ADDRESS_SPACE_EMBEDDED_CONTROLLER,
                                                              ecHandler, nullptr) == UACPI_STATUS_OK) {
        Text<100> t;
        t.add("acpi: embedded controller at ports ").add(static_cast<unsigned long>(ec.data)).add("/")
            .add(static_cast<unsigned long>(ec.command));
        Sys::log(t.cstr());
    }
    return UACPI_ITERATION_DECISION_BREAK; // (one EC)
}

// MARK: Batteries, AC adapter, thermal zones

constexpr unsigned long UNKNOWN = 0xFFFFFFFF; // ACPI's "unknown" in battery packages

// Integers of a package a method returns (unknown or missing: UNKNOWN).
bool packageIntegers(uacpi_namespace_node* node, char const* method, unsigned long* out, unsigned long count) {
    uacpi_object* object = nullptr;
    uacpi_object_array items{};
    if (uacpi_eval_simple_package(node, method, &object) != UACPI_STATUS_OK or
        uacpi_object_get_package(object, &items) != UACPI_STATUS_OK) {
        uacpi_object_unref(object);
        return false;
    }
    for (unsigned long i = 0; i < count; i++) {
        uacpi_u64 v = UNKNOWN;
        if (i >= items.count or uacpi_object_get_integer(items.objects[i], &v) != UACPI_STATUS_OK)
            v = UNKNOWN;
        out[i] = v;
    }
    uacpi_object_unref(object);
    return true;
}

struct Totals {
    unsigned long remaining = 0, full = 0;
    Power::Status* status = nullptr;
};

uacpi_iteration_decision readBattery(void* user, uacpi_namespace_node* node, uacpi_u32) {
    auto* totals = static_cast<Totals*>(user);
    totals->status->batteries++;
    // Last full charge: _BIX field 3, or _BIF field 2. Now: _BST.
    unsigned long info[4], state[4];
    unsigned long full = UNKNOWN;
    if (packageIntegers(node, "_BIX", info, 4))
        full = info[3];
    else if (packageIntegers(node, "_BIF", info, 3))
        full = info[2];
    if (not packageIntegers(node, "_BST", state, 4))
        return UACPI_ITERATION_DECISION_CONTINUE;
    totals->status->discharging |= state[0] & 1;
    totals->status->charging |= (state[0] >> 1) & 1;
    totals->status->critical |= (state[0] >> 2) & 1;
    if (full != UNKNOWN and full and state[2] != UNKNOWN) {
        totals->full += full;
        totals->remaining += state[2] < full ? state[2] : full;
    }
    return UACPI_ITERATION_DECISION_CONTINUE;
}

uacpi_iteration_decision readAdapter(void* user, uacpi_namespace_node* node, uacpi_u32) {
    auto* status = static_cast<Power::Status*>(user);
    uacpi_u64 online = 0;
    if (uacpi_eval_simple_integer(node, "_PSR", &online) == UACPI_STATUS_OK and status->ac != 1)
        status->ac = online ? 1 : 0; // (several adapters: online if any is)
    return UACPI_ITERATION_DECISION_CONTINUE;
}

uacpi_iteration_decision readZone(void* user, uacpi_namespace_node* node, uacpi_u32) {
    auto* status = static_cast<Power::Status*>(user);
    status->thermalZones++;
    uacpi_u64 kelvin = 0, critical = 0; // tenths of a kelvin
    if (uacpi_eval_simple_integer(node, "_TMP", &kelvin) == UACPI_STATUS_OK and kelvin >= 1000 and kelvin < 6000) {
        auto celsius = static_cast<short>(static_cast<long>(kelvin) - 2732);
        if (status->temperature == Power::UNKNOWN_TEMPERATURE or celsius > status->temperature) {
            status->temperature = celsius;
            bool haveCritical = uacpi_eval_simple_integer(node, "_CRT", &critical) == UACPI_STATUS_OK and
                                critical >= 1000 and critical < 6000;
            status->criticalTemperature = haveCritical ? static_cast<short>(static_cast<long>(critical) - 2732)
                                                       : Power::UNKNOWN_TEMPERATURE;
        }
    }
    return UACPI_ITERATION_DECISION_CONTINUE;
}

Power::Status readStatus() {
    Power::Status status{};
    status.percent = Power::UNKNOWN_PERCENT;
    status.ac = -1;
    status.temperature = status.criticalTemperature = Power::UNKNOWN_TEMPERATURE;
    status.powerButtonPresses = powerButtonPresses;
    Totals totals;
    totals.status = &status;
    uacpi_find_devices("PNP0C0A", readBattery, &totals);
    if (totals.full)
        status.percent = static_cast<unsigned char>(totals.remaining * 100 / totals.full);
    uacpi_find_devices("ACPI0003", readAdapter, &status);
    uacpi_namespace_for_each_child(uacpi_namespace_root(), readZone, nullptr, UACPI_OBJECT_THERMAL_ZONE_BIT,
                                   UACPI_MAX_DEPTH_ANY, &status);
    return status;
}

// Off, the ACPI way: \_PTS(5) and \_GTS (uACPI's preparation), then
// SLP_TYP|SLP_EN. If the firmware won't, the kernel's own S5 is the fallback.
void powerOff(char const* why) {
    Text<120> t;
    t.add("acpi: ").add(why).add(": turning off through ACPI (S5)");
    Sys::log(t.cstr());
    uacpi_status s = uacpi_prepare_for_sleep_state(UACPI_SLEEP_STATE_S5);
    if (s == UACPI_STATUS_OK)
        s = uacpi_enter_sleep_state(UACPI_SLEEP_STATE_S5);
    Text<120> e;
    e.add("acpi: ACPI couldn't turn the machine off (").add(uacpi_status_to_string(s)).add("): the kernel tries");
    Sys::log(e.cstr());
    Sys::power(Sys::POWER_OFF);
}

void logStatus() {
    Power::Status s = readStatus();
    Text<200> t;
    t.add("acpi: power: ");
    if (s.batteries) {
        t.add(static_cast<unsigned long>(s.batteries)).add(" battery, ");
        if (s.percent != Power::UNKNOWN_PERCENT)
            t.add(static_cast<unsigned long>(s.percent)).add("%");
        else
            t.add("charge unknown");
        t.add(s.charging ? " charging" : s.discharging ? " discharging" : "").add(s.critical ? " (critical)" : "");
    } else {
        t.add("no battery");
    }
    t.add(s.ac == 1 ? ", on AC" : s.ac == 0 ? ", AC unplugged" : "");
    if (s.temperature != Power::UNKNOWN_TEMPERATURE) {
        t.add(", ").add(static_cast<long>(s.temperature / 10)).add(".").add(static_cast<long>((s.temperature % 10 + 10) % 10))
            .add(" C");
        if (s.criticalTemperature != Power::UNKNOWN_TEMPERATURE)
            t.add(" (critical at ").add(static_cast<long>(s.criticalTemperature / 10)).add(" C)");
    } else {
        t.add(", no temperature reading");
    }
    Sys::log(t.cstr());
}

} // namespace

// MARK: uACPI's host interface

extern "C" {

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr* out) {
    Sys::SystemInfo info{};
    Sys::systemInfo(info);
    if (not info.acpiRsdp)
        return UACPI_STATUS_NOT_FOUND;
    *out = info.acpiRsdp;
    return UACPI_STATUS_OK;
}

void* uacpi_kernel_map(uacpi_phys_addr address, uacpi_size length) { return mapPhysical(address, length); }
void uacpi_kernel_unmap(void* address, uacpi_size) { unmapPhysical(address); }

void uacpi_kernel_log(uacpi_log_level level, uacpi_char const* text) {
    if (level > UACPI_LOG_INFO)
        return; // (trace and debug are too chatty for the serial log)
    Text<300> t;
    t.add(level == UACPI_LOG_ERROR ? "uacpi error: " : level == UACPI_LOG_WARN ? "uacpi warning: " : "uacpi: ");
    for (unsigned long i = 0; text[i] and text[i] != '\n' and i < 250; i++) {
        char c[2] = {text[i], 0};
        t.add(c);
    }
    Sys::log(t.cstr());
}

// PCI configuration (segment 0) through the kernel.
struct PciDevice {
    unsigned long address; // bus << 16 | device << 11 | function << 8
};

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address a, uacpi_handle* out) {
    if (a.segment != 0)
        return UACPI_STATUS_UNIMPLEMENTED;
    auto* d = static_cast<PciDevice*>(Heap::alloc(sizeof(PciDevice)));
    if (not d)
        return UACPI_STATUS_OUT_OF_MEMORY;
    d->address = static_cast<unsigned long>(a.bus) << 16 | static_cast<unsigned long>(a.device) << 11 |
                 static_cast<unsigned long>(a.function) << 8;
    *out = d;
    return UACPI_STATUS_OK;
}
void uacpi_kernel_pci_device_close(uacpi_handle d) { Heap::free(d); }

static uacpi_status pciRead(uacpi_handle d, uacpi_size offset, unsigned width, unsigned long& out) {
    long r = Sys::firmwarePciRead(FIRMWARE, static_cast<PciDevice*>(d)->address | offset, width);
    if (r < 0 or offset > 255)
        return UACPI_STATUS_INVALID_ARGUMENT;
    out = static_cast<unsigned long>(r);
    return UACPI_STATUS_OK;
}
static uacpi_status pciWrite(uacpi_handle d, uacpi_size offset, unsigned width, unsigned long value) {
    if (offset > 255 or Sys::firmwarePciWrite(FIRMWARE, static_cast<PciDevice*>(d)->address | offset, width, value) < 0)
        return UACPI_STATUS_INVALID_ARGUMENT;
    return UACPI_STATUS_OK;
}
uacpi_status uacpi_kernel_pci_read8(uacpi_handle d, uacpi_size o, uacpi_u8* v) {
    unsigned long x;
    uacpi_status s = pciRead(d, o, 1, x);
    *v = static_cast<uacpi_u8>(x);
    return s;
}
uacpi_status uacpi_kernel_pci_read16(uacpi_handle d, uacpi_size o, uacpi_u16* v) {
    unsigned long x;
    uacpi_status s = pciRead(d, o, 2, x);
    *v = static_cast<uacpi_u16>(x);
    return s;
}
uacpi_status uacpi_kernel_pci_read32(uacpi_handle d, uacpi_size o, uacpi_u32* v) {
    unsigned long x;
    uacpi_status s = pciRead(d, o, 4, x);
    *v = static_cast<uacpi_u32>(x);
    return s;
}
uacpi_status uacpi_kernel_pci_write8(uacpi_handle d, uacpi_size o, uacpi_u8 v) { return pciWrite(d, o, 1, v); }
uacpi_status uacpi_kernel_pci_write16(uacpi_handle d, uacpi_size o, uacpi_u16 v) { return pciWrite(d, o, 2, v); }
uacpi_status uacpi_kernel_pci_write32(uacpi_handle d, uacpi_size o, uacpi_u32 v) { return pciWrite(d, o, 4, v); }

// I/O ports through the firmware port handle (the kernel refuses the ones
// it and the drivers own).
struct IoRange {
    unsigned long base, length;
};

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size length, uacpi_handle* out) {
    if (base > 0xFFFF or length > 0x10000 - base)
        return UACPI_STATUS_INVALID_ARGUMENT;
    auto* r = static_cast<IoRange*>(Heap::alloc(sizeof(IoRange)));
    if (not r)
        return UACPI_STATUS_OUT_OF_MEMORY;
    *r = {base, length};
    *out = r;
    return UACPI_STATUS_OK;
}
void uacpi_kernel_io_unmap(uacpi_handle r) { Heap::free(r); }

static uacpi_status ioRead(uacpi_handle h, uacpi_size offset, unsigned width, unsigned long& out) {
    auto* r = static_cast<IoRange*>(h);
    if (offset + width > r->length)
        return UACPI_STATUS_INVALID_ARGUMENT;
    long v = Sys::portInWide(PORTS, static_cast<unsigned>(r->base + offset), width);
    if (v < 0)
        return UACPI_STATUS_INVALID_ARGUMENT; // a port this server may not touch
    out = static_cast<unsigned long>(v);
    return UACPI_STATUS_OK;
}
static uacpi_status ioWrite(uacpi_handle h, uacpi_size offset, unsigned width, unsigned long value) {
    auto* r = static_cast<IoRange*>(h);
    if (offset + width > r->length or Sys::portOutWide(PORTS, static_cast<unsigned>(r->base + offset), width, value) < 0)
        return UACPI_STATUS_INVALID_ARGUMENT;
    return UACPI_STATUS_OK;
}
uacpi_status uacpi_kernel_io_read8(uacpi_handle h, uacpi_size o, uacpi_u8* v) {
    unsigned long x = 0;
    uacpi_status s = ioRead(h, o, 1, x);
    *v = static_cast<uacpi_u8>(x);
    return s;
}
uacpi_status uacpi_kernel_io_read16(uacpi_handle h, uacpi_size o, uacpi_u16* v) {
    unsigned long x = 0;
    uacpi_status s = ioRead(h, o, 2, x);
    *v = static_cast<uacpi_u16>(x);
    return s;
}
uacpi_status uacpi_kernel_io_read32(uacpi_handle h, uacpi_size o, uacpi_u32* v) {
    unsigned long x = 0;
    uacpi_status s = ioRead(h, o, 4, x);
    *v = static_cast<uacpi_u32>(x);
    return s;
}
uacpi_status uacpi_kernel_io_write8(uacpi_handle h, uacpi_size o, uacpi_u8 v) { return ioWrite(h, o, 1, v); }
uacpi_status uacpi_kernel_io_write16(uacpi_handle h, uacpi_size o, uacpi_u16 v) { return ioWrite(h, o, 2, v); }
uacpi_status uacpi_kernel_io_write32(uacpi_handle h, uacpi_size o, uacpi_u32 v) { return ioWrite(h, o, 4, v); }

void* uacpi_kernel_alloc(uacpi_size size) { return Heap::alloc(size ? size : 1); }
void uacpi_kernel_free(void* p) {
    if (p)
        Heap::free(p);
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) { return Sys::timeMs() * 1'000'000ull; }

void uacpi_kernel_stall(uacpi_u8 usec) {
    // shortcut: the clock counts milliseconds, so short stalls spin a rough count.
    for (unsigned long i = 0; i < usec * 200ul; i++)
        asm volatile("pause");
}

void uacpi_kernel_sleep(uacpi_u64 msec) { Sys::sleep(msec); }

// One thread: semaphores are counters, spinlocks and interrupts need nothing.
struct Semaphore {
    unsigned long units;
};

uacpi_handle uacpi_kernel_create_semaphore(uacpi_u32 initial) {
    auto* s = static_cast<Semaphore*>(Heap::alloc(sizeof(Semaphore)));
    if (s)
        s->units = initial;
    return s;
}
void uacpi_kernel_free_semaphore(uacpi_handle s) { Heap::free(s); }
uacpi_status uacpi_kernel_wait_for_semaphore(uacpi_handle h, uacpi_u16) {
    auto* s = static_cast<Semaphore*>(h);
    if (s->units == 0)
        return UACPI_STATUS_TIMEOUT; // nobody else could ever signal it
    s->units--;
    return UACPI_STATUS_OK;
}
void uacpi_kernel_signal_semaphore(uacpi_handle h) { static_cast<Semaphore*>(h)->units++; }

uacpi_thread_id uacpi_kernel_get_thread_id(void) { return reinterpret_cast<uacpi_thread_id>(1); }
uacpi_interrupt_state uacpi_kernel_disable_interrupts(void) { return 0; }
void uacpi_kernel_restore_interrupts(uacpi_interrupt_state) {}

uacpi_handle uacpi_kernel_create_spinlock(void) { return Heap::alloc(1); }
void uacpi_kernel_free_spinlock(uacpi_handle s) { Heap::free(s); }
uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle) { return 0; }
void uacpi_kernel_unlock_spinlock(uacpi_handle, uacpi_cpu_flags) {}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request* request) {
    if (request->type == UACPI_FIRMWARE_REQUEST_TYPE_FATAL)
        Sys::log("acpi: the firmware's AML reported a fatal error");
    return UACPI_STATUS_OK;
}

// The SCI: main() binds it to a channel and calls the handler from the loop.
uacpi_status uacpi_kernel_install_interrupt_handler(uacpi_u32, uacpi_interrupt_handler handler, uacpi_handle context,
                                                    uacpi_handle* out) {
    sciHandler = handler;
    sciContext = context;
    *out = reinterpret_cast<uacpi_handle>(1);
    return UACPI_STATUS_OK;
}
uacpi_status uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler, uacpi_handle) {
    sciHandler = nullptr;
    return UACPI_STATUS_OK;
}

// Work (GPE methods, notifications) is queued and run by the main loop once
// the handler that queued it has returned: never inside it.
uacpi_handle uacpi_kernel_create_work_item(void) { return Heap::alloc(1); }
void uacpi_kernel_free_work_item(uacpi_handle w) { Heap::free(w); }
void uacpi_kernel_schedule_work(uacpi_work_type, uacpi_handle, uacpi_work_handler handler, uacpi_handle context) {
    if (workCount < sizeof(work) / sizeof(work[0]))
        work[workCount++] = {handler, context};
    else
        Sys::log("acpi: too much ACPI work queued: dropped some");
}
uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    runWork();
    return UACPI_STATUS_OK;
}

} // extern "C"

int main() {
    // The fence around firmware code: a port the kernel owns (the PIC) and a
    // page of ordinary RAM must both be refused.
    long pic = Sys::portInWide(PORTS, 0x21, 1);
    long ram = Sys::firmwareMemory(FIRMWARE, 0x200000, PAGE);
    if (pic >= 0 or ram >= 0) {
        Sys::log("acpi: FAILED: the firmware handles reach the kernel's ports or RAM");
        return 1;
    }
    Sys::log("acpi: firmware access limits hold (kernel ports and RAM refused)");

    uacpi_status s = uacpi_initialize(0);
    if (s == UACPI_STATUS_OK)
        s = uacpi_namespace_load();
    if (s == UACPI_STATUS_OK)
        s = uacpi_namespace_initialize();
    if (s != UACPI_STATUS_OK) {
        Text<200> t;
        t.add("acpi: couldn't load the firmware's AML: ").add(uacpi_status_to_string(s));
        Sys::log(t.cstr());
        return 1;
    }
    report();
    routeInterrupts();

    // Events: the EC first (battery methods often read it), then the power
    // button, then the GPEs the AML has handlers for.
    uacpi_find_devices("PNP0C09", setUpEc, nullptr);
    if (uacpi_install_fixed_event_handler(UACPI_FIXED_EVENT_POWER_BUTTON, onPowerButton, nullptr) != UACPI_STATUS_OK)
        Sys::log("acpi: no fixed power button");
    uacpi_find_devices("PNP0C0C", watchButton, nullptr);
    uacpi_finalize_gpe_initialization();
    Channel sci, sciEnd;
    Channel::createPair(sci, sciEnd);
    bool haveSci = Sys::irqBind(SCI, sciEnd.handle(), 1) == Sys::OK;
    Sys::log(haveSci ? "acpi: listening for ACPI events (SCI)" : "acpi: no SCI line of its own: no ACPI events");
    logStatus();

    Channel shell(SHELL);
    bool haveShell = true;
    for (;;) {
        Sys::Handle handles[2];
        int owners[2];
        unsigned long count = 0;
        if (haveShell) {
            handles[count] = shell.handle();
            owners[count++] = 0;
        }
        if (haveSci) {
            handles[count] = sci.handle();
            owners[count++] = 1;
        }
        long ready = count ? Sys::wait(handles, count, Sys::WAIT_FOREVER) : Sys::TIMED_OUT;
        if (count == 0)
            Sys::sleep(60 * 1000);
        if (ready >= 0 and owners[ready] == 1) { // the SCI: uACPI reads and clears what happened
            Sys::IrqMessage message;
            sci.recv(message);
            if (sciHandler)
                sciHandler(sciContext);
            Sys::irqAck(SCI);
            runWork();
        } else if (ready >= 0) {
            Power::Request request{};
            long r = shell.recv(request);
            if (r == Sys::PEER_CLOSED)
                haveShell = false; // (no shell: events only)
            else if (r == Sys::OK and request.op == Power::Op::Status)
                shell.send(readStatus());
            else if (r == Sys::OK and request.op == Power::Op::PowerOff)
                powerOff("shut down from KamalShell");
        }
        if (powerButton) {
            powerButtonPresses++;
            powerButton = false;
            powerOff("power button pressed");
        }
    }
}

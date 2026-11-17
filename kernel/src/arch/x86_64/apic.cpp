#include "arch/x86_64/apic.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/iommu.h"
#include "arch/x86_64/pic.h"
#include "log.h"

namespace Rudracore::Arch::Apic {

namespace {

constexpr u32 MAX_ROUTES = 32, MAX_INPUTS = 120;

// Local APIC registers
constexpr u64 LAPIC_ID = 0x20, LAPIC_TPR = 0x80, LAPIC_EOI = 0xB0, LAPIC_SVR = 0xF0;
constexpr u64 LAPIC_ICR_LOW = 0x300, LAPIC_ICR_HIGH = 0x310;
constexpr u64 LAPIC_LVT_TIMER = 0x320, LAPIC_LVT_LINT0 = 0x350, LAPIC_LVT_LINT1 = 0x360;
constexpr u64 LAPIC_TIMER_INITIAL = 0x380, LAPIC_TIMER_CURRENT = 0x390, LAPIC_TIMER_DIVIDE = 0x3E0;
constexpr u32 LVT_MASKED = 1u << 16, LVT_EXTINT = 0x700, LVT_NMI = 0x400, LVT_PERIODIC = 1u << 17;
constexpr u32 ICR_PENDING = 1u << 12, ICR_INIT = 0x500, ICR_STARTUP = 0x600, ICR_ASSERT = 1u << 14,
              ICR_LEVEL = 1u << 15;
// I/O APIC: select register, then the window
constexpr u64 IOREGSEL = 0x00, IOWIN = 0x10;
constexpr u32 IOAPIC_VERSION = 0x01, REDIRECTION = 0x10;
constexpr u32 RTE_ACTIVE_LOW = 1u << 13, RTE_LEVEL = 1u << 15, RTE_MASKED = 1u << 16;

u32 volatile* lapic = nullptr;
u32 volatile* ioapic = nullptr;
u32 gsiBase = 0, inputs = 0;
u8 apicId = 0;
bool on = false;
bool remapped = false;

Route routes[MAX_ROUTES];
u32 routeCount = 0;
// Which inputs feed each line, and how each input is set up.
struct Input {
    bool used = false;
    u8 line = 0;
    u32 low = 0, high = 0; // the redirection entry, unmasked form
};
Input table[MAX_INPUTS];

u32 lapicRead(u64 reg) { return lapic[reg / 4]; }
void lapicWrite(u64 reg, u32 value) { lapic[reg / 4] = value; }

u32 ioRead(u32 reg) {
    ioapic[IOREGSEL / 4] = reg;
    return ioapic[IOWIN / 4];
}
void ioWrite(u32 reg, u32 value) {
    ioapic[IOREGSEL / 4] = reg;
    ioapic[IOWIN / 4] = value;
}

void writeEntry(u32 input, u32 low, u32 high) {
    ioWrite(REDIRECTION + 2 * input, RTE_MASKED); // masked while it changes
    ioWrite(REDIRECTION + 2 * input + 1, high);
    ioWrite(REDIRECTION + 2 * input, low);
}

// One I/O APIC input feeding `line`. With remapping, the entry is in the
// remappable format, its index the input number. Interrupt distribution:
// the timer (line 0) goes to the boot CPU, which keeps the time; every other
// line goes to the next CPU in turn.
bool route(u32 gsi, u8 line, bool level, bool activeLow) {
    if (gsi < gsiBase or gsi - gsiBase >= inputs)
        return false;
    u32 input = gsi - gsiBase;
    u8 vector = static_cast<u8>(Pic::IRQ_BASE + line);
    u8 destination = line == 0 ? apicId : nextDestination();
    u32 low = vector | (level ? RTE_LEVEL : 0) | (activeLow ? RTE_ACTIVE_LOW : 0);
    u32 high;
    if (remapped) {
        if (not Iommu::remapIoapicPin(input, vector, level, destination))
            return false;
        // Remappable format: bit 48 set, the entry's index in bits 49-63 (and bit 11).
        low |= (input >> 15 & 1) << 11;
        high = 1u << 16 | (input & 0x7FFF) << 17;
    } else {
        high = static_cast<u32>(destination) << 24; // physical destination
    }
    table[input] = {true, line, low, high};
    writeEntry(input, low | RTE_MASKED, high);
    return true;
}

// What the PICs have unmasked now (from their mask registers).
bool picUnmasked(u8 line) {
    u8 mask = inb(line < 8 ? 0x21 : 0xA1);
    return not(mask & (1 << (line % 8)));
}

} // namespace

bool addRoute(Route const& r) {
    bool kernelLine = r.line == 0 or r.line == 1 or r.line == 2 or r.line == 8 or r.line == 12 or r.line == 13;
    if (routeCount == MAX_ROUTES or r.line >= 16 or kernelLine or r.gsi >= 256)
        return false;
    for (u32 i = 0; i < routeCount; i++) {
        if (routes[i].gsi == r.gsi)
            return true; // (functions sharing a pin report it more than once)
    }
    routes[routeCount++] = r;
    return true;
}

bool enable() {
    if (on)
        return true;
    auto const& m = Acpi::info().madt;
    if (not m.present or not m.ioApics or not m.localApic or not m.ioApic) {
        log("[apic] no MADT or I/O APIC: staying on the 8259 PICs");
        return false;
    }
    remapped = Iommu::remapsInterrupts();

    // The local APIC: on (IA32_APIC_BASE bit 11, then the spurious vector
    // register), all priorities accepted.
    if (not initLocal(true))
        return false;
    ioapic = static_cast<u32 volatile*>(Acpi::map(m.ioApic, 4096, Vmm::Cache::Uncached));
    gsiBase = m.ioApicGsiBase;
    inputs = ((ioRead(IOAPIC_VERSION) >> 16) & 0xFF) + 1;
    if (inputs > MAX_INPUTS)
        inputs = MAX_INPUTS;
    for (u32 i = 0; i < inputs; i++)
        writeEntry(i, RTE_MASKED, 0);

    // PCI devices first (their lines), then the ISA IRQs whose lines no PCI
    // route took. ISA defaults: edge-triggered, active high.
    bool lineTaken[16] = {};
    for (u32 i = 0; i < routeCount; i++) {
        if (not route(routes[i].gsi, routes[i].line, routes[i].level, routes[i].activeLow)) {
            log("[apic] can't route GSI ", routes[i].gsi, remapped ? " (no remapping entry for it)" : "",
                ": staying on the 8259 PICs");
            return false;
        }
        lineTaken[routes[i].line] = true;
    }
    for (u8 irq = 0; irq < 16; irq++) {
        if (irq == 2 or lineTaken[irq])
            continue; // (2: the PICs' cascade)
        u16 flags = m.isaFlags[irq];
        bool activeLow = (flags & 3) == 3, level = ((flags >> 2) & 3) == 3;
        if (not route(m.isaIrq[irq], irq, level, activeLow)) {
            log("[apic] can't route ISA IRQ ", irq, ": staying on the 8259 PICs");
            return false;
        }
    }

    // Hand over: the lines open on the PICs open on the I/O APIC, the
    // PICs close, the local APIC turns on.
    bool open[16];
    for (u8 line = 0; line < 16; line++)
        open[line] = line != 2 and picUnmasked(line);
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);
    lapicWrite(LAPIC_TPR, 0);
    lapicWrite(LAPIC_SVR, 0x100 | SPURIOUS_VECTOR);
    on = true;
    for (u8 line = 0; line < 16; line++) {
        if (open[line])
            unmask(line);
    }
    log("[apic] interrupts through the I/O APIC (", inputs, " inputs, ", routeCount, " PCI route(s)",
        remapped ? ", each through a VT-d remapping entry" : "", "); the 8259 PICs are masked");
    return true;
}

bool active() { return on; }

u8 localId() { return lapic ? static_cast<u8>(lapicRead(LAPIC_ID) >> 24) : apicId; }

bool initLocal(bool boot) {
    auto const& m = Acpi::info().madt;
    if (not m.present or not m.localApic)
        return false;
    writeMsr(Msr::APIC_BASE, readMsr(Msr::APIC_BASE) | (1u << 11));
    if (not lapic)
        lapic = static_cast<u32 volatile*>(Acpi::map(m.localApic, 4096, Vmm::Cache::Uncached));
    if (boot)
        apicId = static_cast<u8>(lapicRead(LAPIC_ID) >> 24);
    // Software-enabled, every priority accepted. On the boot CPU, LINT0 stays
    // the 8259s' way in (ExtINT) until the I/O APIC takes over; the other
    // CPUs take no ExtINT. LINT1 is NMI everywhere.
    lapicWrite(LAPIC_TPR, 0);
    lapicWrite(LAPIC_LVT_LINT0, boot ? LVT_EXTINT : LVT_MASKED);
    lapicWrite(LAPIC_LVT_LINT1, LVT_NMI);
    lapicWrite(LAPIC_SVR, 0x100 | SPURIOUS_VECTOR);
    return true;
}

void sendIpi(u8 destination, u8 vector) {
    while (lapicRead(LAPIC_ICR_LOW) & ICR_PENDING)
        asm volatile("pause");
    lapicWrite(LAPIC_ICR_HIGH, u32{destination} << 24);
    lapicWrite(LAPIC_ICR_LOW, vector); // fixed delivery, physical, edge
}

void sendInit(u8 destination) {
    lapicWrite(LAPIC_ICR_HIGH, u32{destination} << 24);
    lapicWrite(LAPIC_ICR_LOW, ICR_INIT | ICR_ASSERT | ICR_LEVEL);
    while (lapicRead(LAPIC_ICR_LOW) & ICR_PENDING)
        asm volatile("pause");
}

void sendStartup(u8 destination, u8 page) {
    lapicWrite(LAPIC_ICR_HIGH, u32{destination} << 24);
    lapicWrite(LAPIC_ICR_LOW, ICR_STARTUP | page);
    while (lapicRead(LAPIC_ICR_LOW) & ICR_PENDING)
        asm volatile("pause");
}

void localEndOfInterrupt() { lapicWrite(LAPIC_EOI, 0); }

u32 measureTimer(u64 tscHz) {
    // Counting down from the top for 10 ms of TSC.
    lapicWrite(LAPIC_TIMER_DIVIDE, 0x3); // divide by 16
    lapicWrite(LAPIC_LVT_TIMER, LVT_MASKED);
    lapicWrite(LAPIC_TIMER_INITIAL, 0xFFFFFFFF);
    u64 start = readTsc(), wait = tscHz / 100;
    while (readTsc() - start < wait)
        asm volatile("pause");
    u32 elapsed = 0xFFFFFFFF - lapicRead(LAPIC_TIMER_CURRENT);
    lapicWrite(LAPIC_TIMER_INITIAL, 0);
    return elapsed / 10; // per millisecond
}

void startTimer(u32 ticksPerMs, u8 vector) {
    lapicWrite(LAPIC_TIMER_DIVIDE, 0x3);
    lapicWrite(LAPIC_LVT_TIMER, LVT_PERIODIC | vector);
    lapicWrite(LAPIC_TIMER_INITIAL, ticksPerMs);
}

namespace {
u8 destinations[Acpi::Madt::MAX_CPUS];
u32 destinationCount = 0, nextOne = 0;
} // namespace

void addDestination(u8 id) {
    if (destinationCount < Acpi::Madt::MAX_CPUS)
        destinations[destinationCount++] = id;
}

u8 nextDestination() {
    if (not destinationCount)
        return apicId;
    return destinations[nextOne++ % destinationCount];
}

void mask(u8 line) {
    for (u32 i = 0; i < inputs; i++) {
        if (table[i].used and table[i].line == line)
            ioWrite(REDIRECTION + 2 * i, table[i].low | RTE_MASKED);
    }
}

void unmask(u8 line) {
    for (u32 i = 0; i < inputs; i++) {
        if (table[i].used and table[i].line == line)
            ioWrite(REDIRECTION + 2 * i, table[i].low);
    }
}

void endOfInterrupt() { lapicWrite(LAPIC_EOI, 0); }

} // namespace Rudracore::Arch::Apic

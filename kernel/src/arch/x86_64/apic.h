#pragma once

#include "types.h"

// The local APIC and the I/O APIC, replacing the legacy 8259 PICs once the
// acpi server has worked out PCI interrupt routing (_PRT). The kernel keeps
// thinking in IRQ lines 0-15 (vector 32 + line): every I/O APIC input
// (GSI) is routed to the line its device already uses, so drivers, IRQ
// objects and the timer don't change. ISA IRQs follow the MADT's overrides.
// With VT-d interrupt remapping on, each I/O APIC input goes through a
// remapping entry that only the I/O APIC (its requester id) may use.
namespace Rudracore::Arch::Apic {

constexpr u8 SPURIOUS_VECTOR = 0xFF;

// A PCI device's interrupt, as the firmware routes it in APIC mode.
struct Route {
    u32 gsi;
    u8 line;        // the IRQ line (vector 32 + line) it's delivered as
    bool level;     // level-triggered (PCI), else edge (ISA)
    bool activeLow;
};

// Adds a PCI route (from the acpi server). False if the table is full or
// the route is nonsense (no such I/O APIC input, a line the kernel owns).
bool addRoute(Route const& route);

// Switches to the APICs: ISA IRQs from the MADT plus the routes added; the
// lines unmasked on the PICs stay unmasked; then the PICs are masked. False
// (and still on the PICs) if there's no MADT/I/O APIC, or remapping is on
// but the I/O APIC's inputs can't be given entries.
bool enable();

bool active();

// This CPU's local APIC id (where interrupt messages go).
u8 localId();

// The local APIC of the CPU running this, software-enabled (the boot CPU
// keeps its LINT0 for the 8259s). False without a MADT.
bool initLocal(bool boot);

// Interprocessor interrupts, and starting another CPU (INIT, then STARTUP
// at physical page `page` << 12).
void sendIpi(u8 destination, u8 vector);
void sendInit(u8 destination);
void sendStartup(u8 destination, u8 page);
// End of an interrupt the local APIC raised itself (IPIs, its timer).
void localEndOfInterrupt();

// The local APIC timer: its rate (ticks per ms, measured with the TSC),
// and periodic interrupts at `vector`, one per millisecond.
u32 measureTimer(u64 tscHz);
void startTimer(u32 ticksPerMs, u8 vector);

// Interrupt distribution: CPUs that take device interrupts, in turn.
void addDestination(u8 apicId);
u8 nextDestination();

// While active: the PIC functions (Pic::mask, unmask, endOfInterrupt) come here.
void mask(u8 line);
void unmask(u8 line);
void endOfInterrupt();

} // namespace Rudracore::Arch::Apic

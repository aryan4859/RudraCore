#pragma once

#include "arch/x86_64/pci.h"

// Message-signalled interrupts: the device writes its interrupt to the local
// APIC instead of pulling a pin. The kernel programs the capability (MSI, or
// MSI-X entry 0) itself, so a driver never picks its own vector or target;
// with VT-d interrupt remapping the message goes through an entry only that
// device may use. Needs the APICs on (Apic::active()).
namespace Rudracore::Arch::Msi {

struct Vector {
    Pci::Address device{};
    u8 capability = 0;               // config-space offset of the MSI or MSI-X capability
    bool msix = false;
    bool maskable = false;           // per-vector mask (always for MSI-X)
    u32 volatile* entry = nullptr;   // MSI-X: table entry 0
    u32 remapIndex = 0;              // the VT-d entry, when remapping is on
};

// Points the device's first message at `vector` (prefers MSI, else MSI-X)
// and turns its INTx pin off. False if it has neither, or no APIC/entry.
bool enable(Pci::Address device, u8 vector, u32 remapIndex, Vector& out);

// Masks or unmasks the message; does nothing if the device can't.
void setMasked(Vector const& v, bool masked);

// Back to the INTx pin; the remapping entry is removed.
void disable(Vector const& v);

} // namespace Rudracore::Arch::Msi

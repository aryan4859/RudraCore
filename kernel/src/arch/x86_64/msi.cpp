#include "arch/x86_64/msi.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/apic.h"
#include "arch/x86_64/iommu.h"

namespace Rudracore::Arch::Msi {

namespace {

constexpr u8 CAP_MSI = 0x05, CAP_MSIX = 0x11;
constexpr u16 COMMAND_INTX_DISABLE = 1 << 10;
constexpr u16 MSI_ENABLE = 1 << 0, MSI_64BIT = 1 << 7, MSI_MASKABLE = 1 << 8, MSI_MULTIPLE = 7 << 4;
constexpr u16 MSIX_ENABLE = 1 << 15, MSIX_FUNCTION_MASK = 1 << 14;

u8 findCapability(Pci::Address d, u8 id) {
    if (not(Pci::read16(d, 0x06) & (1 << 4))) // no capability list
        return 0;
    u8 at = Pci::read32(d, 0x34) & 0xFC;
    for (u32 guard = 0; at and guard < 48; guard++) { // (a looped list ends too)
        u32 header = Pci::read32(d, at);
        if ((header & 0xFF) == id)
            return at;
        at = (header >> 8) & 0xFC;
    }
    return 0;
}

// The BAR's address straight from the register (no sizing: the device may be live).
u64 barAddress(Pci::Address d, u8 index) {
    u32 low = Pci::read32(d, static_cast<u8>(0x10 + 4 * index));
    if (low & 1)
        return 0; // I/O ports: no MSI-X table there
    u64 address = low & ~0xFu;
    if (((low >> 1) & 3) == 2 and index < 5)
        address |= u64{Pci::read32(d, static_cast<u8>(0x14 + 4 * index))} << 32;
    return address;
}

// Where and what the message writes: through VT-d entry `index` when
// remapping (remappable format: bit 4, the handle in bits 5-19 and 2),
// else straight to this CPU's local APIC, fixed delivery, edge.
bool message(Pci::Address d, u8 vector, u32 index, u32& address, u32& data) {
    if (Iommu::remapsInterrupts()) {
        if (not Iommu::remapMsi(index, d, vector, Apic::localId()))
            return false;
        address = 0xFEE00000 | (index & 0x7FFF) << 5 | 1 << 4 | ((index >> 15) & 1) << 2;
        data = 0;
    } else {
        address = 0xFEE00000 | u32{Apic::localId()} << 12;
        data = vector;
    }
    return true;
}

void setPin(Pci::Address d, bool on) {
    u16 command = Pci::read16(d, 0x04);
    Pci::write16(d, 0x04, static_cast<u16>(on ? command & ~COMMAND_INTX_DISABLE : command | COMMAND_INTX_DISABLE));
}

} // namespace

bool enable(Pci::Address d, u8 vector, u32 remapIndex, Vector& out) {
    if (not Apic::active() or Acpi::info().fadt.msiUnsupported)
        return false;
    out = {};
    out.device = d;
    out.remapIndex = remapIndex;
    u32 address, data;

    if (u8 cap = findCapability(d, CAP_MSI)) {
        u16 control = Pci::read16(d, cap + 2);
        Pci::write16(d, cap + 2, static_cast<u16>(control & ~MSI_ENABLE)); // off while it changes
        if (not message(d, vector, remapIndex, address, data))
            return false;
        bool wide = control & MSI_64BIT;
        out.capability = cap;
        out.maskable = control & MSI_MASKABLE;
        Pci::write32(d, cap + 4, address);
        if (wide)
            Pci::write32(d, cap + 8, 0);
        Pci::write16(d, static_cast<u8>(cap + (wide ? 12 : 8)), static_cast<u16>(data));
        if (out.maskable)
            Pci::write32(d, static_cast<u8>(cap + (wide ? 16 : 12)), 0);
        setPin(d, false);
        // One message (multiple-message enable 0), on.
        Pci::write16(d, cap + 2, static_cast<u16>((control & ~MSI_MULTIPLE) | MSI_ENABLE));
        return true;
    }

    if (u8 cap = findCapability(d, CAP_MSIX)) {
        u16 control = Pci::read16(d, cap + 2);
        u32 table = Pci::read32(d, cap + 4);
        u64 base = (table & 7) <= 5 ? barAddress(d, table & 7) : 0;
        if (not base)
            return false;
        Pci::write16(d, cap + 2, static_cast<u16>((control & ~MSIX_ENABLE) | MSIX_FUNCTION_MASK));
        if (not message(d, vector, remapIndex, address, data))
            return false;
        // The table is in device memory: memory decoding must be on to reach it.
        Pci::write16(d, 0x04, static_cast<u16>(Pci::read16(d, 0x04) | 2));
        out.entry = static_cast<u32 volatile*>(Acpi::map(base + (table & ~7u), 16, Vmm::Cache::Uncached));
        out.capability = cap;
        out.msix = out.maskable = true;
        // Entries other than 0 keep their reset state: masked.
        out.entry[3] = 1;
        out.entry[0] = address;
        out.entry[1] = 0;
        out.entry[2] = data;
        out.entry[3] = 0;
        setPin(d, false);
        Pci::write16(d, cap + 2, static_cast<u16>((control & ~MSIX_FUNCTION_MASK) | MSIX_ENABLE));
        return true;
    }
    return false;
}

void setMasked(Vector const& v, bool masked) {
    if (not v.maskable)
        return;
    if (v.msix) {
        v.entry[3] = masked ? 1 : 0;
        (void)v.entry[3]; // (the write reaches the device before we go on)
        return;
    }
    bool wide = Pci::read16(v.device, v.capability + 2) & MSI_64BIT;
    Pci::write32(v.device, static_cast<u8>(v.capability + (wide ? 16 : 12)), masked ? 1 : 0);
}

void disable(Vector const& v) {
    if (not v.capability)
        return;
    u16 control = Pci::read16(v.device, v.capability + 2);
    Pci::write16(v.device, v.capability + 2, static_cast<u16>(control & ~(v.msix ? MSIX_ENABLE : MSI_ENABLE)));
    if (v.msix)
        v.entry[3] = 1;
    setPin(v.device, true);
    Iommu::removeEntry(v.remapIndex);
}

} // namespace Rudracore::Arch::Msi

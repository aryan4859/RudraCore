#pragma once

#include "boot.h"

// UEFI runtime services, for one job: the boot-attempt counter
// (abi/shool/boot.h). ShoolLoader counts each start of a boot entry in a
// UEFI variable; once the system is up, it's deleted from here, so an
// entry whose kernel crashes or hangs after the hand-over is passed over
// for its fallback after a few tries.
//
// The firmware runs at its physical addresses (no SetVirtualAddressMap):
// its runtime regions are identity-mapped in the kernel's own address space
// (lower half, otherwise empty), and each call switches to that space, to a
// stack of its own, with interrupts off and the FPU state saved. A fault in
// the firmware is caught and the call fails instead of the kernel.
namespace Rudracore::Arch {
struct Frame;
}

namespace Rudracore::Arch::Efi {

// Checks the runtime services table (signature, functions inside runtime
// code) and maps the regions. Logs whether the counter can be cleared.
void init(Boot::Info const& info);

bool available();

// Deletes the boot-attempt counter (nothing is written when there's none).
// False, with `why` set, if it couldn't.
bool clearBootCount(char const*& why);

// For the exception handler: true (and the frame redirected so the call
// returns failure) if the fault happened inside a firmware call.
bool recoverFault(Frame& frame);

} // namespace Rudracore::Arch::Efi

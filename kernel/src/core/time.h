#pragma once

#include "types.h"

namespace Rudracore::Time {

constexpr u32 TICKS_PER_SECOND = 1000;

// Starts the system timer (IRQ 0). Interrupts must be enabled separately.
void init();

// Called from the timer interrupt.
void tick();

// Milliseconds since the timer started.
u64 now();

// Nanoseconds since the timer started: the TSC (calibrated at boot; the
// same on every CPU), else milliseconds scaled. For measuring, not waking.
u64 nanoseconds();

// TSC cycles as nanoseconds (0 if the TSC rate is unknown).
u64 cyclesToNs(u64 cycles);

// Seconds since 1970-01-01 (UTC), from the hardware clock read at boot.
u64 unixTime();

// Seconds since midnight (UTC).
u64 timeOfDay();

} // namespace Rudracore::Time

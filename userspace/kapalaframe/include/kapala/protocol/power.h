#pragma once

// Kapalaframe: the power protocol, between KamalShell and the acpi server
// (init connects the two). The shell asks; the server reads the batteries,
// AC adapter and thermal zones through the firmware's AML and answers.
//
//   shell                       acpi
//   Request{Status}          ->
//                            <- Status
//   Request{PowerOff}        ->    (S5 the ACPI way: _PTS, then the sleep registers)

namespace Kapala::Protocol::Power {

enum class Op : unsigned char {
    Status = 1,
    PowerOff = 2,
};

struct Request {
    Op op;
};

constexpr unsigned char UNKNOWN_PERCENT = 255;
constexpr short UNKNOWN_TEMPERATURE = -32768;

struct Status {
    unsigned char batteries;   // present batteries (PNP0C0A, _STA)
    unsigned char percent;     // charge of all of them together, 0-100 (UNKNOWN_PERCENT)
    bool charging;
    bool discharging;
    bool critical;             // a battery says its charge is critical
    signed char ac;            // AC adapter: 1 online, 0 offline, -1 none
    unsigned char thermalZones;
    short temperature;         // the hottest zone, tenths of a degree Celsius (UNKNOWN_TEMPERATURE)
    short criticalTemperature; // its _CRT, the same way
    unsigned powerButtonPresses; // since boot (the shell may ask the user first)
    unsigned char performance;   // the CPU cap passive cooling set, percent (100: not throttled)
};

static_assert(sizeof(Status) <= 128, "must fit in a channel message");

} // namespace Kapala::Protocol::Power

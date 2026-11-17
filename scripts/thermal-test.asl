/*
 * A test SSDT for the thermal policy (`make shot THERMAL_TEST=1`): one
 * thermal zone whose temperature follows a script, one step per reading.
 * It warms past passive (70 C), cools back below it, then climbs past hot
 * (85 C) to critical (90 C). Expected: passive cooling caps the CPU, lifts
 * the cap as it cools, logs hot, then turns the machine off at critical.
 */
DefinitionBlock ("", "SSDT", 2, "BHAIRV", "THRMTEST", 1)
{
    Scope (\_TZ)
    {
        ThermalZone (TZ0)
        {
            // Tenths of a degree Celsius.
            Name (SEQ, Package () {
                600, 650, 700, 730, 760, 740, 710, 680, 650, 620, 600, 600,
                650, 700, 760, 820, 860, 880, 910, 910
            })
            Name (STEP, Zero)
            Method (_TMP, 0, Serialized)
            {
                Local0 = DerefOf (SEQ [STEP])
                If (STEP < (SizeOf (SEQ) - One)) { STEP++ }
                Return (Local0 + 2732) // tenths of a kelvin
            }
            Method (_PSV, 0, Serialized) { Return (3432) } // 70.0 C
            Method (_HOT, 0, Serialized) { Return (3582) } // 85.0 C
            Method (_CRT, 0, Serialized) { Return (3632) } // 90.0 C
            Name (_TC1, 2)
            Name (_TC2, 5)
            Name (_TSP, 10) // sample every 1.0 s while cooling
            Name (_TZP, 20) // poll every 2.0 s otherwise
        }
    }
}

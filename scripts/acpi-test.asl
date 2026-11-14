/*
 * A test SSDT for QEMU, which has no battery, AC adapter or thermal zone:
 * one of each, with fixed readings, so the acpi server and KamalShell's
 * top bar can be checked. Used by `make shot ACPI_TEST=1` (see Makefile):
 * the battery is charging at 75% (36000 of 48000 mWh), the AC adapter is
 * online, and the thermal zone reads 45.0 C with 100.0 C as critical.
 */
DefinitionBlock ("", "SSDT", 2, "BHAIRV", "ACPITEST", 1)
{
    Scope (\_SB)
    {
        Device (BAT0)
        {
            Name (_HID, EisaId ("PNP0C0A"))
            Name (_UID, One)
            Method (_STA, 0, NotSerialized) { Return (0x1F) }
            // _BIF: power unit (0: mWh), design capacity, last full capacity,
            // technology, design voltage, warning, low, granularity x2, model,
            // serial, type, OEM.
            Method (_BIF, 0, NotSerialized)
            {
                Return (Package () { Zero, 50000, 48000, One, 11100, 2400, 1200, 10, 10,
                                     "BHAIRAV-TEST", "1", "LION", "Bhairav" })
            }
            // _BST: state (bit 1: charging), present rate, remaining capacity, voltage.
            Method (_BST, 0, NotSerialized) { Return (Package () { 2, 1500, 36000, 11400 }) }
        }

        Device (ADP0)
        {
            Name (_HID, "ACPI0003")
            Method (_STA, 0, NotSerialized) { Return (0x0F) }
            Method (_PSR, 0, NotSerialized) { Return (One) }
        }
    }

    Scope (\_TZ)
    {
        ThermalZone (TZ0)
        {
            Method (_TMP, 0, Serialized) { Return (3182) } // tenths of a kelvin: 45.0 C
            Method (_CRT, 0, Serialized) { Return (3732) } // 100.0 C
        }
    }
}

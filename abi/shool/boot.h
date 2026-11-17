#pragma once

// The Shool boot protocol: how ShoolLoader🔱 hands over to RudraCore.
//
// Shared by the loader (built as a UEFI program, where `long` is 32 bits)
// and the kernel (where it's 64 bits), so only fixed-size types are used
// and the layout is checked below.
//
// Machine state when the kernel's ELF entry point runs:
//   - 64-bit mode, interrupts disabled, UEFI boot services exited
//   - rdi = SHOOL_MAGIC, rsi = pointer to BootInfo (in the direct map)
//   - paging on, with the loader's page tables:
//       * the kernel image at its ELF virtual addresses
//       * all memory regions mapped at HHDM_OFFSET + physical (direct map)
//         and at their physical address (identity map, for the hand-over)
//   - rsp on a 64 KiB stack in LoaderReclaimable memory
//   - EFER.NXE and CR0.WP enabled; PAT entries: 0 WB, 1 WT, 2 UC-, 3 UC,
//     4 WP, 5 WC (same layout as the Limine protocol)
//
// The page tables, stack and BootInfo are LoaderReclaimable: the kernel
// must copy what it needs and switch to its own page tables and stack
// before reusing that memory.

#include <stdint.h>

namespace Shool {

constexpr uint64_t MAGIC = 0x44414f4c4f4f4853; // "SHOOLOAD" in memory
constexpr uint64_t HHDM_OFFSET = 0xffff800000000000;

// Versioning: VERSION changes whenever BootInfo's layout or meaning does.
// The kernel says which versions it takes in a KernelHeader in its image;
// ShoolLoader refuses (on screen, before handing over) a kernel that can't
// take its VERSION, and the kernel checks BootInfo.version and .size again.
//   1: first version
//   2: BootInfo.flags (verified boot, Secure Boot, diagnostic mode)
//   3: BootInfo.mode (normal, safe, recovery)
//   4: BootInfo.efiRuntime and the EFI runtime region types (the boot-attempt
//      counter is cleared through UEFI variables). v3 is still spoken to a
//      kernel that takes at most v3: then BootInfo ends before efiRuntime
//      (size V3_SIZE) and the new region types read as reserved.
constexpr uint32_t VERSION = 4;
constexpr uint32_t MIN_VERSION = 3; // the oldest the loader still speaks

// What the chosen boot entry asks of the system (BootInfo.mode).
enum BootMode : uint32_t {
    MODE_NORMAL = 0,
    MODE_SAFE = 1,     // known-good minimum: no network, no third-party apps, no self-tests
    MODE_RECOVERY = 2, // repair: no third-party apps, network on, a Terminal opens
};

// Placed in the kernel image (8-byte aligned, in a loaded segment), where
// ShoolLoader finds it by scanning the kernel file.
struct KernelHeader {
    uint64_t magic; // KERNEL_MAGIC
    uint64_t check; // ~KERNEL_MAGIC (so a stray copy of the magic isn't taken for one)
    uint32_t minVersion;
    uint32_t maxVersion;
};
constexpr uint64_t KERNEL_MAGIC = 0x4e524b4c4f4f4853; // "SHOOLKRN" in memory

enum Flags : uint32_t {
    FLAG_VERIFIED_BOOT = 1 << 0, // every file came from the signed list (shool.sum)
    FLAG_SECURE_BOOT = 1 << 1,   // UEFI Secure Boot was on (so the loader itself was checked)
    FLAG_DIAGNOSTIC = 1 << 2,    // diagnostic boot: log everything about the boot
};

enum RegionType : uint32_t {
    REGION_USABLE = 0,
    REGION_RESERVED = 1,
    REGION_ACPI_RECLAIMABLE = 2,
    REGION_ACPI_NVS = 3,
    REGION_BAD_MEMORY = 4,
    REGION_LOADER_RECLAIMABLE = 5, // page tables, stack, BootInfo
    REGION_KERNEL = 6,             // the kernel image and modules
    REGION_FRAMEBUFFER = 7,
    REGION_EFI_RUNTIME = 8,      // v4: UEFI runtime services code and data (RAM)
    REGION_EFI_RUNTIME_MMIO = 9, // v4: device registers the runtime services use
};

// The boot-attempt counter (UEFI variable "BhairavBootCount", non-volatile,
// boot and runtime access, vendor BOOT_COUNT_VENDOR). ShoolLoader adds one
// to the started entry's count just before handing over; the running system
// deletes the variable once it's up (SYS_BOOT_COMPLETE). An entry whose count
// reaches BOOT_ATTEMPTS_LIMIT is skipped for its fallback, unless picked in
// the menu. `configHash` ties the counts to the entry list they were made for.
struct BootCount {
    uint32_t magic;      // BOOT_COUNT_MAGIC
    uint32_t configHash; // FNV-1a of the entry names, in order
    uint8_t attempts[8]; // per entry, in shool.cfg order
};
constexpr uint32_t BOOT_COUNT_MAGIC = 0x544E4342; // "BCNT"
constexpr uint8_t BOOT_ATTEMPTS_LIMIT = 2;
constexpr char16_t BOOT_COUNT_NAME[] = u"BhairavBootCount";
struct BootCountVendor {
    uint32_t data1;
    uint16_t data2, data3;
    uint8_t data4[8];
};
constexpr BootCountVendor BOOT_COUNT_VENDOR = {0x3b8d4c6e, 0x1f2a, 0x4d5b, {0x9c, 0x7e, 0x8a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f}};

struct MemoryRegion {
    uint64_t base;
    uint64_t length;
    uint32_t type; // RegionType
    uint32_t reserved;
};

struct Framebuffer {
    uint64_t physical; // 0 if there's no framebuffer
    uint64_t width;
    uint64_t height;
    uint64_t pitch; // bytes per row
    uint16_t bpp;   // always 32 when present
    uint8_t redShift;
    uint8_t greenShift;
    uint8_t blueShift;
    uint8_t reserved[3];
};

// A file loaded next to the kernel (a program for the boot image).
struct Module {
    uint64_t physical;
    uint64_t size;
    char name[32]; // file name without directory or extension
};

struct BootInfo {
    static constexpr uint32_t MAX_REGIONS = 256;
    static constexpr uint32_t MAX_MODULES = 32;

    uint64_t magic; // MAGIC
    uint32_t version;
    uint32_t size; // sizeof(BootInfo)

    char loaderName[32];
    char loaderVersion[16];

    uint32_t flags; // Flags
    uint32_t mode;  // BootMode

    uint64_t hhdmOffset;
    uint64_t kernelPhysical; // where the kernel's lowest segment was loaded
    uint64_t kernelVirtual;  // its virtual address
    uint64_t acpiRsdp;       // physical address of the ACPI RSDP, or 0

    Framebuffer framebuffer;

    uint64_t regionCount;
    MemoryRegion regions[MAX_REGIONS];

    uint64_t moduleCount;
    Module modules[MAX_MODULES];

    // v4 from here on.
    uint64_t efiRuntime; // physical address of the UEFI runtime services table, or 0
};

constexpr uint32_t V3_SIZE = __builtin_offsetof(BootInfo, efiRuntime);

static_assert(sizeof(BootCount) == 16);
static_assert(sizeof(MemoryRegion) == 24);
static_assert(sizeof(Framebuffer) == 40);
static_assert(sizeof(Module) == 48);
static_assert(sizeof(KernelHeader) == 24);
static_assert(V3_SIZE == 16 + 48 + 8 + 32 + 40 + 8 + 24 * 256 + 8 + 48 * 32);
static_assert(sizeof(BootInfo) == V3_SIZE + 8);

} // namespace Shool

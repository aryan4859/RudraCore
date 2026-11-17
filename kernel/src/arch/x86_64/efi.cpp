#include "arch/x86_64/efi.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/frame.h"
#include "arch/x86_64/idt.h"
#include "log.h"
#include "mem/memory.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "panic.h"

#include <shool/boot.h>

// The firmware call: Microsoft ABI (rcx, rdx, r8, r9, then the stack after
// 32 bytes of shadow space), on the firmware stack. efiCallFault is where
// a caught fault resumes: the call then returns FAULTED.
extern "C" {
u64 efiSavedRsp = 0;
u64 efiStackTop = 0;
u64 efiCall(u64 function, u64 a, u64 b, u64 c, u64 d, u64 e);
extern char const efiCallFault[];
// Self-test targets: a + 2b + 3c + 4d + 5e (Microsoft ABI), and a fault.
extern char const efiTestAdd[], efiTestFault[];
}

asm(R"(
    .text
    .globl efiCall
efiCall:
    push %rbp
    mov %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, efiSavedRsp(%rip)
    mov efiStackTop(%rip), %rsp
    mov %rdi, %rax
    mov %r9, %r10
    mov %rcx, %r11
    mov %rsi, %rcx
    mov %r8, %r9
    mov %r11, %r8
    sub $48, %rsp
    mov %r10, 32(%rsp)
    cld
    call *%rax
efiCallReturn:
    mov efiSavedRsp(%rip), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
    .globl efiCallFault
efiCallFault:
    movabs $0x80000000000000FF, %rax
    jmp efiCallReturn

    .globl efiTestAdd
efiTestAdd:
    lea (%rcx,%rdx,2), %rax
    lea (%r8,%r8,2), %r10
    add %r10, %rax
    lea (%rax,%r9,4), %rax
    mov 40(%rsp), %r10
    lea (%r10,%r10,4), %r10
    add %r10, %rax
    ret
    .globl efiTestFault
efiTestFault:
    ud2
)");

namespace Rudracore::Arch::Efi {

namespace {

constexpr u64 FAULTED = 0x80000000000000FF;
constexpr u64 NOT_FOUND = (1ull << 63) | 14;
constexpr u64 RUNTIME_SIGNATURE = 0x56524553544E5552; // "RUNTSERV"
constexpr u32 VARIABLE_ATTRIBUTES = 1 | 2 | 4;        // non-volatile, boot and runtime access
constexpr u64 STACK_PAGES = 16;                       // 64 KiB

bool ready = false;
bool inCall = false;
u64 getVariable = 0, setVariable = 0; // physical: the firmware runs at its own addresses

u64 call(u64 function, u64 a, u64 b, u64 c, u64 d, u64 e) {
    InterruptGuard guard;
    // The firmware may use SSE: whatever task is current keeps its registers.
    alignas(16) static u8 fpu[512];
    asm volatile("fxsave (%0)" : : "r"(fpu) : "memory");
    u32 mxcsr = 0x1F80;
    asm volatile("fninit; ldmxcsr %0" : : "m"(mxcsr)); // the state UEFI promises its code
    u64 space = readCr3();
    writeCr3(Vmm::kernelSpace().root);
    inCall = true;
    u64 status = efiCall(function, a, b, c, d, e);
    inCall = false;
    writeCr3(space);
    asm volatile("fxrstor (%0)" : : "r"(fpu) : "memory");
    return status;
}

bool within(Boot::Info const& info, u64 address, u64 length, Boot::RegionType type) {
    for (usize i = 0; i < info.regionCount; i++) {
        auto const& r = info.regions[i];
        if (r.type == type and address >= r.base and address - r.base <= r.length and length <= r.length - (address - r.base))
            return true;
    }
    return false;
}

// The trampoline itself: arguments in the right registers, the stack
// switch, and a fault caught. Runs every boot (the stack is all it needs).
void selfTest() {
    u64 sum = call(reinterpret_cast<u64>(efiTestAdd), 1, 10, 100, 1000, 10000);
    if (sum != 1 + 20 + 300 + 4000 + 50000)
        panic("selftest: the firmware call passes its arguments wrongly");
    if (call(reinterpret_cast<u64>(efiTestFault), 0, 0, 0, 0, 0) != FAULTED)
        panic("selftest: a fault inside a firmware call wasn't caught");
}

} // namespace

void init(Boot::Info const& info) {
    u64 stack = Pmm::alloc(STACK_PAGES);
    if (not stack) {
        log("[efi]  no memory for the firmware's stack: boot attempts can't be cleared");
        return;
    }
    efiStackTop = reinterpret_cast<u64>(Mem::toVirtual<u8>(stack)) + STACK_PAGES * Mem::PAGE_SIZE;
    selfTest();

    if (not info.efiRuntime) {
        log("[efi]  no UEFI runtime services (BIOS boot or an older loader): boot attempts aren't counted");
        return;
    }
    // Trust boundary: the table and both functions must be runtime memory.
    if (not within(info, info.efiRuntime, 96, Boot::RegionType::EfiRuntime)) {
        log("[efi]  the runtime services table isn't in runtime memory: not used");
        return;
    }
    auto const* table = static_cast<u8 const*>(Acpi::map(info.efiRuntime, 96, Vmm::Cache::WriteBack));
    u64 signature = *reinterpret_cast<u64 const*>(table);
    u32 headerSize = *reinterpret_cast<u32 const*>(table + 12);
    getVariable = *reinterpret_cast<u64 const*>(table + 72);
    setVariable = *reinterpret_cast<u64 const*>(table + 88);
    if (signature != RUNTIME_SIGNATURE or headerSize < 96 or
        not within(info, getVariable, 1, Boot::RegionType::EfiRuntime) or
        not within(info, setVariable, 1, Boot::RegionType::EfiRuntime)) {
        log("[efi]  the runtime services table is damaged: not used");
        return;
    }

    // The regions the firmware may touch, at their own addresses, in the
    // kernel's otherwise empty lower half (user spaces never see them).
    usize mapped = 0;
    for (usize i = 0; i < info.regionCount; i++) {
        auto const& r = info.regions[i];
        bool mmio = r.type == Boot::RegionType::EfiRuntimeMmio;
        if (not mmio and r.type != Boot::RegionType::EfiRuntime and r.type != Boot::RegionType::AcpiNvs)
            continue;
        u64 base = Mem::alignDown(r.base, Mem::PAGE_SIZE), end = Mem::alignUp(r.base + r.length, Mem::PAGE_SIZE);
        if (end > Vmm::USER_END or
            not Vmm::kernelSpace().map(base, base, end - base, mmio ? Vmm::WRITE : Vmm::WRITE | Vmm::EXEC,
                                       mmio ? Vmm::Cache::Uncached : Vmm::Cache::WriteBack)) {
            log("[efi]  can't map the firmware's region at ", Hex{r.base}, ": runtime services not used");
            return;
        }
        mapped++;
    }
    ready = true;
    log("[efi]  UEFI runtime services: ", mapped, " region(s) mapped at their own addresses; boot attempts are counted");
}

bool available() { return ready; }

bool clearBootCount(char const*& why) {
    if (not ready) {
        why = "no usable UEFI runtime services";
        return false;
    }
    auto name = reinterpret_cast<u64>(Shool::BOOT_COUNT_NAME);
    auto vendor = reinterpret_cast<u64>(&Shool::BOOT_COUNT_VENDOR);
    // Read first: nothing is written to the flash when there's no counter.
    Shool::BootCount data{};
    u64 size = sizeof(data);
    u32 attributes = 0;
    u64 status = call(getVariable, name, vendor, reinterpret_cast<u64>(&attributes), reinterpret_cast<u64>(&size),
                      reinterpret_cast<u64>(&data));
    if (status == NOT_FOUND)
        return true;
    if (status != FAULTED)
        status = call(setVariable, name, vendor, VARIABLE_ATTRIBUTES, 0, 0); // size 0: delete
    if (status == 0 or status == NOT_FOUND)
        return true;
    why = status == FAULTED ? "the firmware faulted (see above)" : "the firmware refused to delete the variable";
    return false;
}

bool recoverFault(Frame& frame) {
    constexpr u64 NMI = 2;
    if (not inCall or frame.vector >= 32 or frame.vector == NMI or (frame.cs & 3))
        return false;
    if (frame.rip == reinterpret_cast<u64>(efiTestFault)) {
        // (the self-test's fault: expected, not logged)
    } else if (frame.vector == 14) {
        log("[efi]  the firmware faulted: page fault at ", Hex{frame.rip}, ", address ", Hex{readCr2()});
    } else {
        log("[efi]  the firmware faulted: ", Idt::exceptionName(frame.vector), " at ", Hex{frame.rip});
    }
    frame.rip = reinterpret_cast<u64>(efiCallFault);
    frame.rsp = efiStackTop - 64; // (efiCallFault goes back to the caller's own stack)
    return true;
}

} // namespace Rudracore::Arch::Efi

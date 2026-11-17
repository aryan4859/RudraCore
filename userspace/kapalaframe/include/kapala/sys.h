#pragma once

// Kapalaframe: system call wrappers for Bhairav OS programs.
// See abi/rudracore/syscalls.h for what each call does.

#include <rudracore/syscalls.h>

// Every program's entry point, called by the Kapalaframe runtime. In a
// freestanding build main isn't special, so give it C linkage here.
extern "C" int main();

namespace Kapala::Sys {

using namespace Rudracore::Abi;

inline long syscall(unsigned long number, unsigned long a = 0, unsigned long b = 0,
                    unsigned long c = 0, unsigned long d = 0, unsigned long e = 0) {
    long result;
    register unsigned long r10 asm("r10") = d;
    register unsigned long r8 asm("r8") = e;
    asm volatile("int $0x80"
                 : "=a"(result)
                 : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                 : "memory");
    return result;
}

template <typename T>
inline unsigned long arg(T* pointer) { return reinterpret_cast<unsigned long>(pointer); }

inline unsigned long length(char const* text) {
    unsigned long n = 0;
    while (text[n])
        n++;
    return n;
}

// MARK: Tasks

inline long log(char const* text, unsigned long len) { return syscall(SYS_LOG, arg(text), len); }
inline long log(char const* text) { return log(text, length(text)); }

[[noreturn]] inline void exit(long code) {
    syscall(SYS_EXIT, static_cast<unsigned long>(code));
    __builtin_unreachable();
}

inline void yield() { syscall(SYS_YIELD); }
inline void sleep(unsigned long milliseconds) { syscall(SYS_SLEEP, milliseconds); }
inline unsigned long taskId() { return static_cast<unsigned long>(syscall(SYS_TASK_ID)); }
inline unsigned long timeMs() { return static_cast<unsigned long>(syscall(SYS_TIME)); }

// Starts a program from the boot image; `handles` move to it (as its
// handles 1, 2, 3...). Returns its task id, or a negative Error.
inline long spawn(char const* name, Handle const* handles = nullptr, unsigned long count = 0) {
    return syscall(SYS_SPAWN, arg(name), length(name), arg(handles), count);
}

inline long systemInfo(SystemInfo& out) { return syscall(SYS_SYSTEM_INFO, arg(&out)); }

// MARK: Threads and processes (most code uses Kapala::Thread instead)

inline long threadCreate(void (*entry)(void*), void* stackTop, void* argument, void* tls) {
    return syscall(SYS_THREAD_CREATE, reinterpret_cast<unsigned long>(entry), arg(stackTop), arg(argument), arg(tls));
}
[[noreturn]] inline void threadExit(long code) {
    syscall(SYS_THREAD_EXIT, static_cast<unsigned long>(code));
    __builtin_unreachable();
}
inline unsigned long threadId() { return static_cast<unsigned long>(syscall(SYS_THREAD_ID)); }
inline long threadJoin(unsigned long thread, long* code = nullptr, unsigned long timeoutMs = WAIT_FOREVER) {
    return syscall(SYS_THREAD_JOIN, thread, arg(code), timeoutMs);
}
inline long threadSetTls(void* base) { return syscall(SYS_THREAD_SET_TLS, arg(base)); }
inline long futexWait(unsigned* word, unsigned expected, unsigned long timeoutMs = WAIT_FOREVER) {
    return syscall(SYS_FUTEX_WAIT, arg(word), expected, timeoutMs);
}
inline long futexWake(unsigned* word, unsigned long count) { return syscall(SYS_FUTEX_WAKE, arg(word), count); }

// Like spawn, with SPAWN_* flags (SPAWN_HANDLE: a process handle comes back).
inline long spawnWith(char const* name, Handle const* handles, unsigned long count, unsigned long flags) {
    return syscall(SYS_SPAWN, arg(name), length(name), arg(handles), count, flags);
}
inline long processWait(Handle process, long* code = nullptr, unsigned long timeoutMs = WAIT_FOREVER) {
    return syscall(SYS_PROCESS_WAIT, process, arg(code), timeoutMs);
}
inline long processSignal(Handle process, unsigned long signal, unsigned long flags = 0) {
    return syscall(SYS_PROCESS_SIGNAL, process, signal, flags);
}
inline long processLimit(Handle process, unsigned long limit, unsigned long value) {
    return syscall(SYS_PROCESS_LIMIT, process, limit, value);
}
inline long processEvents(Handle endpoint) { return syscall(SYS_PROCESS_EVENTS, endpoint); }
inline long processInfo(Handle process, ProcessInfo& out) { return syscall(SYS_PROCESS_INFO, process, arg(&out)); }

// Nanoseconds since boot, for measuring.
inline unsigned long timeNs() { return static_cast<unsigned long>(syscall(SYS_TIME_NS)); }
inline long kernelCounters(KernelCounters& out) { return syscall(SYS_KERNEL_COUNTERS, arg(&out)); }

// Every process (up to `capacity` written): returns how many there are.
inline long taskList(TaskInfo* out, unsigned long capacity) { return syscall(SYS_TASK_LIST, arg(out), capacity); }

inline long kernelStats(KernelStats& out) { return syscall(SYS_KERNEL_STATS, arg(&out)); }

// Starts a program from an ELF file in shared memory (see SpawnImage).
inline long spawnImage(SpawnImage const& request) { return syscall(SYS_SPAWN_IMAGE, arg(&request)); }

// Fills `out` with random bytes from the kernel (any length).
inline long random(void* out, unsigned long length) {
    auto* p = static_cast<unsigned char*>(out);
    while (length) {
        unsigned long n = length < 256 ? length : 256;
        long r = syscall(SYS_RANDOM, arg(p), n);
        if (r < 0)
            return r;
        p += n;
        length -= n;
    }
    return OK;
}

// MARK: Handles and channels

inline long close(Handle handle) { return syscall(SYS_HANDLE_CLOSE, handle); }

// A second handle to the same object, with `rights` (Rights) but never more
// than this one has. E.g. duplicate(end, RIGHT_WRITE) is a send-only channel.
inline long duplicate(Handle handle, unsigned long rights) { return syscall(SYS_HANDLE_DUPLICATE, handle, rights); }

// Drops every right not in `rights`. Rights never come back.
inline long restrictRights(Handle handle, unsigned long rights) { return syscall(SYS_HANDLE_RESTRICT, handle, rights); }

// Cuts off every other handle to this object, in every program.
inline long revoke(Handle handle) { return syscall(SYS_HANDLE_REVOKE, handle); }

// The handle's rights, or an error.
inline long rights(Handle handle) { return syscall(SYS_HANDLE_RIGHTS, handle); }

inline long channelCreate(Handle& a, Handle& b) {
    Handle pair[2] = {};
    long result = syscall(SYS_CHANNEL_CREATE, arg(pair));
    a = pair[0];
    b = pair[1];
    return result;
}

inline long send(Handle endpoint, void const* data, unsigned long size, Handle attach = NO_HANDLE) {
    return syscall(SYS_CHANNEL_SEND, endpoint, arg(data), size, attach);
}

// Returns the message size; `attached` gets a handle that came with it, or NO_HANDLE.
inline long recv(Handle endpoint, void* buffer, unsigned long capacity,
                 Handle* attached = nullptr, unsigned long flags = 0) {
    return syscall(SYS_CHANNEL_RECV, endpoint, arg(buffer), capacity, arg(attached), flags);
}

// Waits until one of `endpoints` has a message (or its peer closed), or the
// timeout passes. Returns the index of a ready endpoint, or TIMED_OUT.
inline long wait(Handle const* endpoints, unsigned long count, unsigned long timeoutMs = WAIT_FOREVER) {
    return syscall(SYS_WAIT, arg(endpoints), count, timeoutMs);
}

// MARK: Memory

// flags: MEMORY_BELOW_4G for a device that only reaches the first 4 GiB.
inline long memoryCreate(unsigned long size, unsigned long flags = 0) { return syscall(SYS_MEMORY_CREATE, size, flags); }

// Removes a region (from memoryMap or memoryAlloc); private memory is freed.
inline long memoryUnmap(void const* address) { return syscall(SYS_MEMORY_UNMAP, arg(address)); }

// Returns the address, or nullptr on failure. flags: MAP_COPY (a private
// copy-on-write view), MAP_READ_ONLY.
inline void* memoryMap(Handle memory, unsigned long flags = 0) {
    long result = syscall(SYS_MEMORY_MAP, memory, flags);
    return result < 0 ? nullptr : reinterpret_cast<void*>(result);
}

// A region (its address) becomes read-only, or writable again.
inline long memoryProtect(void const* address, bool writable) {
    return syscall(SYS_MEMORY_PROTECT, arg(address), writable ? 1 : 0);
}

// Its contents never change again, for anyone (see SYS_MEMORY_SEAL).
inline long memorySeal(Handle memory) { return syscall(SYS_MEMORY_SEAL, memory); }

inline long memoryInfo(Handle memory, MemoryInfo& out) { return syscall(SYS_MEMORY_INFO, memory, arg(&out)); }

// Pagers (the fs server, for memory-mapped files).
inline long memoryCreatePaged(unsigned long size, Handle pagerEnd) {
    return syscall(SYS_MEMORY_CREATE_PAGED, size, pagerEnd);
}
inline long memorySupply(Handle pagerEnd, unsigned long offset, void const* data, unsigned long length) {
    return syscall(SYS_MEMORY_SUPPLY, pagerEnd, offset, arg(data), length);
}

// Fresh zeroed private memory, or nullptr. (Most code uses `new` instead.)
inline void* memoryAlloc(unsigned long size) {
    long result = syscall(SYS_MEMORY_ALLOC, size);
    return result < 0 ? nullptr : reinterpret_cast<void*>(result);
}

// A data file from the boot image (e.g. "fonts"), mapped read-only, or nullptr.
inline void const* openFile(char const* name) {
    long handle = syscall(SYS_FILE_OPEN, arg(name), length(name));
    if (handle < 0)
        return nullptr;
    void* address = memoryMap(static_cast<Handle>(handle));
    syscall(SYS_HANDLE_CLOSE, static_cast<unsigned long>(handle)); // the mapping keeps it
    return address;
}

// MARK: Devices

inline long irqWait(Handle irq) { return syscall(SYS_IRQ_WAIT, irq); }

// Each interrupt now arrives as an IrqMessage{cookie} on the peer of `endpoint`.
inline long irqBind(Handle irq, Handle endpoint, unsigned long cookie) {
    return syscall(SYS_IRQ_BIND, irq, endpoint, cookie);
}

inline long irqAck(Handle irq) { return syscall(SYS_IRQ_ACK, irq); }

inline long portIn(Handle ports, unsigned short port) { return syscall(SYS_PORT_IN, ports, port); }

inline long portOut(Handle ports, unsigned short port, unsigned char value) {
    return syscall(SYS_PORT_OUT, ports, port, value);
}

inline long deviceInfo(Handle device, DeviceInfo& out) { return syscall(SYS_DEVICE_INFO, device, arg(&out)); }

// Returns a shared memory handle for memory BAR `index`, or a negative Error.
inline long deviceBar(Handle device, unsigned long index) { return syscall(SYS_DEVICE_BAR, device, index); }

// A handle to the device's message-signalled interrupt (MSI/MSI-X), used like
// any IRQ handle, or a negative Error (NOT_FOUND: no MSI here; use the pin).
inline long deviceMsi(Handle device) { return syscall(SYS_DEVICE_MSI, device); }

// Physical address of shared memory, for the device to use (DMA).
inline long dmaAddress(Handle device, Handle memory) { return syscall(SYS_DMA_ADDRESS, device, memory); }

// Firmware access (the acpi server): memory to map over non-RAM physical
// addresses, PCI configuration space, and wide port I/O.
inline long firmwareMemory(Handle firmware, unsigned long physical, unsigned long size) {
    return syscall(SYS_FIRMWARE_MEMORY, firmware, physical, size);
}
inline long firmwarePciRead(Handle firmware, unsigned long address, unsigned width) {
    return syscall(SYS_FIRMWARE_PCI, firmware, address, width);
}
inline long firmwarePciWrite(Handle firmware, unsigned long address, unsigned width, unsigned long value) {
    return syscall(SYS_FIRMWARE_PCI, firmware, address, width | PCI_WRITE, value);
}
inline long portInWide(Handle ports, unsigned port, unsigned width) {
    return syscall(SYS_PORT_IN_WIDE, ports, port, width);
}
inline long portOutWide(Handle ports, unsigned port, unsigned width, unsigned long value) {
    return syscall(SYS_PORT_OUT_WIDE, ports, port, width, value);
}

// Thermal throttling: caps the CPU at `percent` (1-100) of its performance; 100 lifts it.
inline long firmwarePerformance(Handle firmware, unsigned long percent) {
    return syscall(SYS_FIRMWARE_PERFORMANCE, firmware, percent);
}

inline long firmwareInterrupts(Handle firmware, unsigned long action, unsigned long a = 0, unsigned long b = 0) {
    return syscall(SYS_FIRMWARE_INTERRUPTS, firmware, action, a, b);
}

// The system is up: clears ShoolLoader's boot-attempt counter (system programs only).
inline long bootComplete() { return syscall(SYS_BOOT_COMPLETE); }

// POWER_OFF or POWER_RESTART (system programs only). Returns only on failure.
inline long power(unsigned long action) { return syscall(SYS_POWER, action); }

} // namespace Kapala::Sys

#pragma once

// The RudraCore system call interface, shared by the kernel and userspace
// (Kapalaframe).
//
// Calling convention: `int $0x80` with the call number in rax and arguments
// in rdi, rsi, rdx, r10, r8. The result comes back in rax: >= 0 on success,
// a negative Error on failure. All other registers are preserved.
//
// Handles: programs reach kernel objects (channels, shared memory, devices)
// only through handles, per-program numbers like file descriptors. A handle
// can be passed to another program in a channel message or when spawning
// it; it then moves to that program. Handle 0 is never valid.
//
// A handle is (generation << 8) | slot. The generation changes each time a
// slot is freed, so a closed handle's number never names a later object.
// A program's first handles (from spawn) are still 1, 2, 3...
//
// Each handle carries rights (Rights below), checked on every call. Rights
// can only shrink: handle_restrict drops some, handle_duplicate makes a
// second handle with the same or fewer, and a moved handle keeps exactly
// its rights. A handle with REVOKE can cut off every other handle to its
// object (handle_revoke). Revoked handles fail with REVOKED.

namespace Rudracore::Abi {

constexpr unsigned char SYSCALL_VECTOR = 0x80;

using Handle = unsigned long;
constexpr Handle NO_HANDLE = 0;

enum Syscall : unsigned long {
    // Tasks
    SYS_LOG = 0,     // (char const* text, usize length): write to the kernel log
    SYS_EXIT = 1,    // (long code): end the calling task
    SYS_YIELD = 2,   // (): let other tasks run
    SYS_SLEEP = 3,   // (u64 milliseconds)
    SYS_TASK_ID = 4, // () -> id of the calling task
    SYS_TIME = 5,    // () -> milliseconds since boot
    SYS_SPAWN = 6,   // (char const* name, usize length, Handle const* handles, usize count) -> task id
                     //   Starts a program from the boot image. The handles move to the new
                     //   program, which finds them as handles 1, 2, 3... (NOT_FOUND, or a bad
                     //   handle, leaves them with the caller.) Boot-image programs are part of
                     //   the system, so this moves handles without RIGHT_TRANSFER too: that's
                     //   how init gives a driver a device it can't pass on.
    SYS_SYSTEM_INFO = 7, // (SystemInfo* out)
    SYS_RANDOM = 8,      // (void* out, usize length <= 256): fills it with random bytes, good for keys
    SYS_SPAWN_IMAGE = 15, // (SpawnImage const*) -> task id: starts a program from an ELF file in
                          //   shared memory (an installed app). The handles move to it, as with
                          //   spawn, but each needs RIGHT_TRANSFER.
    SYS_FILE_OPEN = 9,   // (char const* name, usize length) -> Handle to read-only shared memory holding
                         //   a data file from the boot image (e.g. "fonts"); its size is up to the file

    // Handles and channels
    SYS_HANDLE_CLOSE = 10,   // (Handle): also works on a revoked handle
    SYS_CHANNEL_CREATE = 11, // (Handle out[2]): two connected endpoints
    SYS_CHANNEL_SEND = 12,   // (Handle endpoint, void const* data, usize length, Handle attach)
                             //   Never blocks. Needs RIGHT_WRITE. `attach` (or NO_HANDLE) moves to
                             //   the receiver with its rights; it needs RIGHT_TRANSFER.
    SYS_CHANNEL_RECV = 13,   // (Handle endpoint, void* buffer, usize capacity, Handle* attached, u64 flags)
                             //   -> message length. Waits for a message unless RECV_NONBLOCK. Needs
                             //   RIGHT_READ (so does wait). An attached handle revoked on the way
                             //   arrives as NO_HANDLE.
    SYS_WAIT = 14,           // (Handle const* endpoints, usize count, u64 timeoutMs)
                             //   Waits until one of up to MAX_WAIT endpoints has a message (or its
                             //   peer closed), or until the timeout (WAIT_FOREVER: no limit; 0: just
                             //   check). Returns the index of a ready endpoint, or TIMED_OUT.
    SYS_HANDLE_DUPLICATE = 16, // (Handle, u64 rights) -> a new handle to the same object with
                               //   `rights` & the handle's own. Needs RIGHT_DUPLICATE.
    SYS_HANDLE_RESTRICT = 17,  // (Handle, u64 rights): keep only `rights` & the current ones
    SYS_HANDLE_REVOKE = 18,    // (Handle): every other handle to this object, in any program,
                               //   stops working (REVOKED); shared memory is unmapped from every
                               //   other program; blocked waiters wake up. Needs RIGHT_REVOKE.
    SYS_HANDLE_RIGHTS = 19,    // (Handle) -> the handle's rights

    // Memory. A program's memory is regions; pages are allocated when first
    // touched (but promised and charged to its quota when the region is made,
    // so touching never runs out).
    SYS_MEMORY_CREATE = 20, // (usize size, u64 flags) -> Handle to new zeroed shared memory, physically
                            //   contiguous. flags: MEMORY_BELOW_4G for devices that only reach 32 bits.
    SYS_MEMORY_MAP = 21,    // (Handle memory, u64 flags) -> address where it's mapped. Needs RIGHT_READ.
                            //   Shared: writable only with RIGHT_WRITE, never if read-only or sealed.
                            //   MAP_COPY: a private copy-on-write view (writable; pages are the object's
                            //   until written). MAP_READ_ONLY: read-only either way.
    SYS_MEMORY_ALLOC = 22,  // (usize size) -> address of new zeroed private memory (read + write)
    SYS_MEMORY_UNMAP = 23,  // (address returned by SYS_MEMORY_MAP or SYS_MEMORY_ALLOC): remove that region
    SYS_MEMORY_PROTECT = 24, // (address of a region, u64 writable 0/1): read-only, or writable again
                             //   (only if it was made writable)
    SYS_MEMORY_SEAL = 25,    // (Handle memory): its contents never change again, for anyone (writable
                             //   mappings everywhere become read-only). Needs RIGHT_WRITE and RIGHT_REVOKE.
                             //   Not for device memory or memory a device was given.
    SYS_MEMORY_INFO = 26,    // (Handle memory, MemoryInfo* out). Needs RIGHT_READ.
    SYS_MEMORY_CREATE_PAGED = 27, // (usize size, Handle pagerEnd) -> Handle to a paged object: its pages
                                  //   come on demand from a pager (memory-mapped files). pagerEnd (one end
                                  //   of a channel, RIGHT_WRITE) moves to the kernel; each page a program
                                  //   touches that isn't there yet arrives as a PageRequest at its peer,
                                  //   and the toucher waits. The handle can't write (RIGHT_WRITE dropped).
    SYS_MEMORY_SUPPLY = 28,  // (Handle pager's end, u64 offset, void const* data, u64 length): the pager
                             //   answers, whole pages (offset and length page aligned). Pages may be
                             //   dropped again under memory pressure and asked for anew.

    // Devices (drivers only: needs a handle given by init)
    SYS_IRQ_WAIT = 30,  // (Handle irq): waits for the interrupt to fire
    SYS_PORT_IN = 31,   // (Handle ports, u16 port) -> byte read
    SYS_PORT_OUT = 32,  // (Handle ports, u16 port, u8 value)
    SYS_IRQ_BIND = 33,  // (Handle irq, Handle endpoint, u64 cookie)
                        //   From now on each interrupt sends an IrqMessage{cookie} from
                        //   `endpoint` (to its peer), so a driver can wait for several
                        //   IRQs and other messages in one place. The line stays masked
                        //   after each message until SYS_IRQ_ACK.
    SYS_IRQ_ACK = 34,   // (Handle irq): done with the last interrupt, let the next one in
    SYS_DEVICE_INFO = 35, // (Handle device, DeviceInfo* out): what a PCI device is
    SYS_DEVICE_BAR = 36,  // (Handle device, usize index) -> Handle to shared memory: the device's
                          //   registers in memory BAR `index` (map it to use them, uncached).
                          //   Also turns on the device's memory decoding and DMA.
    SYS_DMA_ADDRESS = 37, // (Handle device, Handle memory) -> physical address of shared memory
                          //   (from SYS_MEMORY_CREATE: physically contiguous), so the device can
                          //   read and write it. Keep the memory handle open while the device
                          //   uses it.
    SYS_POWER = 38,       // (u64 action: POWER_OFF or POWER_RESTART): through ACPI. Root and
                          //   System programs only (KamalShell), not apps: ACCESS_DENIED.
                          //   Returns (IO_ERROR) only if the machine couldn't be turned off.
    // For the acpi server (firmware access; init hands it INIT_HANDLE_FIRMWARE
    // and INIT_HANDLE_FIRMWARE_PORTS):
    //   SYS_FIRMWARE_MEMORY = 39: (Handle firmware, u64 physical, u64 size) -> Handle to
    //       memory to map: physical memory that isn't RAM, kernel, loader or
    //       screen memory (ACPI tables, chipset registers). Uncached except ACPI
    //       table memory. Needs RIGHT_READ.
    //   SYS_FIRMWARE_PCI = 40: (Handle firmware, u64 address, u64 widthAndWrite, u64 value)
    //       -> the value read (or OK). address = bus << 16 | device << 11 |
    //       function << 8 | offset (segment 0, offset < 256); widthAndWrite =
    //       width (1, 2, 4) | 0x100 to write. Reads need RIGHT_READ, writes RIGHT_WRITE.
    //   SYS_PORT_IN_WIDE = 41: (Handle ports, u16 port, u64 width 1/2/4) -> value
    //   SYS_PORT_OUT_WIDE = 42: (Handle ports, u16 port, u64 width, u64 value)
    SYS_FIRMWARE_MEMORY = 39,
    SYS_FIRMWARE_PCI = 40,
    SYS_PORT_IN_WIDE = 41,
    SYS_PORT_OUT_WIDE = 42,
    SYS_FIRMWARE_INTERRUPTS = 43, // (Handle firmware, u64 action, u64 a, u64 b), RIGHT_WRITE:
                                  //   INTERRUPTS_ROUTE: a = GSI, b = line | level << 8 | activeLow << 9
                                  //     (a PCI device's interrupt, as _PRT routes it in APIC mode);
                                  //   INTERRUPTS_APIC: switch from the 8259 PICs to the APICs.
                                  //   IO_ERROR if that couldn't be done (still on the PICs).
    SYS_DEVICE_MSI = 44, // (Handle device) -> Handle irq: the device's message-signalled interrupt
                         //   (MSI, else MSI-X entry 0), programmed by the kernel; its INTx pin goes
                         //   off. Used like any IRQ (wait, bind, ack). Needs RIGHT_MMIO. NOT_FOUND
                         //   without MSI/MSI-X or before the APICs are on (use the pin then);
                         //   ALREADY_EXISTS if the device has one; NO_SPACE when all are taken.
    SYS_BOOT_COMPLETE = 45, // (): the system is up, so ShoolLoader's boot-attempt counter is cleared
                            //   (an entry that keeps failing to get here is passed over for its
                            //   fallback). KamalShell calls it once the desktop has run a while.
                            //   Root and System programs only (ACCESS_DENIED). NOT_FOUND without
                            //   UEFI runtime services (BIOS boot); IO_ERROR if the firmware failed.
    SYS_FIRMWARE_PERFORMANCE = 46, // (Handle firmware, u64 percent 1-100), RIGHT_WRITE: the acpi
                                   //   server's thermal throttling (passive cooling) caps the CPU at
                                   //   that share of its performance; 100 lifts the cap. NOT_FOUND if
                                   //   the CPU has no way (no HWP, no clock modulation).
    SYS_TASK_LIST = 47,    // (TaskInfo* out, usize capacity) -> how many processes are running (up to
                           //   `capacity` of them are written): each one's name, threads, CPU time and memory.
    SYS_KERNEL_STATS = 48, // (KernelStats* out): the kernel's own memory (heap, page tables, promises).

    // Threads. A process has one thread to start with; they share its memory
    // and handles. SYS_EXIT ends the whole process; SYS_THREAD_EXIT just the
    // caller (the process, if it was the last). SYS_TASK_ID is the process's id.
    SYS_THREAD_CREATE = 49,  // (entry, stackTop, u64 arg, u64 tlsBase) -> thread id. It starts at `entry` with
                             //   `arg` in rdi, on the stack the caller made, with its FS base (thread-local
                             //   storage) at tlsBase. NO_SPACE at the process's thread limit.
    SYS_THREAD_EXIT = 50,    // (long code)
    SYS_THREAD_ID = 51,      // () -> the calling thread's id
    SYS_THREAD_JOIN = 52,    // (u64 thread, long* code, u64 timeoutMs): waits for a thread of the same process
                             //   to end, then its exit code. NOT_FOUND if there's no such thread (or its
                             //   code was already taken); TIMED_OUT.
    SYS_THREAD_SET_TLS = 53, // (u64 base): the calling thread's FS base
    SYS_FUTEX_WAIT = 54,     // (u32* address, u32 expected, u64 timeoutMs): sleeps while *address == expected,
                             //   until futex_wake on the same word (any process sharing the memory).
                             //   OK (woken), WOULD_BLOCK (it wasn't `expected`), TIMED_OUT.
    SYS_FUTEX_WAKE = 55,     // (u32* address, u64 count) -> threads woken (oldest first)

    // Processes, through process handles (spawn with SPAWN_HANDLE). RIGHT_READ
    // waits and reads; RIGHT_WRITE signals and limits.
    SYS_PROCESS_WAIT = 56,   // (Handle process, long* code, u64 timeoutMs): waits for it to end, then its
                             //   exit code (>= 0 from the program; EXIT_* if the kernel ended it). TIMED_OUT.
    SYS_PROCESS_SIGNAL = 57, // (Handle process, u64 signal, u64 flags): SIGNAL_KILL ends it at once;
                             //   SIGNAL_TERMINATE asks it to end (an EVENT_TERMINATE on its event channel,
                             //   or, without one, ends it); SIGNAL_INTERRUPT is only an event. SIGNAL_GROUP:
                             //   every process in its group. An app may signal only apps.
    SYS_PROCESS_LIMIT = 58,  // (Handle process or NO_HANDLE for itself, u64 limit, u64 value): lowers a limit
                             //   (never raises): LIMIT_MEMORY (bytes), LIMIT_OBJECTS, LIMIT_THREADS,
                             //   LIMIT_CPU_MS (CPU time; then it's ended, EXIT_CPU_LIMIT).
    SYS_PROCESS_EVENTS = 59, // (Handle endpoint): where this process's events go (an Event message per
                             //   event, to the endpoint's peer); NO_HANDLE stops them. The endpoint moves.
    SYS_PROCESS_INFO = 60,   // (Handle process, ProcessInfo* out)

    // Performance.
    SYS_TIME_NS = 61,         // () -> nanoseconds since boot (the TSC: for measuring)
    SYS_KERNEL_COUNTERS = 62, // (KernelCounters* out): the kernel's event counters (instrumentation)
};

// SYS_KERNEL_COUNTERS: running totals since boot.
struct KernelCounters {
    unsigned long syscalls, interrupts, pageFaults;
    unsigned long switches, switchNs;          // context switches, and the time spent in them
    unsigned long lockAcquires, lockContended; // the kernel lock: taken, and taken after waiting
    unsigned long lockWaitNs;                  // time CPUs spent waiting for it
    unsigned long ipis, shootdowns;
    unsigned long heapAllocs, heapNs;          // kernel heap allocations, and their time
    unsigned long cpus;
};

// SYS_SPAWN (5th argument) and SYS_SPAWN_IMAGE (2nd) flags.
constexpr unsigned long SPAWN_HANDLE = 1;    // return a process handle instead of its id
constexpr unsigned long SPAWN_NEW_GROUP = 2; // start a new process group (else the parent's)

// Exit codes the kernel gives a process it ended.
constexpr long EXIT_FAULT = -1;         // a thread faulted (page fault, invalid instruction...)
constexpr long EXIT_KILLED = -2;        // SIGNAL_KILL, or SIGNAL_TERMINATE with no event channel
constexpr long EXIT_CPU_LIMIT = -3;     // used up LIMIT_CPU_MS
constexpr long EXIT_OUT_OF_MEMORY = -4; // ended to free memory (the app holding the most)

constexpr unsigned long SIGNAL_KILL = 1, SIGNAL_TERMINATE = 2, SIGNAL_INTERRUPT = 3;
constexpr unsigned long SIGNAL_GROUP = 1;
constexpr unsigned long LIMIT_MEMORY = 1, LIMIT_OBJECTS = 2, LIMIT_THREADS = 3, LIMIT_CPU_MS = 4;

// What arrives on a process's event channel (SYS_PROCESS_EVENTS). This is
// Bhairav's equivalent of signals: events are messages the process reads
// when it likes, never code run behind its back. Faults aren't events: a
// faulting thread ends its process (EXIT_FAULT), and whoever holds a handle
// to it reads what happened (ProcessInfo).
struct Event {
    unsigned long kind; // EVENT_*
    unsigned long from; // the sender's process id
};
constexpr unsigned long EVENT_TERMINATE = 1, EVENT_INTERRUPT = 2;

// SYS_PROCESS_INFO.
struct ProcessInfo {
    unsigned long id, group, parent;
    unsigned long threads;    // live threads
    long exitCode;            // once exited
    unsigned char exited;
    unsigned char reserved[7];
    unsigned long cpuMs;
    unsigned long faultVector;  // why it ended, when it faulted (EXIT_FAULT)
    unsigned long faultAddress; // the address of a page fault
    unsigned long faultRip;
};

// SYS_TASK_LIST: one task. Memory counts whole bytes.
struct TaskInfo {
    unsigned long id;
    char name[32];
    unsigned char privilege; // TASK_APP, TASK_SYSTEM, TASK_ROOT
    unsigned char state;     // TASK_READY, TASK_RUNNING, TASK_WAITING (its busiest thread)
    unsigned short threads;
    unsigned int regions;    // memory regions it has mapped
    unsigned long cpuMs;
    unsigned long residentBytes;  // private memory it holds now
    unsigned long committedBytes; // private memory it may touch (reserved; taken as touched)
    unsigned long sharedBytes;    // shared memory it maps (others' too)
};
constexpr unsigned char TASK_APP = 0, TASK_SYSTEM = 1, TASK_ROOT = 2;
constexpr unsigned char TASK_READY = 0, TASK_RUNNING = 1, TASK_WAITING = 2;

// SYS_KERNEL_STATS.
struct KernelStats {
    unsigned long heapBytes, heapPeakBytes, heapPages; // the kernel heap
    unsigned long heapAllocations, heapFailures;
    unsigned long pageTablePages;
    unsigned long promisedBytes; // promised to programs, not taken yet
    unsigned long fileBytes;     // memory-mapped files' pages in memory (dropped first when memory is short)
};

constexpr unsigned long INTERRUPTS_ROUTE = 1, INTERRUPTS_APIC = 2;

constexpr unsigned long MEMORY_BELOW_4G = 1;        // SYS_MEMORY_CREATE
constexpr unsigned long MAP_COPY = 1, MAP_READ_ONLY = 2; // SYS_MEMORY_MAP

// SYS_MEMORY_INFO.
struct MemoryInfo {
    unsigned long size; // bytes (page aligned)
    unsigned long flags;
};
constexpr unsigned long MEMORY_SEALED = 1, MEMORY_READ_ONLY = 2, MEMORY_PAGED = 4;

// What a paged object's pager receives: supply [offset, offset + length).
struct PageRequest {
    unsigned long offset;
    unsigned long length;
};

constexpr unsigned long POWER_OFF = 1, POWER_RESTART = 2;
constexpr unsigned long PCI_WRITE = 0x100;

// A PCI device's identity (SYS_DEVICE_INFO).
struct DeviceInfo {
    unsigned short vendor, device;
    unsigned char classCode, subclass, progIf, irqLine;
    unsigned long barSize[6]; // 0: no memory BAR there
};

struct SpawnImage {
    Handle memory;          // shared memory holding the ELF file
    unsigned long size;     // its length in bytes
    char name[32];          // the task's name
    Handle handles[8];      // given to the program as its handles 1, 2, 3...
    unsigned long handleCount;
};

// What a handle allows. Objects are created with every right that applies.
enum Rights : unsigned long {
    RIGHT_READ = 1 << 0,      // channel: receive, wait; memory: map; IRQ: wait, bind, ack;
                              // ports: in; device: info
    RIGHT_WRITE = 1 << 1,     // channel: send; memory: map writable, DMA target; ports: out
    RIGHT_TRANSFER = 1 << 2,  // move it to another program
    RIGHT_DUPLICATE = 1 << 3, // make another handle to the same object
    RIGHT_REVOKE = 1 << 4,    // cut off every other handle to the object
    RIGHT_MMIO = 1 << 5,      // device: map its registers (device_bar)
    RIGHT_DMA = 1 << 6,       // device: get physical addresses for it (dma_address)
    RIGHTS_ALL = (1 << 7) - 1,
};

struct IrqMessage {
    unsigned long cookie;
};

enum RecvFlags : unsigned long {
    RECV_NONBLOCK = 1 << 0, // return WOULD_BLOCK instead of waiting
};

constexpr unsigned long MAX_MESSAGE_SIZE = 128;
constexpr unsigned long MAX_WAIT = 32;
constexpr unsigned long WAIT_FOREVER = ~0ul;

enum Error : long {
    OK = 0,
    UNKNOWN_SYSCALL = -1,
    BAD_ADDRESS = -2,      // a pointer argument isn't valid user memory
    INVALID_ARGUMENT = -3,
    BAD_HANDLE = -4,       // not an open handle
    WRONG_TYPE = -5,       // the handle refers to another kind of object
    PEER_CLOSED = -6,      // the other end of the channel is gone
    WOULD_BLOCK = -7,
    QUEUE_FULL = -8,
    NO_SPACE = -9,         // handle table or address space full
    NOT_FOUND = -10,
    BUFFER_TOO_SMALL = -11,
    OUT_OF_MEMORY = -12,
    TIMED_OUT = -13,

    // Used by userspace servers (file system)
    ALREADY_EXISTS = -14,
    NOT_EMPTY = -15,    // a directory that still has entries
    IO_ERROR = -16,     // the disk failed
    IS_DIRECTORY = -17, // wanted a file
    NOT_DIRECTORY = -18,

    // Used by the network server
    CONNECTION_REFUSED = -19,
    CONNECTION_RESET = -20,
    NETWORK_DOWN = -21, // no address yet (DHCP hasn't answered) or no network card

    // Capabilities
    ACCESS_DENIED = -22, // the handle lacks a right the call needs
    REVOKED = -23,       // the handle was revoked
};

// Handles init starts with (when the hardware exists).
enum InitHandle : Handle {
    INIT_HANDLE_FRAMEBUFFER = 1, // shared memory: the screen
    INIT_HANDLE_PS2_PORTS = 2,   // I/O ports 0x60-0x64 (PS/2 controller)
    INIT_HANDLE_KEYBOARD_IRQ = 3,
    INIT_HANDLE_MOUSE_IRQ = 4,
    INIT_HANDLE_STORAGE = 5,     // PCI device: the disk controller (AHCI with a disk, else NVMe, else IDE)
    INIT_HANDLE_NETWORK = 6,     // PCI device: the network card (Intel e1000 family)
    INIT_HANDLE_NETWORK_IRQ = 7, // its interrupt line
    INIT_HANDLE_FIRMWARE = 8,       // ACPI: non-RAM physical memory and PCI configuration
    INIT_HANDLE_FIRMWARE_PORTS = 9, // ACPI: I/O ports, except those the kernel and drivers own
    INIT_HANDLE_SCI = 10,           // ACPI: the SCI interrupt (events: power button, GPEs), if it has a line of its own
    INIT_HANDLE_STORAGE_PORTS = 11, // IDE only: the primary channel's ports, 0x1F0-0x1F7
};

struct SystemInfo {
    unsigned long uptimeMs;
    unsigned long totalMemory;
    unsigned long freeMemory;
    unsigned long taskCount;

    // Framebuffer (all zero if there's none). 32 bits per pixel.
    unsigned long screenWidth;
    unsigned long screenHeight;
    unsigned long screenPitch; // bytes per row
    unsigned char redShift, greenShift, blueShift, reserved;

    unsigned long timeOfDay; // seconds since midnight, from the hardware clock (UTC)
    unsigned long unixTime;  // seconds since 1970-01-01 (UTC)

    unsigned long bootMode; // BOOT_NORMAL, BOOT_SAFE or BOOT_RECOVERY: the boot entry chosen
    unsigned long acpiRsdp; // physical address of the ACPI RSDP (system programs only; apps get 0)
};

// SystemInfo.bootMode. Safe: the known-good minimum (no network, no
// third-party apps, no self-tests). Recovery: repair (no third-party apps,
// network on, a Terminal opens).
constexpr unsigned long BOOT_NORMAL = 0, BOOT_SAFE = 1, BOOT_RECOVERY = 2;

} // namespace Rudracore::Abi

# Bhairav OS security assessment

Status: first audit, 2026-11-12, of commit `38a627f`, plus the fixes in
§6 (memory reserve) and §7 (kernel hardening round).
Scope: everything I read line by line is marked **reviewed**. Anything
else is marked **not reviewed** and makes no claim. Nothing here is a
certification or a formal proof.

Reviewed: the RudraCore kernel (`kernel/src/core/*`, `mem/*`,
`arch/x86_64/{idt,vmm,cpu}`), the ABI (`abi/rudracore/syscalls.h`), how init
hands out handles, how KamalShell launches apps, the format and install path
of apt/BPK packages, the TLS certificate handling, and the bootloader's CPU
setup. Not reviewed: the `fs` server's path handling, the TCP/IP stack's
packet parsers, the browser's HTML/URL parsers, the image decoders, the
crypto primitives beyond their boot-time test vectors, and the ShoolLoader
file loader.

---

## 1. Current architecture: what is actually enforced

| Property | Status | Evidence |
|---|---|---|
| Separate address space per program | **Enforced** | `Vmm::createUserSpace` gives each task its own lower half and shares only the kernel half. |
| User/kernel split | **Enforced** | Kernel pages have no U bit. `protect-test` checks this at every boot (a read faults and a kernel pointer gets `BAD_ADDRESS`). |
| Syscall pointer validation | **Enforced** | `isUserRange` checks the range is below `USER_END`, has no overflow, is mapped, and is writable when written. Every pointer argument goes through it. |
| W^X for user programs | **Enforced** | The ELF loader rejects W+X segments. NX is set on every non-EXEC leaf. EFER.NXE is set (ShoolLoader `handover.cpp`, Limine). |
| W^X for the kernel image | **Enforced** | `.text` is R-X, `.rodata` R--, `.data` RW-. The direct map is RW and NX. |
| W^X for every alias | **Enforced (§7)** | The direct-map alias of the kernel's code and constants is now read-only too. |
| NX / CR0.WP | **Enforced (§7)** | The kernel sets EFER.NXE and CR0.WP itself, and refuses to boot on a CPU without NX. |
| SMEP / SMAP | **Enforced when the CPU has them (§7)** | SMAP allows user memory only inside two copy helpers. AC is cleared on every kernel entry. |
| Kernel stack guard pages | **Enforced (§7)** | Each kernel stack sits in its own slot with an unmapped page below. The boot task's static stack is the one exception. |
| User stack guard | **Enforced (§7)** | Programs must load below 4 GiB. The stack sits below 128 TiB with nothing mapped under it but shared memory far below. |
| Handles | **Capabilities (§8)** | Each handle has rights (read, write, transfer, duplicate, revoke, MMIO, DMA) and a generation counter, and can be revoked. Rights only shrink. |
| Who reaches hardware | **Enforced by delegation and rights (§8)** | Only init gets IRQ, I/O-port and PCI handles. It strips them to what each driver uses before moving them, so drivers can't pass devices on. |
| DMA isolation | **Enforced with VT-d (§10, §12)** | Each device reaches only the buffers its driver registered, and can't send interrupt messages (interrupt remapping). Without VT-d hardware, unconfined (logged). |
| Kernel memory accounting | **Added in §6 and §7** | A 4 MiB kernel reserve, plus a per-program quota of half of RAM. |
| Boot integrity | **Signed on UEFI, hashed on BIOS (§11)** | ShoolLoader boots only files in an Ed25519-signed list and refuses older boot images. Limine checks a BLAKE2B hash per file and an enrolled config hash. |
| TLS server authentication | **Enforced (§10)** | Chain to a trusted root, hostname, dates, and the CertificateVerify signature. Fails closed. |
| Package integrity | **Enforced (§10, §11)** | Ed25519-signed packages and repository indexes, trusted keys in the boot image, no rollback. Checked again at every launch. |
| App isolation from data | **Enforced (§9)** | Installed apps see only their own folder and no network unless the user grants more. Built-ins get fixed profiles. |
| RNG | **Health-checked, fails closed (§15)** | ChaCha20 DRBG keyed from RDRAND (when present), TSC jitter and IRQ timing. It rekeys before and after each output. A known-answer test runs at boot, plus start-up and continuous source tests. With no healthy source, `random` returns an error and TLS refuses to connect. TSC-only seeding (no RDRAND) is still weak early in boot. |

Concurrency model: a single CPU. The kernel runs with interrupts disabled for
every syscall and IRQ. This rules out syscall TOCTOU races on user memory
today, including an ELF image in shared memory that a peer could rewrite.
**SMP would invalidate this. Every user-memory read would then need
copy-in semantics.**

## 2. Threat model

**Assets:** kernel integrity; the user's files on the FAT32 disk; network
traffic and credentials; installed apps; the boot chain; the audit log
(serial).

**Threat actors:**
1. A malicious or compromised **third-party app**: installed through apt or
   BPK, runs as an ordinary task.
2. A **network attacker** on the path: café Wi-Fi, a hostile router, DNS
   spoofing.
3. **Malicious input** to a trusted program: web pages, images, packets,
   disk images, ELF files.
4. A **compromised driver**: e1000 or rtl8139 parsing hostile frames.
5. **Physical / boot-media attacker:** someone who can swap the ISO or the
   EFI partition.

**Trust boundaries:** user↔kernel (`int 0x80`) · app↔fs/net servers (IPC) ·
driver↔hardware (DMA) · network↔net/TLS · repository↔apt ·
firmware↔ShoolLoader↔kernel.

| # | Scenario | Path | Impact | Today |
|---|---|---|---|---|
| T1 | App exhausts RAM, kernel panics | `memory_alloc` loop, then any kernel `new` | Whole-system DoS | **Fixed (§6)** |
| T2 | MITM serves a malicious package | `http://` repo, or `https://` with no cert check, and no signature | Code execution as an app, with full disk and network access | **Open, critical** |
| T3 | Hostile app reads or alters every file, including other apps' `app.elf` | full `fs` channel | Data theft, persistence, trojaning other apps | **Open, critical** |
| T4 | Compromised NIC driver DMAs over kernel memory | `SYS_DMA_ADDRESS` + bus master, no IOMMU | Kernel compromise | **Open, high (needs VT-d)** |
| T5 | MITM on HTTPS | no X.509 validation | Credential theft, content injection | **Open, high** |
| T6 | Boot media tampering | no verified boot | Persistent kernel compromise | **Mitigated (§11, §13)**: signed boot files; the loader is signed for UEFI Secure Boot |
| T7 | Memory corruption in a parser (HTML, PNG/JPEG, TCP, FAT) | not reviewed | Compromise of that one task (contained by isolation) | **Unknown: fuzz** |
| T8 | Kernel exploit made easier | no SMEP/SMAP, no stack guards | Escalation from a kernel bug | **Mitigation gap** |

## 3. Security gap analysis

### Confirmed vulnerabilities (reproduced or traced through the code)

| ID | Sev | Finding | Status |
|---|---|---|---|
| V-01 | High | **An unprivileged program can panic the kernel.** `SYS_MEMORY_ALLOC` (256 MiB per call, no limit on calls), `SYS_MEMORY_CREATE`, spawn and channel creation take physical pages with no reserve. Once RAM is gone, the next kernel `new` (for example `new Endpoint` in `channel_create`) calls `panic("heap: out of memory")`. **Reproduced:** serial log `oom check: took 246 MiB … !!! RudraCore panic: heap: out of memory`. | **Fixed, §6** |
| V-02 | Critical | **Packages have no integrity.** BPK (`tools/bpk.cpp`) has no hash or signature, apt accepts `http://` sources, and `https://` doesn't authenticate the server. Anyone on the path can replace an app. | **Fixed, §10** |
| V-03 | Critical | **Apps get the whole disk and network.** `KamalShell::launch` gives every app, built-in or third-party, an unrestricted `fs` and `net` channel. One bad app can overwrite `/apps/<other>/app.elf`. | **Fixed, §9** |
| V-04 | High | **TLS doesn't check the server certificate.** `tls.cpp` parses the Certificate message and drops it. There is no X.509 parsing, chain, hostname or expiry check, and no trust store. | **Fixed, §10** |
| V-05 | Medium | **Endpoint reference cycles leak kernel memory for good.** Send endpoint `y` over its peer `x` and `y` lands in its own queue holding a reference to itself. Close `x` and `y` can never be freed. Longer cycles work too. | **Fixed, §7** |
| V-06 | Medium | **Dead tasks' memory wasn't freed while nothing else was runnable.** Zombies were reaped only at a task switch away from a ready task. | **Fixed, §6** (reaped on each timer tick) |
| V-07 | Low | **Log spoofing.** `SYS_LOG` writes user bytes, including newlines, into the kernel log after a `[name]` prefix. Spawned app names are user-chosen (`SpawnImage.name`), so an app can call itself `init` in the log. | **Fixed, §7** |
| V-08 | Low | **An ELF segment can overlap the shared-memory window (≥ 4 GiB).** A later `memory_map` or `memory_alloc` then overwrites an OWNED PTE and leaks that page. It only hurts the task itself. | **Fixed, §7** |

### Architectural weaknesses / insecure assumptions

- ~~No handle rights~~ and ~~no handle generations~~: done in §8.
- **Any task may `spawn` any boot program.** It's harmless today, because
  drivers need handles only init holds, but it widens the attack surface.
- **A driver is trusted with all of RAM (DMA).** The comment in
  `device.h` says so. VT-d is the only real fix. In software, the most we can
  do is limit `SYS_DMA_ADDRESS` to memory the driver itself created.
- **FAT32 can't hold ownership or permissions.** Isolation has to be enforced
  by the `fs` server: per-app roots, or capabilities to subtrees.
- **No SMEP/SMAP or guard pages.** They don't fix any bug, but they make
  kernel bugs much harder to exploit.
- **Single-CPU assumption.** See §1.

## 4. Cybersecurity platform gap analysis

| Tool | Buildable now on existing infrastructure? | Needs |
|---|---|---|
| Forensics (hashing, file signatures, hex view, entropy) | **Yes.** `crypto.h` has SHA-256 and `fs` reads files. | MD5/SHA-1/SHA-512 for compatibility; a read-only evidence mode in `fs` |
| BinaryLab: ELF inspector, strings, entropy | **Yes**, purely userspace parsing | x86-64 disassembler (large); debugging needs new kernel calls (ptrace-like, register/memory access by capability) |
| Malware static analysis | **Yes** (static part) | Rule engine; isolated execution needs V-03 fixed first (a sandbox without fs/net handles is already possible: spawn with no handles) |
| Recon: TCP connect scan, DNS, reverse DNS | **Partly.** The `net` protocol does TCP connect and DNS. | Scope/rate-limit policy in `net`; UDP and raw ICMP from apps; audit log |
| PacketLab live capture | **No** | A capture tap in the NIC driver: a shared-memory ring to a capture service. Promiscuous mode is **not enabled** (`e1000.cpp` RCTL sets no UPE/MPE). IPv6 isn't in the stack. |
| WebProbe proxy | **Partly** (HTTP client exists) | Listening sockets in `net` (unverified), X.509 parsing (shared with V-04) |
| VulnScan | Depends on Recon plus a vulnerability data source | Data source and update channel (needs V-02 fixed) |
| NetGuard firewall / IDS | **No** | A policy hook in `net` (it's the only path to the NIC, which is a good single choke point) |
| Hardware research (USB, UART, SPI/I2C) | **No** | No USB host controller (xHCI) driver and no serial driver for users |

**Ordering consequence:** V-02 and V-03 must come before any "security
workstation" features. Otherwise the security tools themselves can be
replaced or read by any app.

## 5. Prioritised roadmap

| P | Item | Components | Change | Depends on | Size | Validation |
|---|---|---|---|---|---|---|
| 0 | ✅ Kernel memory reserve | pmm, syscall, elf, shared_memory, sched | §6 | – | S | `SECURITY_TEST=1` oom-test |
| 1 | ✅ Per-app storage isolation | kamalshell, fs, net, store | §9 | – | M | fs-test, net-test |
| 2 | Package signatures | tools/bpk, apt, apps.cpp | Ed25519 signature over the BPK. Public key in the boot image. Refuse unsigned packages. Repo index signed (anti-rollback: version must not decrease) | Ed25519 implementation + RFC 8032 test vectors | M | Tampered or unsigned `.bpk` refused; vectors in tls-test |
| 3 | X.509 + chain + hostname + expiry | kapala/tls, new x509.cpp | DER parser, RSA-PKCS1/PSS and ECDSA-P256 verify, trust store file in the boot image, fail closed | Bignum/P-256 code | L | Bad-cert test servers (expired, wrong host, self-signed) must fail |
| 4 | ✅ Endpoint cycle prevention | channel, syscall | §7 | – | S | harden-test |
| 5 | ✅ SMEP and SMAP | arch/protect, syscall copy paths | §7 | – | S / M | `FAULT_TEST=smep\|smap` |
| 6 | ✅ Handle rights, generations, revocation | object, task, syscalls | §8 | – | M | harden-test |
| 7 | ✅ Kernel stack guard pages | sched | §7 | – | M | `FAULT_TEST=stack` |
| 8 | ✅ Verified boot | shoolloader, Makefile | §11 | P2's signature code | M | Altered module refused |
| 9 | Capture service + firewall hook | e1000/rtl8139, net | Shared-memory ring, policy in `net` | P1 | L | Fuzzed frames; policy tests |
| 10 | VT-d | new kernel ACPI DMAR + IOMMU code | Per-device page tables | ACPI parsing | XL | QEMU `-device intel-iommu`: DMA outside a mapping faults |
| – | Fuzzing harness | hosted builds of ELF loader, BPK, PNG/JPEG, HTML, TCP parsers | libFuzzer + ASan on Linux host | – | M | Corpus runs clean |

## 6. Change made: kernel memory reserve (V-01, V-06)

**Problem.** Programs could take every physical page. The kernel's own
allocations (`operator new` panics on failure) then took the whole system
down. Any program could do it, third-party apps included.

**Fix.**
- `Pmm::userCanUse(pages)` keeps 4 MiB (1024 pages) that only the kernel's
  own allocations may use.
- It is checked before everything a system call allocates:
  `SharedMemory::allocate` (`memory_create`, boot files), `memory_alloc`
  (including page tables), `channel_create` (two heap endpoints), and
  `Elf::load` (segments, page tables, stacks, task state; this covers
  `spawn` and `spawn_image`). These now return `OUT_OF_MEMORY` (spawn used to
  say `INVALID_ARGUMENT` for every load failure).
- Dead tasks are also reaped on each timer tick, so their memory comes back
  even when nothing else is runnable (V-06).

**Test.** `userspace/programs/oom-test`, run first by init in
`make shot SECURITY_TEST=1` builds. It takes all memory, then checks that
`channel_create`, `memory_create` and `spawn` all return `OUT_OF_MEMORY`.
init waits for it to exit before starting anything else.

**Results (QEMU q35, 256 MiB):**
- Before the fix: `took 246 MiB` → `RudraCore panic: heap: out of memory`.
- After the fix: all three refused, `oom check: passed`. Then every boot
  check passes (ipc, protect, fpu, fs, net, tls) and KamalShell starts.
- A normal build boots to the desktop under both BIOS (Limine) and UEFI
  (ShoolLoader).

**Limits.** This is a global reserve, not per-app quotas. One app can still
starve other apps of memory (they get `OUT_OF_MEMORY`), but no longer the
kernel. Per-task accounting is the follow-up. `memory_map` page tables and
`device_bar` objects aren't counted: they're bounded (32 mappings, driver
only) and the reserve absorbs them.

## 7. Kernel hardening round

Each item below was built, then booted in QEMU (q35, 256 MiB). The test
setups were: the default CPU model (no SMEP/SMAP), `-cpu max` (both), BIOS,
and UEFI.

| Item | What changed | How it's checked |
|---|---|---|
| SMEP | Set in CR4 when CPUID leaf 7 reports it (`arch/x86_64/protect.cpp`). | `FAULT_TEST=smep`: the kernel calls a user page and gets `page fault … protection violation, instruction fetch`. |
| SMAP | Set when supported. The kernel touches user memory only in `fromUser`/`toUser` (`core/syscall.cpp`), which open it with STAC/CLAC. `interruptDispatch` runs CLAC first, because ring 3 can set RFLAGS.AC and an interrupt doesn't clear it. | `FAULT_TEST=smap`: a plain kernel read of a user page faults. Every boot check still passes with SMAP on, and the browser opens and renders. |
| Kernel stack guards | Kernel stacks are mapped at `0xffffff0000000000` in 20 KiB slots, with an unmapped page below each 16 KiB stack. Overflow → #PF can't be pushed → #DF on its IST stack → panic that names the guard address. | `FAULT_TEST=stack`: `double fault … kernel stack overflow into its guard page, at 0xffffff000000afd8`. |
| User stack guard | ELF segments must end below 4 GiB (`Elf::USER_IMAGE_END`, static_assert ≤ `Task::MAP_BASE`). The stack below 128 TiB has no mapping beneath it. This also fixes V-08, since images can no longer overlap the shared-memory window. | harden-test: a segment at 5 GiB is refused. |
| NX and W^X | The kernel sets EFER.NXE (and panics without NX) and CR0.WP itself. The direct-map alias of `.text`/`.rodata` is read-only. | Every boot works with the stricter mappings. |
| Memory quotas | `Core::Quota`: half of RAM per program, charged by `memory_alloc` and `memory_create`. Shared memory refunds its creator when freed, even after that program has ended (the quota is reference counted). | oom-test: one program stops at 124 of 248 MiB. With a helper taking the rest, the kernel reserve still refuses channel, memory and spawn requests. |
| Syscall validation | Log text and spawned app names have control characters replaced (V-07). `sleep` and `wait` timeouts are capped so deadlines can't wrap. Channel sends refuse anything that could start a reference cycle (V-05). | harden-test: both cycle shapes are refused. A forged newline in the log stays on one line. |
| ELF validation | All headers are checked before anything is allocated: EI_VERSION, at most 64 program headers, no PT_INTERP/PT_DYNAMIC, segment address and file offset congruent mod 4 KiB, no shared page with different rights, entry point in an executable segment. | harden-test: 6 crafted bad files refused, and a good one still runs. |
| Object lifetime | Audit: references are held by handles, mappings, queued messages and bound IRQs. Cycles were the only leak (fixed above). `Object::ref()` now traps rather than wrap a u32 count. Waiters are cleared on wake, on wait exit and in `releaseResources`. | Code review, plus the cycle tests. |
| Info leaks | `system_info` zeroes padding (4 bytes after `reserved` used to carry stale kernel stack). `random` output is built in a kernel buffer that is wiped afterwards. Every other output struct and new page was already zeroed. | harden-test: the padding is checked for zero. |

**Not covered.** ELF segments still don't count toward the quota (bounded
by the loader's 256 MiB per program and the kernel reserve). The boot
task's static stack has no guard page. SMEP and SMAP are off on CPUs
without them, which includes QEMU's default model. Handle rights and
generation counters were added afterwards (§8).

## 8. Capabilities

Handles are now capabilities. Contract: `abi/rudracore/syscalls.h`.
Kernel: `core/object.h` (`Capability`, object epoch, quota charge),
`core/task.cpp` (handle table), `core/syscall.cpp` (checks and the new calls).

| Item | Design | Checked by harden-test |
|---|---|---|
| Generation counters | Handle = `(generation << 8) \| slot`. The slot's generation is bumped when the slot is freed, so a stale number never matches. First handles are still 1, 2, 3…, so existing programs didn't change. | A reused slot gets a new number. The old number gives `BAD_HANDLE`. |
| Rights | `READ`, `WRITE`, `TRANSFER`, `DUPLICATE`, `REVOKE`, `MMIO`, `DMA`, checked on every call (`ACCESS_DENIED`). New objects get all applicable rights. Boot files never get `WRITE` or `REVOKE` (one object shared by every program). Device registers aren't transferable. | Restricting never adds rights, and duplicating needs `DUPLICATE`. |
| Read-only and send-only | `handle_duplicate(h, rights)` and `handle_restrict(h, rights)` (intersection only). Memory without `WRITE` maps read-only. A channel end with only `WRITE` sends but can't receive, and vice versa. | Send-only can't receive, receive-only can't send. The kernel won't write into a read-only mapping (`random` → `BAD_ADDRESS`). |
| Revocation | Each object has an epoch and each handle records it. `handle_revoke` bumps the epoch, so every other handle (any program, in flight too) gets `REVOKED`. Memory is unmapped from every other program, and waiters on channels and IRQs are woken. | The revoker keeps access, others get `REVOKED`. A handle revoked in flight arrives as nothing. **A child program reading revoked memory faults at once.** |
| Secure transfer | A moved handle keeps exactly its rights. Channel sends and `spawn_image` (untrusted apps) need `TRANSFER`. `spawn` of boot-image programs doesn't, which is how init gives drivers devices they can't pass on. Revoked handles can't move. Cycle rules from §7 still apply. | Moving without `TRANSFER` gets `ACCESS_DENIED`, and a revoked handle can't be moved. |
| Object quotas | 1,024 channels and memory objects per program, charged to the creator, refunded when the object is destroyed (`Object::~Object`). | Parking channel ends in queues hits `OUT_OF_MEMORY`. Closing them gives the quota back. |
| Device permissions | init restricts its hardware handles before spawning drivers: disk and network cards `READ\|MMIO\|DMA`, IRQs `READ`, PS/2 ports `READ\|WRITE`, screen `READ\|WRITE`. `dma_address` needs `DMA` on the device and `WRITE` on the memory. | Every driver works with only these rights (AHCI, e1000, RTL8139, PS/2), in QEMU under BIOS and UEFI. |

**Lifetime fix found while adding revocation.** If a handle was revoked
while its task was blocked in `wait` on several channels, the other
channels could keep naming the task as their waiter. That pointer would
dangle after the task exited. `wait` now clears the task's stale
registrations on that path, and `handle_close` clears the closing task as
waiter.

**Limits.**
- Revocation is all-or-nothing per object: it doesn't track which handle
  was derived from which.
- Revoking a channel end doesn't touch its peer.
- A driver could still `spawn` a boot-image program with its device; boot
  programs are trusted system code.
- DMA itself is still unconfined without an IOMMU (threat T4 in §2).

## 9. App sandbox

| Item | Design | Checked by |
|---|---|---|
| Unforgeable identity | Identity and scope travel in the `Connect` message on the fs/net **connect** channel, which only init and KamalShell hold. An app gets only its session channel, and nothing on it changes the scope. KamalShell takes the identity from what it launches: the built-in's name, or the installed folder's id. Installs can't take a built-in's name (`isBuiltInProgram`). The Connect magic changed, so an old-format Connect is refused. | Code review. Every other check below depends on it. |
| Per-app roots, private storage | fs scopes: **System** (whole disk), **User**, **Private** (`/appdata/<app>` shown as `/`, made on first connect). Each path is first rewritten with no `.`/`..` parts and refused if `..` would climb above `/`. This matters because the resolver follows `..` entries on the disk, so a plain prefix could be escaped. | fs-test: private write lands in `/appdata/fs-test`; `/../../…` refused; `/sub/../x` works; `/apps` invisible. |
| Protected system directories | `/apps`, `/var`, `/appdata`. User scope: the first two read-only, `/appdata` hidden (NOT_FOUND, left out of `/` listings). Only System scope writes them. The check is on the normalised first component with the resolver's own case-insensitive compare, so case and `..` tricks name the same folder. | fs-test: writes, mkdir and remove refused, including `/VAR/…` and `/tmp/../var/…`. Files (User) doesn't list `appdata`. |
| Network policies | net levels: **None** (Status only), **Local** (DNS; ping/TCP only to 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16), **Internet**. Checked before each request. | net-test: None can't resolve or ping. Local pings the gateway but can't open TCP to example.com. |
| Explicit hardware permissions | Kernel privilege levels: Root (init) → System (what init starts) → App (anything else, including every installed app). Apps can't call `spawn`/`spawn_image`. The kernel refuses to give an app hardware (IRQ, ports, PCI device, device memory) by spawn or by message. Drivers hold devices with only the rights from §8. | harden-test: an app's `spawn` → ACCESS_DENIED. The hardware rule is code review (no app holds hardware to try with). |
| Process resource limits | Apps: a quarter of RAM and 256 kernel objects. System services: half and 1,024. Also 63 handles per program, 64 KiB stack, 256 MiB image. | oom-test: system service 124/248 MiB, app helpers 62 and 55 MiB, then the reserve refuses channel, memory and spawn. |
| Permission review | Manifest `permissions = network local-network files`. Install grants what's asked; an update keeps the old grant, intersected with the new request. Grants live in `/var/permissions/<id>`. The App Store **Permissions** panel shows the request and cycles Network (Off / Local / Internet) and Your files (Off / On). Hardware shows "Never", own folder "Always". Uninstall deletes the grants and `/appdata/<id>`. | In QEMU: the panel opened for Clock, toggles saved `network` and `files` to the disk, and Clock started with `/appdata/clock`. |

**Built-in profiles** (`kamalshell/main.cpp` `APPS`):

| App | Files | Network |
|---|---|---|
| Browser | Private | Internet |
| Files | User | None |
| Notes | User | None |
| Terminal | System | Internet |
| App Store | System | Internet |
| Monitor | Private | None |
| About | Private | None |

Terminal and the App Store need System scope because they install apps,
which means writing `/apps` and `/var`.

**Limits.**
- Apps installed before this change have no grants file, so they start
  with their own folder only until the user grants more.
- Grants are per app, not per folder: `files` means all of the user's files.
- Network policy works by address. An app with Local access can still look
  up names, and a local proxy would relay its traffic further.
- The shell and the servers are trusted to apply all this. A compromised
  KamalShell could connect an app with any scope.
- There's no CPU-time limit yet.

## 10. Closing the open items

| Item | Design | Checked by |
|---|---|---|
| CPU time | Two ready queues: system tasks (kernel, init and what it starts) always run before apps, and a ready system task preempts an app at the next 1 ms tick. Apps share what's left round-robin. Each task's CPU time is counted (`Task::cpuMs`). | harden-test: with an app spinning for 1.5 s, a system task's worst wake-up delay was 0 ms. With preemption switched off as a check, it was 5 ms and the test failed. |
| Per-folder file grants | Permission `folder`: a Private app also gets one user folder, which it sees as `/shared`. The folder is chosen in the App Store and checked by fs (never `/`, never a protected directory; `..` normalised away). | fs-test: writes land in the folder; `..` can't leave it; it can't be removed; a `/var` grant is refused at connect. |
| Host allowlists (the proxy route) | Access level `Hosts`: DNS only for the names in the manifest's `hosts` line (`*.` covers subdomains), and ping/TCP only to addresses those lookups returned. A local proxy is just another unlisted address. | net-test: a hosts-only client can't ping the gateway or resolve another name, but can reach example.com. |
| Signed packages | Ed25519 (RFC 8032, after TweetNaCl) over the whole package; the signature is the last file. Build: `bpk tbs` → `openssl pkeyutl -sign -rawin` → `bpk attach`, key in `keys/` (gitignored). Trusted keys: `trust.bin` in the boot image. `installPackage` refuses unsigned, altered and older versions. | tls-test: RFC 8032 vectors (and tampered ones), SHA-512/384 vectors, every catalog package verifies, one changed byte fails. OpenSSL signs and Bhairav verifies, so the two implementations cross-check. |
| HTTPS certificates | `x509.cpp` (DER, chain to `roots.bin` from the build machine's CA bundle, dates, CA flag, SAN hostnames, unknown critical extensions refused) plus `pkey.cpp` (Montgomery arithmetic; RSA PKCS #1 and PSS; ECDSA P-256/P-384). TLS verifies the chain and the CertificateVerify signature over the transcript, and fails closed. | tls-test: example.com and wikipedia.org verify. A wrong host name, an expired chain, no roots and a changed certificate are all refused. Also tried: debian.org, microsoft.com, github.com and kernel.org all verify, exercising ECDSA SHA-256/384, RSA PKCS #1 SHA-256/384 and RSA-PSS. |
| IOMMU | Intel VT-d (`arch/x86_64/iommu.cpp`). The ACPI DMAR table names the units. One root table, a context entry per device, a second-level page table per device. Every device starts blocked. `dma_address` maps exactly that buffer for that device (same address); freeing the buffer unmaps it and flushes the IOTLB before the pages are reused. Blocked DMA is logged. | `IOMMU=1`: every boot check passes through the mappings. `IOMMU=1 FAULT_TEST=dma`: the AHCI and e1000 DMA are blocked and logged, and the disk stops. Without VT-d the log says DMA is unconfined. |

**Limits.**
- CPU priority is two levels, not per-app shares or caps.
- The root store is the build machine's bundle. There's no revocation
  checking (OCSP/CRL), and no IP-address names.
- A lost signing key means packages built with a new key won't update
  installed ones signed by the old key, unless both keys are in
  `trust.bin`.
- VT-d needs the hardware. AMD IOMMU is not supported. A compromised driver
  can still misuse the buffers it registered. Interrupt remapping: see §12.

## 11. Supply chain: boot, repositories, installs

| Item | Design | Checked by |
|---|---|---|
| Signed boot modules, kernel verification | The build writes `shool.sum` (`version N` plus the SHA-256 of the kernel, every module and `shool.cfg`) and signs it with `keys/boot-signing.pem` as `shool.sig`. ShoolLoader has the public key built in (`build/boot-key.h`). It refuses to boot when the signature is wrong or missing, and when any file it loads is unlisted or changed. `shool.cfg` is listed, so it can't point `kernel =` at another signed file. | UEFI tests: an untouched image boots. A changed `init.elf`, a re-hashed but unsigned `shool.sum`, a `shool.cfg` with `kernel = /boot/init.elf`, and a missing `shool.sig` are each refused, with the reason on screen. |
| BIOS path | `build/limine.conf` gets a BLAKE2B hash after every path, and `limine enroll-config` writes the config's hash into the ISO's `limine-bios.sys`. | A changed `init.elf`: Limine panics with "Blake2b hash … does not match". An edited `limine.conf`: "CHECKSUM MISMATCH FOR CONFIG FILE". |
| Boot anti-rollback | `BOOT_VERSION` (Makefile) is the image's security version. ShoolLoader keeps the highest that has booted in the UEFI variable `BhairavBootVersion`, set non-volatile and boot-services only, so the running OS can't change it. A variable with other attributes or another size isn't ours, so it's replaced. An older image is refused. | OVMF with persistent variables: version 2 boots, then version 1 is refused ("rollback refused"). |
| Signed repository metadata | `make repo` writes `Packages` starting with `serial = <time>`, adds `sha256 =` per package, and signs it as `Packages.sig` (package key). `apt update` refuses an index that's unsigned or wrongly signed, has no serial, or has a serial lower than the last one read from that repository (`/var/apt/serials/`). `apt install` from a repository refuses a package whose SHA-256 or version differs from the signed index. | A served repo: the signed index is accepted. The same index with one line changed is refused ("isn't signed by a trusted publisher"). A properly signed index with an older serial is refused ("older than one already read"). |
| Package anti-rollback | §10 (an update never installs an older version), plus the index's version and hash binding above, so a mirror can't swap in an older signed build. | §10 |
| Trusted key management | Separate roles: the boot key only signs boot images and lives in the loader. The package key signs packages and indexes and lives in `trust.bin`, which is itself a signed boot file. `keys/trusted/*.pem` adds more public keys (rotation: keep the old key's public half there; revocation: delete it, rebuild). Up to 15 extra keys. New keys are made with `umask 077`. | Build: `trust.bin` holds the key count and keys. Boot: `trust.bin` is checked like every other boot file. |
| Secure installation | `installPackage` keeps the signed package as `/apps/<id>/package.bpk` (written first) plus its manifest and icon, and deletes any old `app.elf`. KamalShell never runs a bare program file. At every launch it reads the package and checks the signature, that it's this app's (not another app's signed package, which would run with this app's grants), and that it matches the installed manifest. Only then does it run the `app.elf` inside. A failed check logs why and doesn't start the app. | Code review. The same check (`loadInstalled`) is what `apt verify` runs, tested below. |
| Recovery verification | `apt verify` re-checks every installed app and names each failure. `apt install <id>` repairs a failed app from its signed source even at the same version. | On a copy of the user's disk: Clock, installed before this change, shows `FAILED … its package is missing`. After `apt install clock`, `apt verify` shows `ok clock 1.0`. |

**Limits.**
- The root of trust is `BOOTX64.EFI` on the medium. Anyone who can rewrite the whole medium can replace the loader, and the BIOS path's `limine-bios.sys`. Closing that needs UEFI Secure Boot with the loader signed by a key in the firmware's `db` (not set up). The BIOS path has hashes but no signature.
- Boot rollback state is a UEFI variable. A physical attacker with a UEFI shell, or someone resetting NVRAM, can clear it. QEMU's `-bios OVMF.fd` (as `make run-uefi` uses) doesn't persist variables at all.
- Index serials stop replays of older indexes, but not a freeze: an attacker can keep serving the latest signed index forever, hiding new updates. That would need an expiry date in the index.
- Installed apps are checked against `trust.bin`, not against what was installed, so swapping an app's package for an older signed version of the same app (offline) isn't caught. Removing a repository forgets its serial.
- Apps installed before this change don't start until reinstalled (`apt verify` lists them).
- A lost boot key means new images need a new loader. A lost package key is handled as in §10, with `keys/trusted/`.

## 12. VT-d interrupt remapping

**Investigation.** DMA remapping (§10) gives each device its own domain: a page table holding only the buffers its driver registered with `dma_address`, unmapped and flushed before the memory is reused. But a device write to `0xFEExxxxx` isn't DMA. It's an interrupt message (MSI), and DMA remapping doesn't translate it. A compromised driver can point its device's MSI anywhere and raise any vector, an NMI or an SMI. Every interrupt Bhairav OS uses arrives through the legacy 8259 PIC as a wire: the kernel programs no LAPIC, IOAPIC, MSI or MSI-X. So no device has a legitimate reason to send an interrupt message.

| Item | Design | Checked by |
|---|---|---|
| Interrupt remapping | When every DRHD unit reports ECAP.IR, `Iommu::init` installs a 256-entry interrupt remapping table (xAPIC format) with every entry not present, then sets SIRTP and IRE. GCMD.CFI stays clear, so compatibility-format messages are blocked too. GSTS is read back: the log says "on" only if IRES is set and CFIS is clear. Blocked messages appear in the fault log with the device and reason. Without IR support the log says devices can still send interrupt messages. | `IOMMU=1`: every boot check passes with remapping on. `IOMMU=1 FAULT_TEST=msi`: the kernel aims the SATA controller's MSI at CPU 0 as an NMI, and the AHCI driver turns its interrupts on. Result: `blocked an interrupt message by device 0:31.2 (reason 0x22)`, and the system keeps running. With `IOMMU=dma-only`, the same NMI arrives: `ahci (task 10) crashed: non-maskable interrupt`. |

**Limits.**
- QEMU 8.2 doesn't model the compatibility-format block. It reports CFIS clear but passes such messages anyway, so the test uses the remappable format, which reaches our table. Real VT-d hardware blocks both formats. This hasn't been tried on real hardware.
- Drivers' MSI now get entries with source-id checking (SVT/SID), flushed through queued invalidation (§18). Without queued invalidation, entries can't change safely, so the I/O APIC and MSI both stay off.
- An NMI that does arrive (without interrupt remapping) is treated as a fault of whatever task is running, which kills that task.

## 13. ShoolLoader hardening and Secure Boot

| Item | Design | Checked by |
|---|---|---|
| Robust configuration parser | `shool.cfg` is checked completely. It must be 16 KiB at most, plain text (no control characters), and `key = value` lines only. It needs exactly one `kernel`, at most 32 distinct `module`s, and at most one each of `resolution` (320x200 to 16384x16384) and `diagnostic` (yes/no). Paths are absolute, printable and under 96 characters, with no `.` or `..` parts. Any error stops the boot with the line number, instead of being skipped or truncated. | UEFI, each re-signed so it reaches the parser: unknown key, second kernel, bad resolution, overlong path, control character, `..` path and a repeated module are each refused with "shool.cfg line N: …". |
| Memory map validation | The kernel (`Boot::collect`) doesn't trust either loader. It drops empty, wrapping and beyond-52-bit regions and page-aligns usable ones inward. Usable memory overlapping anything else is cut out (split in two when needed). Modules must lie in kernel memory, the direct map must be in the higher half, the kernel where it was linked, and the framebuffer sane (otherwise serial only). A built-in test runs every boot on a deliberately broken map (overlaps, unaligned, empty, wrapping, beyond any address). **Found and fixed:** Limine places modules in bootloader-reclaimable memory, which the kernel frees early, yet boot programs are read from there later. Their pages are now marked kernel memory. | Every boot: "memory map validation ok". On the real QEMU maps: 0 repairs. BIOS boots keep module pages out of reclaimable memory. |
| ELF validation | The loader checks the kernel: 64-bit little-endian x86_64 `ET_EXEC`, ELF version 1, 1 to 64 program headers inside the file, segments inside the file, page-congruent and not wrapping, all in the top 2 GiB with no two sharing a page, entry point in an executable segment, at most 64 MiB. Every `.elf` module gets the same header and segment checks. The kernel still checks programs fully when it starts them (§7). | A kernel with another machine type and a big-endian `notes.elf` (both re-signed) are refused, naming the file. |
| Boot protocol versioning | Shool protocol v2 (`BootInfo.flags`). The kernel embeds a `Shool::KernelHeader` (magic, inverted magic, min and max version). ShoolLoader finds it by scanning the kernel file and refuses, on screen and before handing over, a kernel that doesn't take its version. The kernel also checks `BootInfo.version` and `.size`. | A kernel patched to take only v1 (re-signed): "this loader speaks Shool protocol v2; the kernel takes v1 to v1". |
| Kernel handover validation | Before ExitBootServices, the loader requires NX and walks the new page tables. They must map every kernel page, the entry point, the stack, BootInfo (both ends), every module, the framebuffer, and the loader's own hand-over code (identity) where the protocol says. The kernel then validates BootInfo as above. | Every boot passes the walk. Diagnostic boots print "hand-over checked". |
| Signed module verification | §11. A module named in `shool.cfg` but missing now stops the boot instead of being skipped. | A missing `notes.elf` is refused. |
| Secure Boot integration | The build signs `BOOTX64.EFI` (Authenticode, `sbsign`) with `keys/secureboot.key`, made the first time with a self-signed certificate. `build/secureboot.cer` is what to enroll in a firmware's db. `make secure-boot-vars` makes OVMF variables with only that certificate enrolled and Secure Boot on, and `make run-secureboot` boots with them. The loader reads `SecureBoot`/`SetupMode`, shows the state and passes `FLAG_SECURE_BOOT`. The kernel logs it. | OVMF Secure Boot build with our key: the signed loader boots, and both the loader and the kernel report Secure Boot on. An unsigned loader and one signed by another key are refused by the firmware ("Access Denied"). |
| Failure recovery | Every loader error is shown, then after a key or 30 seconds the loader calls `Exit` back to the firmware, which tries its next boot option instead of halting. All errors happen before ExitBootServices. | Missing module, then Enter: the firmware reports "Load Error" for our entry and goes on to PXE. |
| Diagnostic boot mode | Hold D while booting, or set `diagnostic = yes`. The loader shows the checks it made for each file, the screen mode and the hand-over check, then waits for a key (60 s at most). It skips the splash and sets `FLAG_DIAGNOSTIC`. The kernel then logs the validated memory map and every module. | With `diagnostic = yes`: the loader's lines, the wait, then "[diag]" lines with the whole memory map. |

**Limits.**
- The Secure Boot key is a local self-signed one. Real machines trust Microsoft's keys by default, so booting there with Secure Boot on means enrolling `secureboot.cer` in the firmware (or a shim, not done). `make secure-boot-vars` also puts Microsoft's KEK in KEK (a `virt-fw-vars` default), though db holds only our certificate.
- The BIOS path has no Secure Boot. Limine checks hashes (§11), and the kernel reports "boot files not signature-checked".
- The Limine path's modules are checked against the map but not ELF-checked before the kernel starts them (the kernel's own ELF checks still apply).
- Diagnostic mode via the D key depends on the firmware buffering the key. In QEMU, keys typed on the serial console work, but the monitor's `sendkey` didn't reach OVMF.
- Failure recovery is "try the next boot option". There's no second, known-good boot image on the medium to fall back to.

## 14. Boot menu, modes, fallback, GPT

| Item | Design | Checked by |
|---|---|---|
| GPT partition tables | `make disk-image` builds `build/bhairavos.img`: a GPT (made with `sgdisk`) holding an EFI System Partition and a Bhairav data partition (type `B4A1F0E2-6D3C-4B8A-9E7F-2C5D1A0B3E64`, FAT32). The `fs` server recognizes the protective MBR. It reads the GPT header and entry array, checking both CRC32s, that `MyLBA` matches, and the partition bounds. It then serves only the data partition and never the ESP, and the FAT volume may not extend past it. A damaged primary header falls back to the backup at the disk's end. Disks without GPT (`disk.img`) work as before. | Disk image as the only disk: UEFI and BIOS boot it and `fs` mounts the data partition (fs-test passes). Primary header damaged (BIOS; OVMF repairs it on its own): "using the backup". Both damaged: the disk is refused and the system runs without files. |
| EFI System Partition | Partition 1 of the image (type EF00): `EFI/BOOT/BOOTX64.EFI` (signed ShoolLoader), the signed boot files, and Limine's enrolled config for BIOS (`limine bios-install` on the GPT disk). The ISO keeps its El Torito EFI image as before. | Both firmware types boot from it. |
| Multiple kernel configurations | `shool.cfg` holds entries (`entry =`, `title`, `like`, `kernel`, `module`, `mode`, `diagnostic`, `fallback`) plus global `timeout`, `default` and `resolution`. The old single-entry form still works (as an entry called "default"). The loader shows a menu: 1-9 picks, Enter the default, D adds diagnostics, and any key stops the countdown. Entries whose kernel isn't in the signed list are hidden. `limine.conf` has the matching entries for BIOS. | The menu lists normal, safe, recovery and diagnostic. Keys 2 and 3 start safe and recovery. Limine's second entry starts safe mode. |
| Recovery boot | `mode = recovery` → Shool protocol v3 `BootInfo.mode` (or Limine `cmdline: mode=recovery`) → `SystemInfo.bootMode`. init skips the self-tests. KamalShell runs no installed apps and opens a Terminal, which explains the repair (`apt verify`, `apt install`, `apt remove`). The network stays on, so repositories can be reached. The top bar says "Recovery mode". | Screenshot: Terminal open with the repair steps, "Recovery mode" in the top bar. |
| Safe-mode boot | `mode = safe`: no network (init hands KamalShell a closed network channel and starts no NIC driver or net server), no installed apps, no self-tests. The top bar says so. An unknown mode value from a loader is treated as safe. | Screenshot: "Safe mode: no network, no installed apps", "Offline", no installed apps in the dock. |
| Diagnostic mode | §13, now also its own menu entry. | §13 |
| Kernel fallback | When an entry fails to load (a missing or changed file, a bad ELF, a protocol mismatch), `fail()` frees every page that attempt allocated, jumps back to `efiMain` (`saveContext`/`restoreContext`, a small setjmp for the Microsoft ABI) and tries the entry's `fallback`: normal → previous → safe → recovery. Each entry is tried at most once, and unusable ones are skipped. With none left, it returns to the firmware (§13). `make PREVIOUS_KERNEL=…` ships a known-good kernel as `/boot/rudracore-previous.elf` (signed) for the "previous" entry. | A previous kernel shipped and the normal kernel changed: "hash doesn't match" → "trying its fallback instead" → the previous kernel boots. Normal (and everything `like` it) naming a missing module: normal, safe and recovery are each tried, then "no fallback left". |

| Boot-attempt counter | A kernel that loads but then crashes or hangs is caught too. ShoolLoader keeps a per-entry count in the UEFI variable `BhairavBootCount` (non-volatile; `Shool::BootCount`, tied to the entry list by a hash). It adds one just before the hand-over. Once the desktop has run for 10 s, KamalShell calls `SYS_BOOT_COMPLETE` (not for apps), and the kernel deletes the variable through the UEFI runtime services. An entry that reached 2 attempts without that is passed over for its fallback, unless it's picked in the menu. When the whole chain is used up, counting starts again from the chosen entry, so the machine is never locked out. The kernel calls the firmware at its physical addresses (no SetVirtualAddressMap). Shool protocol v4 passes the runtime table and marks the runtime regions (`EFI_MEMORY_RUNTIME`). These regions, plus ACPI NVS, are identity-mapped only in the kernel's own address space; user spaces never see them. Each call runs on a 64 KiB stack of its own, with interrupts off and the FPU state saved. The table's signature is checked, and both functions must lie in runtime memory. A fault inside the firmware is caught (logged) and the call fails instead of the kernel. The loader still speaks v3 to an older kernel (the "previous" entry), and doesn't count its boots: it couldn't clear them. | UEFI with persistent OVMF variables: a good boot gives "boot-attempt counter cleared". Two boots killed after the hand-over lead to "Bhairav OS didn't finish starting 2 times in a row", then safe mode starts and clears the counter, and the next boot is normal again. Six killed boots use up normal, safe and recovery, then "its fallbacks failed too: trying it again" and normal boots. Every boot also runs a self-test of the firmware trampoline (argument order, a caught fault). BIOS (Limine): "no UEFI runtime services", nothing counted. |

**Limits.**
- The boot-attempt counter has been tried on OVMF only. Real firmware calls its runtime services from the OS in ways OVMF doesn't. Some buggy firmware touches boot-services memory, which the kernel has reused by then. Such a fault is caught, but the counter then never clears, so normal boots end up in safe mode until the firmware is fixed (logged as "the firmware faulted"). The v3 path for an older "previous" kernel hasn't been booted.
- "Up" means the desktop ran 10 s. A crash after that isn't counted.
- Safe and recovery use the same kernel and boot programs as normal. They only reduce what userspace starts.
- The disk image's data partition is fresh on each build. `disk.img` stays the default data disk for `make run`/`shot`.
- The fs server serves one partition. The ESP isn't reachable from Bhairav OS, so boot files can't be updated from inside it yet.

## 15. TLS, certificates, randomness: review and negative tests

Reviewed this round, line by line: `tls.cpp`, `x509.cpp`, the RSA/ECDSA code in `pkey.cpp`, the AEAD/HKDF/HMAC parts of `crypto.cpp`, `http.cpp`'s body handling, and the kernel RNG.

| Item | Before → after | Checked by |
|---|---|---|
| X.509 validation | Added: the signed algorithm must equal the outer one (RFC 5280 4.1.1.2). DER must be strict (minimal lengths, no trailing bytes). Validity dates are range-checked. Key Usage is enforced (the leaf needs digitalSignature, CAs need keyCertSign), and so is Extended Key Usage (serverAuth for the leaf and any authority that limits it). | Negative test: a clientAuth-only certificate is refused. Real sites still verify (example.com, wikipedia.org). |
| Chain verification | Added: pathLenConstraint. Intermediates still need CA:true. | Negative tests: an intermediate without CA:true is refused; a good chain (leaf, intermediate, test root) is accepted. |
| Hostname validation | Added: a wildcard needs two labels after `*.` (`*.com` names nobody). Still SAN dNSName only, with no IP-address names. | Negative test: a certificate for another name is refused. |
| Trusted certificate store | `roots.bin` (the build machine's Mozilla bundle) is now a signed boot file (§11). `Tls::useRoots` lets tests bring their own authority without touching it. | §11 boot tests |
| RNG health checks | ChaCha20 known-answer test (RFC 8439 2.3.2). RDRAND start-up test (16 distinct outputs, never 0 or all ones) and a continuous test (repeats turn it off). SP 800-90B-style repetition-count (C = 21) and adaptive-proportion (410 of 512) tests on 1024 cycle-counter samples, assuming 1 bit per sample. `fill()` refuses output unless the known answer is right and a source is healthy. The `random` syscall then returns IO_ERROR, and TLS checks it (it used to ignore it). | Every boot logs "[rand] health: ChaCha20 known answer ok, RDRAND …, cycle-counter source ok". |
| Cryptographic implementation review | Found and fixed. **TLS:** the session-id echo, legacy version, compression and exact extension block are now checked; only offered extensions are accepted, each once. Handshake order is enforced (EE → Certificate → CertificateVerify → Finished). No unencrypted handshake records after the key change, no handshake data across a key change, CCS only as one byte 1 during the handshake. Plaintext is limited to 2^14+1 (record_overflow). Post-handshake messages are parsed strictly, and a KeyUpdate request is answered (it was ignored). The Certificate message's request context and length are checked exactly. **RSA:** at least 2048 bits and an odd e ≥ 3 (1024 bits and e = 1 were accepted). **ECDSA:** exactly SEQUENCE{r, s} of positive integers. **HKDF:** bounds on `info` and the output length. Confirmed sound: PKCS #1 v1.5 compares the whole encoding (no Bleichenbacher '06 forgery), ECDSA checks r and s ranges and the point is on the curve, PSS checks salt length, Ed25519 rejects S ≥ L, both AEADs check the tag in constant time before decrypting, X25519 clamps and the all-zero shared secret is refused. AES is still table-based (cache timing, documented in `crypto.h`). | The negative tests below. All boot vectors still pass. |
| Key lifecycle management | Traffic keys and secrets are wiped on `close()` and when the peer closes, not only in the destructor. Finished keys, HMAC pads and hash states, HKDF blocks, decrypted buffers and the ephemeral X25519 key are wiped once used. The client traffic secret is kept only to answer KeyUpdate. Signing keys (boot, package, Secure Boot) live on the build machine only, made with `umask 077` (§11, §13). | Code review |
| TLS 1.3 negative testing | `make tls-negative` (`scripts/tls-negative.sh`) builds a throwaway PKI, starts `openssl s_server`s that misbehave and a tampering proxy (`scripts/tls-proxy.py`), and boots. tls-test fetches the test authority and checks 17 scenarios. Two controls must succeed: a good server, and a full page with close_notify. These must be refused: wrong host, expired, self-signed, TLS 1.2 only, clientAuth-only EKU, non-CA intermediate, 1024-bit RSA, no common group, client-certificate request, only an unoffered cipher, a ServerHello bit flip, an encrypted-record bit flip, a record relabelled as handshake, a plaintext handshake injected after ServerHello, and a response cut short without close_notify. | "tls negative check: 17 of 17 scenarios behaved correctly". |
| Truncation | `Tls::closedCleanly()`. `httpGet` no longer treats a receive error as the end of the body, checks Content-Length, needs the final chunk of a chunked body, and otherwise (over TLS) needs close_notify. | The truncation scenario: 4017 bytes arrived without close_notify and were flagged. |

**Limits.**
- No revocation checking (OCSP/CRL), no name constraints (a critical one is refused, not evaluated), no IP-address names.
- AES-GCM uses lookup tables (timing leak to code on the same machine). ChaCha20-Poly1305 is preferred in our ClientHello.
- The RNG tests assume 1 bit of entropy per cycle-counter sample. That's an estimate, not a measured min-entropy. Without RDRAND (QEMU's default CPU), early-boot randomness rests on timing alone.
- A KeyUpdate split across records, or several messages straddling records after the handshake, is refused rather than reassembled.
- The negative tests run only when the harness is running (`make tls-negative`). A normal boot logs "skipped".

## 16. ACPI

One module, `arch/x86_64/acpi.{h,cpp}`, replaces the IOMMU's private table walk.

| Item | Design | Checked by |
|---|---|---|
| RSDP discovery | From the loader (UEFI configuration table, or Limine). Checked: signature, the ACPI 1.0 checksum (20 bytes), and on 2.0+ the extended checksum (36 bytes). | Both firmware types. |
| XSDT/RSDT | The XSDT on ACPI 2.0+, else the RSDT. A damaged XSDT falls back to the RSDT. Every table is mapped, its length bounded (36 bytes to 16 MiB) and its checksum checked before use; a bad one is skipped and counted. | SeaBIOS (ACPI 1.0, RSDT, 6 tables) and OVMF (XSDT, 7 tables): "checksums ok". |
| MADT | Local APIC address (and its 64-bit override), PCAT_COMPAT, enabled CPUs (local APIC and x2APIC entries), I/O APICs, and interrupt source overrides (ISA IRQ → GSI). | OVMF: local APIC 0xfee00000, I/O APIC 0xfec00000, 5 overrides, IRQ0 → GSI 2, 8259s present. With `-smp 2`: 2 CPUs. |
| FADT | SCI, SMI command and ACPI_ENABLE, PM1a/b control blocks (the extended GAS fields win when they're I/O), the PM timer (24/32-bit), the reset register and value, X_DSDT, IA-PC boot flags (8042, VGA, MSI, CMOS RTC), and hardware-reduced. | SCI 9, PM1a 0x604, PM timer 0x608, reset supported, 8042 present. |
| HPET | Base address (memory space only), then its own capabilities register: tick period (accepted only if 1 fs to 100 ns), timers, 64-bit counter. | 3 timers, 100 MHz, 64-bit. |
| MCFG | ECAM ranges: base, segment, bus range (an inverted range is dropped). PCI configuration still goes through ports 0xCF8/0xCFC. | Segment 0, buses 0-255 at 0xe0000000. |
| DMAR | Now found (checksum-checked) through `Acpi::find`. | VT-d boots as before (§10, §12). |
| SRAT where required | Processor (local APIC, x2APIC) and memory affinity entries, enabled ones only: domains, CPUs, ranges, bytes. Reported. The kernel is single-CPU and doesn't place memory by domain yet. | QEMU with 2 NUMA nodes: "2 NUMA domains, 2 CPUs, 3 memory ranges, 255 MiB". |
| Power management | Shutdown: S5, with SLP_TYPa/b read from the DSDT's `Name(_S5, Package…)`. It switches to ACPI mode (SMI_CMD ← ACPI_ENABLE, waits for SCI_EN) if needed, then writes SLP_TYP\|SLP_EN to PM1a (and PM1b). Restart: the FADT reset register, then the 8042, then a triple fault. `SYS_POWER` (new) refuses apps (ACCESS_DENIED). KamalShell offers Restart and Shut Down in the lotus menu, and does what the Terminal's `shutdown`/`reboot` ask, ignoring that request from any other program. | Terminal `shutdown`: "powering off (S5)", and QEMU exits by itself. `reboot`: the kernel starts a second time. |
| Battery and thermal information | Without an AML interpreter, `_BST`/`_BIF`/`_TMP` can't be evaluated. The kernel reports what the DSDT/SSDTs declare: battery devices (EisaId PNP0C0A) and ThermalZone objects. | QEMU: 0 and 0, reported as "readings need an AML interpreter: not available". |

**Limits.**
- The kernel itself has no AML interpreter: the acpi server does that work (§17-§20). The kernel's own S5 is the fallback, with `_S5` found by pattern, which covers the common encodings (ZeroOp, OneOp, BytePrefix).
- Hardware-reduced ACPI machines (no PM1 blocks) can't be powered off this way, and the log says so.
- Before powering off, nothing is told to close: the fs server writes every change before it replies, so no data waits in memory, but open apps aren't asked to save.
- The MADT drives the APICs (§18), and the FADT's PM timer calibrates the TSC. The HPET, MCFG and SRAT data isn't used yet: the PIT and port-based PCI configuration stay, and the kernel uses one CPU.
- Damaged-table handling (skip and count) was checked by code review only: QEMU fixes the checksums of the tables it builds.

## 17. The ACPI server (AML interpreter)

Step 1 of 4 toward APIC interrupts, battery and thermal readings, and sleep: the firmware's AML now runs, in userspace.

| Item | Design | Checked by |
|---|---|---|
| Interpreter | uACPI 7.0.0 (MIT, released 2026-10-16), vendored in `third_party/uacpi` (its `source/` and `include/`, plus its LICENSE) and linked only into `userspace/programs/acpi`. The server implements uACPI's host interface on Bhairav's syscalls. It's single-threaded: semaphores are counters, spinlocks do nothing, and queued work runs at once. It keeps a cache of up to 24 physical mappings (a program may hold 32). | SeaBIOS and OVMF: QEMU's DSDT loads (1705 ops in about 12 ms), 36 devices, 261 namespace objects. |
| Isolation | AML is the firmware vendor's code and can name any I/O port or physical address, so it runs outside the kernel, behind two capabilities only init gets (only when there's ACPI) and only the server receives (never in safe mode). **Firmware** (`SYS_FIRMWARE_MEMORY`) maps physical memory that isn't RAM, kernel, loader or screen memory (write-back for ACPI tables, uncached otherwise), and gives PCI configuration space (`SYS_FIRMWARE_PCI`, segment 0). **Firmware ports** cover every port except the ones the kernel and drivers own: PICs and their trigger registers, PIT, PS/2, CMOS clock, PCI configuration, serial. 16- and 32-bit port I/O was added for it (`SYS_PORT_IN_WIDE`/`OUT_WIDE`). Both are "hardware" objects, so apps can never receive them. | Each start: "firmware access limits hold": the PIC's port and a page of RAM are refused. |
| What it proves | `\_S5` evaluated (not pattern-matched); the PCI root bridge's `_PRT`; battery (PNP0C0A), AC adapter (ACPI0003), power button (PNP0C0C) and thermal zones found through the namespace, `_STA` respected. | QEMU: `\_S5` = 0, 0 (agrees with the kernel's pattern match); `_PRT` has 128 entries, all through link devices (we're in PIC mode); no battery, AC, power button or thermal zone (QEMU has none). |

**Next (not done yet).**
1. ✅ APIC (§18): local APIC and I/O APIC, `\_PIC(1)`, `_PRT` routing, ISA overrides, the 8259s masked. (The APIC timer is still to do.)
2. ✅ Events, battery, thermal (§19): the SCI, GPEs, the power button, an EC driver, `_BIF`/`_BIX`/`_BST`, `_PSR`, `_TMP`/`_CRT`, shown in KamalShell.
3. Sleep (§20): ✅ S5 through uACPI (`_PTS` first). S3 not done: it needs a display driver first (§20).

**Limits now.** The kernel's own power-off still uses its pattern-matched `\_S5` (it will move to the server). Short stalls (`uacpi_kernel_stall`) spin a rough count, because the clock counts milliseconds. A 1- or 2-byte PCI config write is a read-modify-write of the dword. A semaphore wait that would block returns a timeout (one thread: nobody could signal it).

## 18. From the 8259 PICs to the APICs

Step 2 of 4 (§17).

| Item | Design | Checked by |
|---|---|---|
| Local APIC and I/O APIC | `arch/x86_64/apic.cpp`, from the MADT: the local APIC is turned on (IA32_APIC_BASE, spurious vector 0xFF, TPR 0), and the I/O APIC's inputs are counted and all masked first. The kernel keeps its IRQ lines 0-15 (vector 32 + line): `Pic::mask`/`unmask`/`endOfInterrupt` act on the APICs once they're on, so drivers, IRQ objects and the PIT timer don't change. | Every boot: "interrupts through the I/O APIC (24 inputs, 2 PCI routes); the 8259 PICs are masked". The scheduler keeps ticking (PIT through GSI 2). |
| PCI routing through `_PRT` | The acpi server evaluates `\_PIC(1)` (uACPI's interrupt model), reads the PCI root's `_PRT`, resolves link devices through their `_CRS` (GSI, trigger, polarity), and for each bus-0 function with an interrupt pin reports `GSI → its line` (`SYS_FIRMWARE_INTERRUPTS`, firmware handle, RIGHT_WRITE). Then it asks the kernel to switch. Any function it can't route, or a route the kernel refuses (a line it owns, an input that doesn't exist), means no switch: the machine stays on the PICs. | 3 PCI interrupts routed. Network interrupts arrive after the switch: DHCP and HTTP work over e1000 and rtl8139. |
| ISA IRQs | From the MADT's overrides, with their polarity and trigger (ISA default: edge, active high), except lines a PCI route took. The PICs' open lines are opened on the I/O APIC, then both PICs are masked. | Keyboard and mouse: a click opens the Terminal, and typing works. |
| With VT-d interrupt remapping | Remapping blocks compatibility-format interrupts (§12), which would cut off the I/O APIC on real hardware. So each I/O APIC input gets its own remapping entry (index = input; vector, trigger, this CPU) that only the I/O APIC may use: its requester id comes from DMAR's device scope, with SVT = 1. The redirection entries use the remappable format. Changing entries while remapping is on needs the interrupt entry cache flushed, which only the queued invalidation interface can do, so the IOMMU now uses that interface when it remaps interrupts (context-cache and IOTLB invalidation too, with wait descriptors). | `IOMMU=1`: every check passes through the remapping entries. `FAULT_TEST=msi` now aims the SATA controller's MSI at entry 2, which is live (the timer's): blocked, reason 0x26 (requester id doesn't match). |
| MSI / MSI-X | `SYS_DEVICE_MSI` (device handle, RIGHT_MMIO) returns an IRQ handle. The kernel programs the capability itself (`arch/x86_64/msi.cpp`): vector 32 + line (lines 16-31), this CPU, edge, INTx off. A driver never chooses the address or data. With remapping, the message uses the remappable format through entry 128 + line, which only that device's requester id may use. While the driver is busy, the vector is masked at the device (MSI-X, or MSI with per-vector masking). Without masking, a message that arrives meanwhile is held as pending. | `NIC=e1000e`: "0:2.0 interrupts by MSI (vector 48)", then DHCP, DNS and HTTP. `IOMMU=1 NIC=e1000e`: the same, "through its own VT-d remapping entry". `IOMMU=1 FAULT_TEST=msi`: still blocked (0x26). |

**Limits.**
- The timer is still the PIT (through GSI 2). The local APIC timer, calibrated by the HPET, is a follow-up.
- Bus 0 only: devices behind PCI bridges would need the bridge's `_PRT` or swizzling. Everything QEMU has is on bus 0.
- One I/O APIC (the MADT's first) and one CPU.
- MSI: one message per device (MSI, else MSI-X entry 0), lines 16-31. A driver that starts before the acpi server has switched to the APICs gets NOT_FOUND and uses its pin. With remapping, a device behind a PCIe-to-PCI bridge sends with the bridge's requester id and would be blocked.
- The switch happens when the acpi server gets there, early in boot, while drivers start. Interrupts are off for the switch itself, so it's atomic, and level-triggered lines re-assert, but an edge that arrives exactly during it could be lost.

## 19. ACPI events, battery and thermal

Step 3 of 4 (§17).

| Item | Design | Checked by |
|---|---|---|
| SCI | The kernel gives init an IRQ object for the FADT's SCI line (`INIT_HANDLE_SCI`, level-triggered), when no driver's line shares it. init passes it to the acpi server, which binds it to a channel and, in its loop, runs uACPI's SCI handler (fixed events, GPEs) and acknowledges. Work uACPI queues (GPE methods, notifications) runs after the handler returns, never inside it. GPEs with AML handlers are enabled (`uacpi_finalize_gpe_initialization`). | "listening for ACPI events (SCI)". Under the APIC, the SCI arrives through the I/O APIC (ISA 9, level, from the MADT), and with VT-d through its remapping entry. |
| Power button | A fixed-event handler, plus a notify handler (0x80) on PNP0C0C devices. A press turns the machine off (S5). | QEMU `system_powerdown`: "power button pressed: turning off", "powering off (S5)", and QEMU exits. Same on UEFI with VT-d. |
| Embedded controller | A driver for the ACPI EC protocol (status/command and data ports from the PNP0C09 device's `_CRS`; read 0x80, write 0x81, IBF/OBF waits with a timeout, so a stuck EC gives the AML an error instead of a hang), installed as the EmbeddedControl address space handler before anything reads batteries. | Not testable in QEMU (it has no EC). Code review only. |
| Battery | For each present PNP0C0A battery: last full capacity (`_BIX` field 3, or `_BIF` field 2), `_BST` state (charging, discharging, critical) and remaining capacity, summed over batteries into a percentage. ACPI's "unknown" (0xFFFFFFFF) is skipped. | Test SSDT (`scripts/acpi-test.asl`, `make shot ACPI_TEST=1`): "1 battery, 75% charging". |
| AC adapter | ACPI0003 `_PSR` (online if any adapter is). | Test SSDT: "on AC". |
| Thermal | Every ThermalZone's `_TMP` (tenths of a kelvin, accepted from 100 K to 600 K), the hottest one reported with its `_CRT`. | Test SSDT: "45.0 C (critical at 100 C)". |
| KamalShell | A power channel to the acpi server (`protocol/power.h`), set up by init. The shell asks every 5 seconds and the answer joins its wait loop. The top bar shows a battery icon with the percentage ("+" when charging; red when critical or at 10% or less) and the temperature (red within 10 °C of critical). With no acpi server (safe mode, no ACPI), the channel is closed and nothing is shown. | Screenshot with the test SSDT: battery 75% +, 45°C. Safe mode: KamalShell runs without the server. |

| Thermal policy | The acpi server watches every thermal zone (`_TZP`, or every 5 s; every `_TSP` while cooling; at once on Notify 0x80/0x81, which also re-reads the trip points). At `_CRT` it turns the machine off (S5, the ACPI way). At `_HOT` it logs once: that point asks for S4, which Bhairav lacks. At `_PSV` passive cooling starts with ACPI's formula, ΔP = `_TC1`·(Tn − Tn−1) + `_TC2`·(Tn − `_PSV`). It continues until the zone is below `_PSV` and the cap is back at 100% (never below 10%). The cap goes to the kernel (`SYS_FIRMWARE_PERFORMANCE`, firmware handle, RIGHT_WRITE). There it limits HWP's highest ratio, or, without HWP, uses Intel on-demand clock modulation (IA32_CLOCK_MODULATION, 8 or 16 steps). A `_PSV` without `_TC1`/`_TC2` gets no passive cooling (logged). KamalShell shows the cap next to the temperature, in red. | Test SSDT (`scripts/thermal-test.asl`, `make shot THERMAL_TEST=1`): the zone warms past 70 C (cap 70%, then 54%), cools (71%, then "back at 100%"), then climbs: 10%, "past its hot 85.0 C", "past its critical 90.0 C", S5, and QEMU exits. QEMU's CPU has neither HWP nor clock modulation, so the log says it can't be throttled. |

**Limits.**
- Thermal throttling has been tested only as policy: the kernel's HWP and clock-modulation paths haven't run on hardware. No active cooling (`_ACx`/`_ALx` fans): on most laptops the embedded controller runs the fans itself. Only the CPU the kernel runs on is capped (the kernel uses one CPU).
- The power button turns the machine off at once, without asking open apps to save (the fs server keeps no unwritten data).
- No EC query events (`_Qxx`): battery and temperature are read when asked (every 5 s), not on notification. No ECDT (an EC needed before the namespace loads).
- The SCI can't share a line with a driver's interrupt (one owner per line): then there are no events, and the log says so.
- Battery percentage mixes units if two batteries report different ones (mWh and mAh). Rare.

## 20. Sleep states

Step 4 of 4 (§17), in part.

| Item | Design | Checked by |
|---|---|---|
| S5 through ACPI | The acpi server turns the machine off the ACPI way: `uacpi_prepare_for_sleep_state(S5)` runs `\_PTS(5)` and `\_GTS`, then `uacpi_enter_sleep_state(S5)` writes SLP_TYP, then SLP_EN. The power button, KamalShell's Shut Down and the Terminal's `shutdown` all go through it (power protocol `PowerOff`). If ACPI can't, or there's no server (safe mode), the kernel's own S5 (§16) is the fallback. | Power button and Terminal `shutdown` (BIOS, and UEFI with VT-d): "turning off through ACPI (S5)", QEMU exits, and the kernel's fallback never runs. |
| S3 (suspend to RAM) | **Not done.** Assessment below. | — |

**What S3 needs, and the blocker.** Waking from S3 starts the CPU in real mode at the FACS waking vector with every device reset (QEMU does the same). The pieces:
1. A wake trampoline below 1 MiB: real mode → long mode, with its own page tables mapping it and the kernel.
2. Saving and restoring the CPU's state (control registers, GDT/IDT/TSS with the busy bit cleared, EFER, PAT, FPU), and re-initialising what the kernel owns (PICs or APICs and the I/O APIC entries, PIT, serial, and VT-d's root table, queued invalidation, interrupt remapping and translation).
3. Returning to the acpi server where it entered sleep. uACPI's cache-flush hook (`UACPI_ARCH_FLUSH_CPU_CACHE`, called just before SLP_EN) can trap into the kernel to save state and sleep, then jump back out of `uacpi_enter_sleep_state` on wake.
4. Suspend and resume in every driver: stop DMA before (AHCI command engine, e1000 and rtl8139 rings), re-initialise after (they come back reset). Orchestrated by init, which would have to keep a channel to each driver.
5. **The display.** Bhairav draws on the framebuffer the firmware set up at boot, and has no graphics driver. After S3 the firmware doesn't set it up again (SeaBIOS doesn't re-run the VGA BIOS; OVMF's GOP is gone), so the screen stays black. It needs a display driver that can set the mode itself: in QEMU the Bochs/VBE "dispi" registers of the standard VGA device, on real hardware a GPU driver.

1-4 are a large but well-understood piece of work. 5 is the blocker: until there's at least a QEMU display driver, S3 would resume to a black screen.

## 21. Memory management

Kernel maturity, step 4.1. A program's address space is now regions (`core/vm.{h,cpp}`), not pages mapped up front.

| Item | Design | Checked by |
|---|---|---|
| Physical memory | Commit accounting: memory a program reserves is *promised* (`Pmm::promise`), not allocated. `userCanUse` offers only free − promised − the 4 MiB kernel reserve, so a later touch always finds its page. There's also a low-water mark (reserve + ~1.5% of RAM): below it, a reclaimer runs (memory-mapped files' pages go first). Allocation below 4 GiB serves devices with 32-bit DMA (`MEMORY_BELOW_4G`; the RTL8139 driver uses it). | `SECURITY_TEST=1`: oom-test's quotas and reserve hold as before (system service 122 of 246 MiB, apps a quarter, then OUT_OF_MEMORY with no panic). RTL8139: DHCP and HTTP work. |
| Virtual address management | Each task has a sorted region list (up to 512): Anonymous, Shared (an object's own pages), or Copy (copy-on-write). New regions take the first gap from 4 GiB, with an unmapped guard page after each. `memory_unmap` works on any region and frees its private pages; freed addresses are reused. `memory_protect` makes a region read-only, or writable again if it was made writable. The old fixed table (32 mappings) and the address bump allocator are gone. | harden-test: an unmapped 8 MiB block's address comes back for the next one, zeroed. A read-only region refuses writes, even the kernel's (`random` → BAD_ADDRESS); after protect it's writable again. Unmapping nothing → NOT_FOUND. |
| Demand paging | Private memory, the stack and `.bss` are zero-filled on first touch. The page-fault handler resolves the fault, or blocks the task for a pager, or ends it (invalid access). System calls fault in the user buffers they're given before touching them (`Vm::prepare`); a buffer waiting on a pager makes the whole call run again once the page is there. | harden-test: 8 MiB reserved costs < 2 MiB of RAM; touched pages are zero and keep what's written. |
| Copy-on-write | Copy regions read an object's pages in place and copy a page on its first write. Programs run from their image this way. Boot programs share the module's own pages (nothing copied at all). An installed app's image is sealed first, copied if it isn't, so the caller can't change code under it. Writable data is copied when first written, and `.bss` and the tail of a partial page are zero-filled. Images whose segments share pages keep the old copy-in path. `memory_map(MAP_COPY)` gives programs the same. | Every boot program starts this way (all boot checks pass). harden-test: a MAP_COPY view sees the object until it writes, then keeps its own page; the object doesn't change. Each crafted app still gets the code it was given, though the test rewrites the image between spawns. |
| Memory-mapped files | Paged memory objects (`memory_create_paged`): a pager (here the fs server) gets a `PageRequest` on a channel for each missing page, and answers with `memory_supply`. Faulting tasks wait for it. `Files::map(path, size, copy)` maps a file read-only, or copy-on-write. After a file is written or removed, the fs server stops answering for its old mappings: its clusters may hold another file now. A touch of a page not yet read then ends the program, like touching a truncated file elsewhere. | fs-test: a 150 KiB file mapped matches byte for byte. A copy-on-write view of it is changed while the file and another view aren't. |
| Shared-memory authorization | `memory_seal` (needs RIGHT_WRITE and RIGHT_REVOKE): the contents never change again, for anyone. Writable shared mappings everywhere become read-only, and `memory_info` reports MEMORY_SEALED, so a receiver can check it once and trust it. A shared mapping is writable only with RIGHT_WRITE, and never for a read-only or sealed object. Device memory is marked as such (`hardware`), not "not owned", so boot files can be handed to apps. | harden-test: sealing without RIGHT_REVOKE → ACCESS_DENIED; after sealing, the existing writable mapping refuses writes; a MAP_COPY of the sealed object is writable. |
| Per-process accounting | Each region counts the pages it promised (charged to the task's quota) and the private pages it holds. `task_list` reports each task's memory in use, reserved, shared, regions and CPU time. `kernel_stats` reports the heap, page tables, promises and file pages. System Monitor shows the ten tasks holding the most. | Built; Monitor not checked on screen. |
| Memory pressure | When available memory drops below the low-water mark, pages of memory-mapped files are dropped (unmapped everywhere, freed): their pager can supply them again. The kernel heap tries reclaim before failing. | Not triggered in a test yet. |
| OOM without panic | A fault that can't get a page ends the app holding the most memory, and the fault is retried; if that's the faulting app, it's ended (logged). `Sched::kill` ends a task that isn't running, freeing everything at once. Programs never make the kernel panic: their memory is promised up front, and kernel objects come out of the reserve. | oom-test (above). The OOM-kill path itself isn't triggered in a test: with commit accounting, it needs RAM gone that was promised. |
| Kernel heap diagnostics | A guard word after every block (where there's room), checked on free ("written past its end" panics). Freed small blocks are filled with 0xDE. Each block taken from a free list is checked, and every free list is walked in the boot self-test. Counters: peak, allocations, frees, failures, per-size-class blocks and pages. Logged on diagnostic boots and before a heap panic. | Every boot: the heap self-test includes the free-list check. |

**Limits.**
- One CPU still: TLB entries are flushed only on the CPU that changes a mapping (SMP needs shootdowns, step 4.3).
- File pages are dropped in object order, not least recently used. The fs server serves at most 15 mapped files at once (one wait call), and mapped files are read-only (no shared writable file mappings, no write-back).
- A paged object's page tables aren't promised (they come out of the reserve's margin).
- A system call whose buffer waits on a pager runs again from the start; calls validate their buffers before acting, so nothing is done twice, but a call that acted first and validated later would.

## 22. Processes and threads (step 4.2)

A process (`core/process.{h,cpp}`) holds the address space, handles, quota, regions, group, limits, exit status and event channel. Threads (`Task`) hold their stack, registers, state and TLS base. A process's id is its first thread's id.

- **Threads:** `thread_create`, `thread_exit` and `thread_join` (exit codes, timeouts). The last thread to end ends the process. `exit` ends every thread.
- **Thread-local storage:** each thread has its own FS base. The PT_TLS segment is in `userspace/link.ld`, and the runtime builds each thread's block, so `thread_local` works.
- **Synchronization:** futexes are keyed by physical address, so threads of different processes sharing memory meet too. `Kapala::Mutex` and `Condition` are built on them, and the userspace heap is now locked.
- **Process handles:** spawn with `SPAWN_HANDLE`. `process_wait` returns the exit code. `process_info` gives the fault vector, address and RIP after a crash.
- **Exit codes:** the program's own, or EXIT_FAULT, EXIT_KILLED, EXIT_CPU_LIMIT or EXIT_OUT_OF_MEMORY when the kernel ended it.
- **Groups:** a child joins its parent's group, unless spawned with `SPAWN_NEW_GROUP`. `SIGNAL_GROUP` reaches the whole group, and an app may signal only apps.
- **Limits:** `process_limit` lowers memory, objects, threads or CPU time, and never raises them.
- **Signals equivalent:** events are messages on a channel the process registers (`process_events`). SIGNAL_TERMINATE arrives as an event, and ends the process if it doesn't listen. SIGNAL_KILL always ends it. Faults end the process; there are no asynchronous handlers.
- **Tested:** thread-test, 25 checks. It covers TLS, a contended mutex, a condition variable, join, futex rules, wait, terminate as an event, kill, the CPU limit, fault post-mortem, group signal and the thread limit.

## 23. SMP (step 4.3)

- **AP startup:** `ap_start.S` is a real-mode → long-mode trampoline in a page below 1 MiB, with its page tables below 4 GiB. CPUs start with INIT, then STARTUP twice. Each copies the boot CPU's CR0, CR4 and PAT.
- **Per-CPU data:** a TSS per CPU in one GDT. `str` tells a CPU which one it is.
- **Per-CPU scheduler:** each CPU has its own ready queues and idle task. A ready task goes back to the CPU it last ran on, unless another CPU is less busy by more than one task. An idle CPU gets a reschedule IPI, and a CPU with nothing to run takes work from the busiest.
- **Timers:** each CPU has a local APIC timer at 1 ms, measured against the TSC. The PIT keeps the time on the boot CPU.
- **Kernel lock:** a recursive ticket lock. `InterruptGuard` takes it, so every existing critical section is serialized across CPUs, while user code runs in parallel.
  - Its depth travels with the task, since kernel tasks can switch inside a guard.
  - It's released in `interrupts.S` after the stack switch, so no CPU can resume or free a thread whose stack another CPU is still on.
- **Interrupt distribution:** the I/O APIC lines and MSIs go to the CPUs in turn. The timer line stays on the boot CPU.
- **IPIs:** reschedule, TLB and stop.
- **TLB shootdowns:** every `unmap`, `take` and `update` flushes the other CPUs that have the address space loaded (each space tracks them in `cpuMask`), or every CPU for kernel addresses. A CPU waiting for the kernel lock still services shootdowns and a panic's stop, so neither can deadlock.
- **Ending threads on other CPUs:** a thread running elsewhere is marked dead and its CPU gets an IPI. Its stack is freed only once no CPU is on it.
- **Panic:** stops every other CPU.
- **Tested (`SMP=4`):** 4 CPUs come up, and every boot check passes, including thread-test and harden-test. 1000 IPC round trips take 106 ms, against 2.3 s on 1 CPU. 1 CPU still passes everything.

**Performance (step 4.4).**
- **Instrumentation:** `core/counters.h` keeps relaxed-atomic counters: system calls, interrupts, page faults, switches with their TSC time, kernel-lock acquisitions, contended waits and wait time, IPIs, shootdowns, and kernel heap allocations with their time. `kernel_counters` reads them.
- **Timer resolution:** `time_ns` is the TSC in nanoseconds.
- **Fairness:** a wake-up jumps the queue at most once per time slice.
- **perf-test** (every boot) measures and reports:
  - timer resolution and sleep accuracy (a sleep must never end early)
  - IPC round-trip latency
  - context-switch cost
  - private-memory and heap allocation cost
  - fairness: the least-served spinner must get at least a quarter of the busiest's share
  - kernel-lock contention
- **Stress test** (part of perf-test): 8 threads share a mutex-protected list, the heap and yields. Every item is checksummed and accounted for, and each join has a 30 s deadline, so a deadlock fails the test.
- **Results:** 21/21 on 1 CPU. On 4 CPUs under QEMU's software emulation, the stress test passes, fairness is 36% (94% on 1 CPU), and the kernel lock is contended in 34% of acquisitions during the stress test. That contention is the main scaling limit.

**Limits.** It's one big kernel lock, not fine-grained locking: kernel work doesn't scale across CPUs. Up to 16 CPUs, xAPIC only. MTRRs are left as the firmware set them, and machine-check banks are set up only on the boot CPU. Not tried on real hardware.

// nvme: the NVMe disk driver (NVM Express 1.4, the parts a disk needs).
// One admin queue pair, one I/O queue pair, polled (no interrupts);
// namespace 1, 512-byte blocks. Transfers go straight to and from the
// client's buffer by DMA (through the IOMMU when there is one).
//
// Handles from init:
//   1: the NVMe controller (PCI device)
//   2: a channel to its client, the file system server (protocol/block.h)

#include <kapala/channel.h>
#include <kapala/protocol/block.h>
#include <kapala/sys.h>
#include <kapala/text.h>

extern "C" void* memset(void* dest, int value, unsigned long n);

using namespace Kapala;
namespace Block = Kapala::Protocol::Block;

namespace {

constexpr Sys::Handle DEVICE = 1;
constexpr Sys::Handle CLIENT = 2;

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned;
using u64 = unsigned long;

constexpr u64 PAGE = 4096;
// Controller registers
constexpr u64 CAP = 0x00, CC = 0x14, CSTS = 0x1C, AQA = 0x24, ASQ = 0x28, ACQ = 0x30, DOORBELLS = 0x1000;
constexpr u32 CC_ENABLE = 1, CSTS_READY = 1, CSTS_FATAL = 2;
// Commands
constexpr u8 ADMIN_CREATE_SQ = 0x01, ADMIN_CREATE_CQ = 0x05, ADMIN_IDENTIFY = 0x06;
constexpr u8 IO_FLUSH = 0x00, IO_WRITE = 0x01, IO_READ = 0x02;

constexpr u32 ENTRIES = 64; // per queue (capped by CAP.MQES)
// The driver's own DMA memory, one page each.
constexpr u64 ADMIN_SQ = 0, ADMIN_CQ = 1, IO_SQ = 2, IO_CQ = 3, IDENTIFY = 4, PRP_LIST = 5, PAGES = 6;

struct Command {
    u32 dw0; // opcode, command id << 16
    u32 nsid;
    u32 reserved[2];
    u64 metadata;
    u64 prp1, prp2;
    u32 dw10, dw11, dw12, dw13, dw14, dw15;
};
static_assert(sizeof(Command) == 64);

struct Completion {
    u32 result, reserved;
    u16 sqHead, sqId;
    u16 commandId;
    u16 status; // bit 0: phase; bits 1-15: status
};
static_assert(sizeof(Completion) == 16);

struct Queue {
    Command* sq = nullptr;
    Completion volatile* cq = nullptr;
    u32 tail = 0, head = 0, size = 0;
    u16 phase = 1;
    u32 id = 0;
};

class Disk {
public:
    bool start() {
        long bar = Sys::deviceBar(DEVICE, 0);
        _regs = bar > 0 ? static_cast<u8 volatile*>(Sys::memoryMap(static_cast<Sys::Handle>(bar))) : nullptr;
        if (not _regs)
            return fail("can't map the controller's registers");
        u64 cap = read64(CAP);
        _stride = 4u << ((cap >> 32) & 0xF);
        _timeoutMs = ((cap >> 24) & 0xFF) * 500 + 500;
        u32 entries = static_cast<u32>((cap & 0xFFFF) + 1);
        if (entries > ENTRIES)
            entries = ENTRIES;
        if ((cap >> 48 & 0xF) != 0)
            return fail("the controller can't use 4 KiB pages");

        long memory = Sys::memoryCreate(PAGES * PAGE);
        _memory = memory > 0 ? static_cast<u8*>(Sys::memoryMap(static_cast<Sys::Handle>(memory))) : nullptr;
        long physical = memory > 0 ? Sys::dmaAddress(DEVICE, static_cast<Sys::Handle>(memory)) : -1;
        if (not _memory or physical < 0)
            return fail("can't get DMA memory");
        _physical = static_cast<u64>(physical);
        memset(_memory, 0, PAGES * PAGE);

        // Reset, then the admin queues, then enable (4 KiB pages, NVM
        // command set, 64-byte submissions, 16-byte completions).
        write32(CC, read32(CC) & ~CC_ENABLE);
        if (not waitReady(false))
            return fail("the controller won't reset");
        _admin = queue(0, ADMIN_SQ, ADMIN_CQ, entries);
        write32(AQA, (entries - 1) | (entries - 1) << 16);
        write64(ASQ, page(ADMIN_SQ));
        write64(ACQ, page(ADMIN_CQ));
        write32(CC, CC_ENABLE | 6u << 16 | 4u << 20);
        if (not waitReady(true))
            return fail("the controller won't start");

        // Namespace 1: its size and block size.
        Command identify{};
        identify.dw0 = ADMIN_IDENTIFY;
        identify.nsid = 1;
        identify.prp1 = page(IDENTIFY);
        identify.dw10 = 0; // CNS 0: the namespace
        if (not run(_admin, identify))
            return fail("namespace 1 didn't answer IDENTIFY");
        u8 const* ns = _memory + IDENTIFY * PAGE;
        _sectors = *reinterpret_cast<u64 const*>(ns);
        u32 format = *reinterpret_cast<u32 const*>(ns + 128 + 4 * (ns[26] & 0xF));
        if (((format >> 16) & 0xFF) != 9)
            return fail("namespace 1 doesn't use 512-byte blocks");

        // One I/O queue pair (completion queue first).
        _io = queue(1, IO_SQ, IO_CQ, entries);
        Command cq{};
        cq.dw0 = ADMIN_CREATE_CQ;
        cq.prp1 = page(IO_CQ);
        cq.dw10 = (entries - 1) << 16 | 1;
        cq.dw11 = 1; // physically contiguous, no interrupts
        Command sq{};
        sq.dw0 = ADMIN_CREATE_SQ;
        sq.prp1 = page(IO_SQ);
        sq.dw10 = (entries - 1) << 16 | 1;
        sq.dw11 = 1u << 16 | 1; // completions to queue 1, physically contiguous
        if (not run(_admin, cq) or not run(_admin, sq))
            return fail("couldn't create the I/O queues");

        Text<100> t;
        t.add("NVMe disk: ").add(_sectors / 2048).add(" MiB");
        Sys::log(t.cstr());
        return true;
    }

    bool attach(Sys::Handle memory) {
        long physical = Sys::dmaAddress(DEVICE, memory);
        if (physical < 0)
            return false;
        _buffer = static_cast<u64>(physical);
        // The PRP list: pages 2.. of the buffer (page 1 goes in PRP1).
        auto* list = reinterpret_cast<u64*>(_memory + PRP_LIST * PAGE);
        for (u64 i = 1; i < Block::BUFFER_SIZE / PAGE; i++)
            list[i - 1] = _buffer + i * PAGE;
        return true;
    }

    unsigned long sectors() const { return _sectors; }

    long transfer(bool write, u64 lba, u32 count) {
        if (not _buffer or count == 0 or count > Block::MAX_SECTORS or lba >= _sectors or count > _sectors - lba)
            return Sys::INVALID_ARGUMENT;
        u64 bytes = static_cast<u64>(count) * Block::SECTOR_SIZE;
        Command c{};
        c.dw0 = write ? IO_WRITE : IO_READ;
        c.nsid = 1;
        c.prp1 = _buffer;
        c.prp2 = bytes <= PAGE ? 0 : bytes <= 2 * PAGE ? _buffer + PAGE : page(PRP_LIST);
        c.dw10 = static_cast<u32>(lba);
        c.dw11 = static_cast<u32>(lba >> 32);
        c.dw12 = count - 1;
        return run(_io, c) ? Sys::OK : Sys::IO_ERROR;
    }

    long flush() {
        Command c{};
        c.dw0 = IO_FLUSH;
        c.nsid = 1;
        return run(_io, c) ? Sys::OK : Sys::IO_ERROR;
    }

private:
    bool fail(char const* why) {
        Text<120> t;
        t.add("nvme: ").add(why);
        Sys::log(t.cstr());
        return false;
    }

    u32 read32(u64 off) const { return *reinterpret_cast<u32 volatile*>(_regs + off); }
    u64 read64(u64 off) const { return u64{read32(off)} | u64{read32(off + 4)} << 32; }
    void write32(u64 off, u32 v) { *reinterpret_cast<u32 volatile*>(_regs + off) = v; }
    void write64(u64 off, u64 v) {
        write32(off, static_cast<u32>(v));
        write32(off + 4, static_cast<u32>(v >> 32));
    }

    u64 page(u64 index) const { return _physical + index * PAGE; }

    Queue queue(u32 id, u64 sqPage, u64 cqPage, u32 entries) {
        Queue q;
        q.id = id;
        q.size = entries;
        q.sq = reinterpret_cast<Command*>(_memory + sqPage * PAGE);
        q.cq = reinterpret_cast<Completion volatile*>(_memory + cqPage * PAGE);
        return q;
    }

    bool waitReady(bool ready) {
        unsigned long start = Sys::timeMs();
        for (;;) {
            u32 status = read32(CSTS);
            if (ready and (status & CSTS_FATAL))
                return false;
            if (bool(status & CSTS_READY) == ready)
                return true;
            if (Sys::timeMs() - start > _timeoutMs)
                return false;
            Sys::yield();
        }
    }

    // Submits one command and waits for its completion. True if it succeeded.
    bool run(Queue& q, Command c) {
        c.dw0 = (c.dw0 & 0xFFFF) | static_cast<u32>(++_commandId) << 16;
        q.sq[q.tail] = c;
        q.tail = (q.tail + 1) % q.size;
        asm volatile("" : : : "memory");
        write32(DOORBELLS + 2 * q.id * _stride, q.tail); // submission tail
        unsigned long start = Sys::timeMs();
        for (unsigned long spins = 0;; spins++) {
            Completion volatile& e = q.cq[q.head];
            if ((e.status & 1) == q.phase) {
                bool ok = (e.status >> 1) == 0;
                q.head = (q.head + 1) % q.size;
                if (q.head == 0)
                    q.phase ^= 1;
                write32(DOORBELLS + (2 * q.id + 1) * _stride, q.head); // completion head
                return ok;
            }
            if (spins > 1000) {
                if (Sys::timeMs() - start > _timeoutMs)
                    return false;
                Sys::yield();
            }
        }
    }

    u8 volatile* _regs = nullptr;
    u32 _stride = 4;
    unsigned long _timeoutMs = 1000;
    u8* _memory = nullptr;
    u64 _physical = 0;
    Queue _admin, _io;
    u16 _commandId = 0;
    u64 _sectors = 0;
    u64 _buffer = 0;
};

Disk disk;

} // namespace

int main() {
    Channel client(CLIENT);
    bool ready = disk.start();

    for (;;) {
        Block::Request request;
        Sys::Handle attached = Sys::NO_HANDLE;
        long result = client.recv(request, &attached);
        if (result == Sys::PEER_CLOSED)
            return 0;

        Block::Reply reply{Sys::INVALID_ARGUMENT, 0};
        if (result == Sys::OK and ready) {
            switch (request.op) {
            case Block::Op::Attach:
                if (attached and disk.attach(attached)) {
                    attached = Sys::NO_HANDLE; // the disk keeps it
                    reply = {Sys::OK, disk.sectors()};
                }
                break;
            case Block::Op::Read: reply.status = disk.transfer(false, request.lba, request.count); break;
            case Block::Op::Write: reply.status = disk.transfer(true, request.lba, request.count); break;
            case Block::Op::Flush: reply.status = disk.flush(); break;
            }
        } else if (not ready) {
            reply.status = Sys::NOT_FOUND;
        }
        if (attached)
            Sys::close(attached);
        client.send(reply);
    }
}

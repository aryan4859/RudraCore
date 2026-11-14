// ata: the IDE (parallel ATA) disk driver, for machines whose disk sits on
// the legacy IDE controller (VirtualBox's default for "Other" systems,
// older PCs). Programmed I/O through the primary channel's ports, polled:
// no DMA, no interrupts.
//
// Handles from init:
//   1: I/O ports 0x1F0-0x1F7 (the primary channel's command block)
//   2: a channel to its client, the file system server (protocol/block.h)

#include <kapala/channel.h>
#include <kapala/protocol/block.h>
#include <kapala/sys.h>
#include <kapala/text.h>

using namespace Kapala;
namespace Block = Kapala::Protocol::Block;

namespace {

constexpr Sys::Handle PORTS = 1;
constexpr Sys::Handle CLIENT = 2;

constexpr unsigned BASE = 0x1F0;
constexpr unsigned DATA = 0, FEATURES = 1, COUNT = 2, LBA_LOW = 3, LBA_MID = 4, LBA_HIGH = 5, DRIVE = 6,
                   STATUS = 7, COMMAND = 7;
constexpr unsigned char BSY = 0x80, DF = 0x20, DRQ = 0x08, ERR = 0x01;
constexpr unsigned char IDENTIFY = 0xEC, READ_EXT = 0x24, WRITE_EXT = 0x34, READ = 0x20, WRITE = 0x30,
                        FLUSH_EXT = 0xEA, FLUSH = 0xE7;

unsigned char in(unsigned reg) { return static_cast<unsigned char>(Sys::portInWide(PORTS, BASE + reg, 1)); }
void out(unsigned reg, unsigned char v) { Sys::portOutWide(PORTS, BASE + reg, 1, v); }
unsigned short inData() { return static_cast<unsigned short>(Sys::portInWide(PORTS, BASE + DATA, 2)); }
void outData(unsigned short v) { Sys::portOutWide(PORTS, BASE + DATA, 2, v); }

// Waits until the drive isn't busy; with `data`, until it also wants data
// moved (DRQ). False on an error, a fault, or after about 5 seconds.
bool waitReady(bool data) {
    unsigned long start = Sys::timeMs();
    for (unsigned long spins = 0;; spins++) {
        unsigned char s = in(STATUS);
        if (s == 0xFF)
            return false; // nothing on the channel
        if (not(s & BSY)) {
            if (s & (ERR | DF))
                return false;
            if (not data or (s & DRQ))
                return true;
        }
        if (spins > 1000) {
            if (Sys::timeMs() - start > 5000)
                return false;
            Sys::yield();
        }
    }
}

class Disk {
public:
    bool start() {
        for (unsigned slave = 0; slave < 2; slave++) {
            if (identify(slave)) {
                _slave = slave;
                Text<120> t;
                t.add("IDE disk (").add(slave ? "slave" : "master").add("): ").add(_sectors / 2048).add(" MiB")
                    .add(_lba48 ? ", LBA48" : ", LBA28");
                Sys::log(t.cstr());
                return true;
            }
        }
        Sys::log("no IDE disk on the primary channel");
        return false;
    }

    bool attach(Sys::Handle memory) {
        _buffer = static_cast<unsigned short*>(Sys::memoryMap(memory));
        return _buffer != nullptr;
    }

    unsigned long sectors() const { return _sectors; }

    long transfer(bool write, unsigned long lba, unsigned count) {
        if (not _buffer or count == 0 or count > Block::MAX_SECTORS or lba >= _sectors or count > _sectors - lba)
            return Sys::INVALID_ARGUMENT;
        if (not waitReady(false))
            return Sys::IO_ERROR;
        select(lba, count);
        out(COMMAND, write ? (_lba48 ? WRITE_EXT : WRITE) : (_lba48 ? READ_EXT : READ));
        for (unsigned s = 0; s < count; s++) {
            if (not waitReady(true))
                return Sys::IO_ERROR;
            unsigned short* words = _buffer + s * 256;
            for (int i = 0; i < 256; i++) {
                if (write)
                    outData(words[i]);
                else
                    words[i] = inData();
            }
        }
        return waitReady(false) ? Sys::OK : Sys::IO_ERROR;
    }

    long flush() {
        if (not waitReady(false))
            return Sys::IO_ERROR;
        out(DRIVE, static_cast<unsigned char>(0xE0 | _slave << 4));
        out(COMMAND, _lba48 ? FLUSH_EXT : FLUSH);
        return waitReady(false) ? Sys::OK : Sys::IO_ERROR;
    }

private:
    bool identify(unsigned slave) {
        out(DRIVE, static_cast<unsigned char>(0xA0 | slave << 4));
        for (int i = 0; i < 4; i++)
            in(STATUS); // 400 ns for the drive to answer the selection
        out(COUNT, 0);
        out(LBA_LOW, 0);
        out(LBA_MID, 0);
        out(LBA_HIGH, 0);
        out(COMMAND, IDENTIFY);
        if (in(STATUS) == 0)
            return false; // no drive
        unsigned long start = Sys::timeMs();
        while (in(STATUS) & BSY) {
            if (Sys::timeMs() - start > 2000)
                return false;
        }
        if (in(LBA_MID) or in(LBA_HIGH))
            return false; // ATAPI (a CD drive) or SATA in disguise: not ours
        if (not waitReady(true))
            return false;
        unsigned short id[256];
        for (int i = 0; i < 256; i++)
            id[i] = inData();
        _lba48 = id[83] & (1 << 10);
        unsigned long lba48 = static_cast<unsigned long>(id[100]) | static_cast<unsigned long>(id[101]) << 16 |
                              static_cast<unsigned long>(id[102]) << 32 | static_cast<unsigned long>(id[103]) << 48;
        unsigned long lba28 = static_cast<unsigned long>(id[60]) | static_cast<unsigned long>(id[61]) << 16;
        _sectors = _lba48 and lba48 ? lba48 : lba28;
        if (not _lba48 and _sectors > (1ul << 28))
            _sectors = 1ul << 28;
        return _sectors > 0;
    }

    void select(unsigned long lba, unsigned count) {
        if (_lba48) {
            out(DRIVE, static_cast<unsigned char>(0x40 | _slave << 4));
            out(COUNT, static_cast<unsigned char>(count >> 8)); // high bytes first
            out(LBA_LOW, static_cast<unsigned char>(lba >> 24));
            out(LBA_MID, static_cast<unsigned char>(lba >> 32));
            out(LBA_HIGH, static_cast<unsigned char>(lba >> 40));
            out(COUNT, static_cast<unsigned char>(count));
            out(LBA_LOW, static_cast<unsigned char>(lba));
            out(LBA_MID, static_cast<unsigned char>(lba >> 8));
            out(LBA_HIGH, static_cast<unsigned char>(lba >> 16));
        } else {
            out(DRIVE, static_cast<unsigned char>(0xE0 | _slave << 4 | ((lba >> 24) & 0xF)));
            out(COUNT, static_cast<unsigned char>(count)); // (0 means 256: count is at most 128 here)
            out(LBA_LOW, static_cast<unsigned char>(lba));
            out(LBA_MID, static_cast<unsigned char>(lba >> 8));
            out(LBA_HIGH, static_cast<unsigned char>(lba >> 16));
        }
        (void)FEATURES;
    }

    unsigned _slave = 0;
    bool _lba48 = false;
    unsigned long _sectors = 0;
    unsigned short* _buffer = nullptr;
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

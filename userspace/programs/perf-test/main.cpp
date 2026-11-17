// perf-test: kernel performance and a stress test, at every boot (step 4.4).
//
// Measures: timer resolution, IPC round-trip latency (two threads over a
// channel), context-switch cost, memory allocation (private memory touched
// page by page, and the kernel heap), scheduler fairness (spinning threads
// get comparable shares), and the kernel lock's contention. Then a stress
// test: threads hammer a shared mutex-protected list, the heap and channels
// at once; every result is checked (no lost or corrupted item), and each
// join has a deadline (a deadlock fails the test instead of hanging).

#include <kapala/channel.h>
#include <kapala/sys.h>
#include <kapala/text.h>
#include <kapala/thread.h>

using namespace Kapala;

namespace {

int passed = 0, failed = 0;

void expect(char const* what, bool ok, long detail = 0) {
    (ok ? passed : failed)++;
    if (not ok) {
        Text<> line;
        line.add("perf check: FAILED: ").add(what).add(" (").add(detail).add(")");
        Sys::log(line.cstr());
    }
}

void report(char const* what, unsigned long value, char const* unit) {
    Text<> line;
    line.add("perf: ").add(what).add(" ").add(value).add(" ").add(unit);
    Sys::log(line.cstr());
}

// MARK: Measurements

void timerResolution() {
    unsigned long a = Sys::timeNs(), b = Sys::timeNs();
    while (b == a)
        b = Sys::timeNs();
    report("timer resolution: consecutive readings", b - a, "ns apart");
    unsigned long start = Sys::timeNs();
    Sys::sleep(5);
    unsigned long slept = (Sys::timeNs() - start) / 1000;
    report("sleep(5 ms) took", slept, "us");
    // Never early (how late depends on the load, and in an emulator on the host).
    expect("a 5 ms sleep never ends early", slept >= 4900, static_cast<long>(slept));
}

constexpr int ROUND_TRIPS = 2000;

long echo(void* end) {
    auto handle = static_cast<Sys::Handle>(reinterpret_cast<unsigned long>(end));
    for (int i = 0; i < ROUND_TRIPS; i++) {
        unsigned long v;
        if (Sys::recv(handle, &v, sizeof(v)) != sizeof(v))
            return -1;
        v++;
        Sys::send(handle, &v, sizeof(v));
    }
    return 0;
}

void ipcLatency() {
    Sys::Handle mine, theirs;
    Sys::channelCreate(mine, theirs);
    Thread peer;
    peer.start(echo, reinterpret_cast<void*>(static_cast<unsigned long>(theirs)));
    Sys::KernelCounters before{}, after{};
    Sys::kernelCounters(before);
    unsigned long start = Sys::timeNs();
    bool ok = true;
    for (unsigned long i = 0; i < ROUND_TRIPS and ok; i++) {
        Sys::send(mine, &i, sizeof(i));
        unsigned long back = 0;
        ok = Sys::recv(mine, &back, sizeof(back)) == sizeof(back) and back == i + 1;
    }
    unsigned long elapsed = Sys::timeNs() - start;
    Sys::kernelCounters(after);
    expect("IPC round trips all answered", ok and peer.join(5000) == 0);
    report("IPC round trip (channel, two threads):", elapsed / ROUND_TRIPS, "ns");
    unsigned long switches = after.switches - before.switches;
    if (switches)
        report("context switch (kernel side):", (after.switchNs - before.switchNs) / switches, "ns");
    Sys::close(mine);
    Sys::close(theirs);
}

void allocation() {
    constexpr unsigned long SIZE = 4ul << 20;
    unsigned long start = Sys::timeNs();
    auto* p = static_cast<unsigned char volatile*>(Sys::memoryAlloc(SIZE));
    for (unsigned long at = 0; p and at < SIZE; at += 4096)
        p[at] = 1; // each touch: a demand-paging fault
    unsigned long elapsed = Sys::timeNs() - start;
    Sys::memoryUnmap(const_cast<unsigned char*>(p));
    expect("4 MiB of private memory", p != nullptr);
    report("private memory, allocated and touched:", elapsed / (SIZE / 4096), "ns per page");

    start = Sys::timeNs();
    void* blocks[256];
    for (auto*& b : blocks)
        b = new unsigned char[96];
    for (auto* b : blocks)
        delete[] static_cast<unsigned char*>(b);
    report("userspace heap, new + delete:", (Sys::timeNs() - start) / 256, "ns");

    Sys::KernelCounters k{};
    Sys::kernelCounters(k);
    if (k.heapAllocs)
        report("kernel heap allocation:", k.heapNs / k.heapAllocs, "ns on average");
}

bool volatile stopSpinning = false;
unsigned long spins[16];

long spinner(void* arg) {
    auto i = reinterpret_cast<unsigned long>(arg);
    while (not stopSpinning)
        spins[i]++;
    return 0;
}

void fairness() {
    Sys::KernelCounters k{};
    Sys::kernelCounters(k);
    unsigned long count = k.cpus * 2 < 16 ? k.cpus * 2 : 16; // more spinners than CPUs: they must share
    Thread threads[16];
    stopSpinning = false;
    for (unsigned long i = 0; i < count; i++)
        threads[i].start(spinner, reinterpret_cast<void*>(i));
    Sys::sleep(600);
    stopSpinning = true;
    unsigned long least = ~0ul, most = 0;
    for (unsigned long i = 0; i < count; i++) {
        threads[i].join(5000);
        least = spins[i] < least ? spins[i] : least;
        most = spins[i] > most ? spins[i] : most;
    }
    report("fairness: least / most CPU share among spinners (percent):", most ? least * 100 / most : 0, "%");
    expect("every spinner got a fair share (at least a quarter of the busiest's)", least * 4 >= most,
           static_cast<long>(most ? least * 100 / most : 0));
}

// MARK: Stress

constexpr int WORKERS = 8, ITEMS = 1500;

struct Node {
    Node* next;
    unsigned long value, check;
};

Mutex listLock;
Node* list = nullptr;
unsigned long pushed = 0, popped = 0, sum = 0;

long worker(void* arg) {
    auto me = reinterpret_cast<unsigned long>(arg);
    unsigned long seed = me * 2654435761u + 1;
    for (int i = 0; i < ITEMS; i++) {
        seed = seed * 6364136223846793005ul + 1442695040888963407ul;
        auto* n = new Node{nullptr, seed >> 16, ~(seed >> 16)};
        auto* scratch = new unsigned char[16 + (seed >> 40) % 2000]; // varied sizes: heap churn
        scratch[0] = static_cast<unsigned char>(me);
        {
            MutexGuard held(listLock);
            n->next = list;
            list = n;
            pushed++;
            sum += n->value;
        }
        if (seed & 1) {
            MutexGuard held(listLock);
            if (Node* taken = list) {
                list = taken->next;
                if (taken->check != ~taken->value)
                    return -1; // corrupted
                sum -= taken->value;
                popped++;
                delete taken;
            }
        }
        if (scratch[0] != static_cast<unsigned char>(me))
            return -2;
        delete[] scratch;
        if (i % 100 == 0)
            Sys::yield();
    }
    return 0;
}

void stress() {
    unsigned long start = Sys::timeNs();
    Sys::KernelCounters before{}, after{};
    Sys::kernelCounters(before);
    Thread workers[WORKERS];
    for (unsigned long i = 0; i < WORKERS; i++)
        expect("starting a stress worker", workers[i].start(worker, reinterpret_cast<void*>(i)));
    bool clean = true;
    for (auto& w : workers) {
        long code = w.join(30000); // a deadlock fails here instead of hanging
        clean = clean and code == 0;
        expect("a stress worker finished (no deadlock, no corruption)", code == 0, code);
    }
    // What's left in the list must add up.
    unsigned long left = 0, check = 0;
    for (Node* n = list; n; n = n->next) {
        left++;
        check += n->value;
    }
    expect("stress: no item lost or duplicated", clean and pushed == WORKERS * ITEMS and left == pushed - popped and
                                                     check == sum,
           static_cast<long>(left));
    Sys::kernelCounters(after);
    report("stress: 8 threads,", (Sys::timeNs() - start) / 1000000, "ms");
    unsigned long acquires = after.lockAcquires - before.lockAcquires;
    unsigned long contended = after.lockContended - before.lockContended;
    if (acquires)
        report("kernel lock contention during the stress test (percent of acquisitions):",
               contended * 100 / acquires, "%");
    if (contended)
        report("average wait for the kernel lock when contended:",
               (after.lockWaitNs - before.lockWaitNs) / contended, "ns");
}

} // namespace

int main() {
    timerResolution();
    ipcLatency();
    allocation();
    fairness();
    stress();

    Sys::KernelCounters k{};
    Sys::kernelCounters(k);
    Text<200> totals;
    totals.add("perf: since boot: ").add(k.syscalls).add(" system calls, ").add(k.interrupts).add(" interrupts, ")
        .add(k.pageFaults).add(" page faults, ").add(k.switches).add(" switches, ").add(k.ipis).add(" IPIs, ")
        .add(k.shootdowns).add(" TLB shootdowns, on ").add(k.cpus).add(" CPU(s)");
    Sys::log(totals.cstr());

    Text<> line;
    line.add("perf check: ").add(passed).add(" passed, ").add(failed).add(" failed");
    Sys::log(line.cstr());
    return failed ? 1 : 0;
}

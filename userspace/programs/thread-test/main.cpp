// thread-test: checks threads and processes at every boot (step 4.2).
//
// Threads: thread_local copies, a mutex under contention, a condition
// variable, join with exit codes and timeouts, futex wait rules, the
// thread limit. Processes: wait for exit codes, the event model
// (SIGNAL_TERMINATE as an event the child handles), SIGNAL_KILL, a CPU
// time limit, a fault's exit code and post-mortem info, and a group signal
// that reaches the group and nothing else.
//
// It also plays each child: the first message on its handle 1 says which.

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
        line.add("thread check: FAILED: ").add(what).add(" (").add(detail).add(")");
        Sys::log(line.cstr());
    }
}

// MARK: Threads

thread_local long perThread = 42; // from the TLS template
thread_local long zeroed;         // .tbss

long tlsWorker(void* arg) {
    long mine = reinterpret_cast<long>(arg);
    bool fresh = perThread == 42 and zeroed == 0;
    perThread = mine;
    zeroed = mine * 2;
    Sys::sleep(5); // let the others write theirs meanwhile
    return fresh and perThread == mine and zeroed == mine * 2 ? mine : -1;
}

Mutex counterLock;
unsigned long counter = 0;
constexpr int ROUNDS = 20000;

long counterWorker(void*) {
    for (int i = 0; i < ROUNDS; i++) {
        MutexGuard held(counterLock);
        unsigned long v = counter;
        if (i % 1000 == 0)
            Sys::yield(); // hold the lock across a switch now and then: real contention
        counter = v + 1;
    }
    return 0;
}

Mutex queueLock;
Condition queueReady;
int queued = 0, consumed = 0;

long consumer(void*) {
    for (int got = 0; got < 50;) {
        MutexGuard held(queueLock);
        while (queued == 0)
            queueReady.wait(queueLock);
        queued--;
        got++;
        consumed++;
    }
    return 0;
}

long sleeper(void* arg) {
    Sys::sleep(reinterpret_cast<unsigned long>(arg));
    return 99;
}

void checkThreads() {
    perThread = 1;
    Thread workers[4];
    for (long i = 0; i < 4; i++)
        expect("starting a thread", workers[i].start(tlsWorker, reinterpret_cast<void*>(i + 10)));
    bool tls = true;
    for (long i = 0; i < 4; i++)
        tls = workers[i].join() == i + 10 and tls;
    expect("thread_local: every thread its own copy, from the template", tls and perThread == 1, perThread);

    Thread counters[4];
    for (auto& t : counters)
        t.start(counterWorker, nullptr);
    for (auto& t : counters)
        t.join();
    expect("a mutex under contention: no lost update", counter == 4ul * ROUNDS, static_cast<long>(counter));

    Thread taker;
    taker.start(consumer, nullptr);
    for (int i = 0; i < 50; i++) {
        MutexGuard held(queueLock);
        queued++;
        queueReady.notifyOne();
    }
    expect("a condition variable: producer and consumer", taker.join() == 0 and consumed == 50, consumed);

    Thread slow;
    slow.start(sleeper, reinterpret_cast<void*>(300));
    expect("join with a timeout", slow.join(20) == Sys::TIMED_OUT);
    expect("join returns the thread's exit code", slow.join() == 99);
    expect("join a thread that doesn't exist", Sys::threadJoin(123456) == Sys::NOT_FOUND);
    expect("join yourself", Sys::threadJoin(Sys::threadId()) == Sys::INVALID_ARGUMENT);

    unsigned word = 5;
    expect("futex_wait on a changed word returns at once", Sys::futexWait(&word, 4, 1000) == Sys::WOULD_BLOCK);
    unsigned long before = Sys::timeMs();
    expect("futex_wait times out", Sys::futexWait(&word, 5, 30) == Sys::TIMED_OUT and Sys::timeMs() - before >= 30);
    expect("futex_wake with nobody waiting", Sys::futexWake(&word, 1) == 0);
}

// MARK: Processes

enum Role : unsigned long { SPIN = 1, EVENTS = 2, FAULT = 3 };

long child(Role role, Sys::Handle& handle, unsigned long flags = Sys::SPAWN_HANDLE) {
    Sys::Handle mine, theirs;
    Sys::channelCreate(mine, theirs);
    unsigned long message = role;
    Sys::send(mine, &message, sizeof(message));
    Sys::Handle give[] = {theirs};
    long h = Sys::spawnWith("thread-test", give, 1, flags);
    if (h < 0) {
        Sys::close(mine);
        Sys::close(theirs);
        return h;
    }
    handle = static_cast<Sys::Handle>(h);
    return static_cast<long>(mine); // (the caller's end, to hear from it)
}

void checkProcesses() {
    // The event model: SIGNAL_TERMINATE arrives as an event; the child ends itself.
    Sys::Handle p;
    long talk = child(EVENTS, p);
    expect("spawning with a process handle", talk > 0, talk);
    if (talk > 0) {
        char ready;
        Sys::recv(static_cast<Sys::Handle>(talk), &ready, 1); // it listens now
        expect("signal: terminate", Sys::processSignal(p, Sys::SIGNAL_TERMINATE) == Sys::OK);
        long code = 0;
        expect("it got the event and exited with its own code", Sys::processWait(p, &code, 3000) == Sys::OK and code == 7,
               code);
        Sys::close(p);
        Sys::close(static_cast<Sys::Handle>(talk));
    }

    // Kill: no event, it just ends.
    talk = child(SPIN, p);
    if (talk > 0) {
        long code = 0;
        expect("waiting with a timeout", Sys::processWait(p, &code, 10) == Sys::TIMED_OUT);
        Sys::processSignal(p, Sys::SIGNAL_KILL);
        expect("signal: kill", Sys::processWait(p, &code, 3000) == Sys::OK and code == Sys::EXIT_KILLED, code);
        Sys::close(p);
        Sys::close(static_cast<Sys::Handle>(talk));
    }

    // A CPU time limit ends a spinning child.
    talk = child(SPIN, p);
    if (talk > 0) {
        long code = 0;
        Sys::processLimit(p, Sys::LIMIT_CPU_MS, 50);
        expect("a CPU time limit", Sys::processWait(p, &code, 5000) == Sys::OK and code == Sys::EXIT_CPU_LIMIT, code);
        Sys::close(p);
        Sys::close(static_cast<Sys::Handle>(talk));
    }

    // A fault: exit code and what happened.
    talk = child(FAULT, p);
    if (talk > 0) {
        long code = 0;
        Sys::processWait(p, &code, 3000);
        Sys::ProcessInfo info{};
        Sys::processInfo(p, info);
        expect("a fault ends the process", code == Sys::EXIT_FAULT, code);
        expect("post-mortem: the fault", info.exited and info.faultVector == 14 and info.faultAddress == 8,
               static_cast<long>(info.faultVector));
        Sys::close(p);
        Sys::close(static_cast<Sys::Handle>(talk));
    }

    // A group signal: its own group, and not ours.
    talk = child(SPIN, p, Sys::SPAWN_HANDLE | Sys::SPAWN_NEW_GROUP);
    if (talk > 0) {
        Sys::ProcessInfo info{};
        Sys::processInfo(p, info);
        expect("a new group", info.group == info.id);
        Sys::processSignal(p, Sys::SIGNAL_KILL, Sys::SIGNAL_GROUP);
        long code = 0;
        expect("a group signal reaches the group", Sys::processWait(p, &code, 3000) == Sys::OK and
                                                       code == Sys::EXIT_KILLED, code);
        Sys::close(p);
        Sys::close(static_cast<Sys::Handle>(talk));
    }
}

void checkLimits() {
    Sys::processLimit(Sys::NO_HANDLE, Sys::LIMIT_THREADS, 1); // just this one
    Thread extra;
    expect("the thread limit", not extra.start(sleeper, nullptr));
}

[[noreturn]] void beChild(Role role) {
    switch (role) {
    case SPIN:
        for (;;)
            asm volatile("" ::: "memory");
    case EVENTS: {
        Sys::Handle kernels, mine;
        Sys::channelCreate(kernels, mine);
        Sys::processEvents(kernels);
        char ready = 1;
        Sys::send(1, &ready, 1);
        Sys::Event event{};
        while (Sys::recv(mine, &event, sizeof(event)) == sizeof(event)) {
            if (event.kind == Sys::EVENT_TERMINATE)
                Sys::exit(7); // a clean, chosen exit
        }
        Sys::exit(1);
    }
    case FAULT:
        *reinterpret_cast<long volatile*>(8) = 1; // page 0: never mapped
        Sys::exit(1);
    }
    Sys::exit(1);
}

} // namespace

int main() {
    unsigned long role;
    if (Sys::recv(1, &role, sizeof(role), nullptr, Sys::RECV_NONBLOCK) == sizeof(role))
        beChild(static_cast<Role>(role));

    checkThreads();
    checkProcesses();
    checkLimits(); // last: it lowers this process's own limit

    Text<> line;
    line.add("thread check: ").add(passed).add(" passed, ").add(failed).add(" failed");
    Sys::log(line.cstr());
    return failed ? 1 : 0;
}

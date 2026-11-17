#pragma once

// Kapalaframe: threads and synchronization.
//
//   Thread worker;
//   worker.start([](void* arg) -> long { ...; return 0; }, &data);
//   long code = worker.join();
//
//   Mutex lock;           { MutexGuard held(lock); ... }
//   Condition ready;      ready.wait(lock); ready.notifyAll();
//
// `thread_local` variables work: every thread gets its own copy (made from
// the program's TLS template when it starts). Mutexes and conditions are
// futexes: without contention they never enter the kernel.

#include <kapala/sys.h>

namespace Kapala {

class Mutex {
public:
    void lock();
    bool tryLock();
    void unlock();

private:
    unsigned _state = 0; // 0 free, 1 locked, 2 locked and someone waits
};

class MutexGuard {
public:
    explicit MutexGuard(Mutex& m) : _mutex(m) { _mutex.lock(); }
    ~MutexGuard() { _mutex.unlock(); }
    MutexGuard(MutexGuard const&) = delete;
    MutexGuard& operator=(MutexGuard const&) = delete;

private:
    Mutex& _mutex;
};

class Condition {
public:
    // Unlocks `mutex`, waits for a notify (or the timeout), locks it again.
    // False on timeout. Wake-ups can be spurious: wait in a loop.
    bool wait(Mutex& mutex, unsigned long timeoutMs = Sys::WAIT_FOREVER);
    void notifyOne();
    void notifyAll();

private:
    unsigned _sequence = 0;
};

class Thread {
public:
    using Entry = long (*)(void* arg);

    static constexpr unsigned long DEFAULT_STACK = 64 * 1024;

    // Starts it; false if it couldn't (out of memory, the thread limit).
    bool start(Entry entry, void* arg, unsigned long stackSize = DEFAULT_STACK);

    // Waits for it to end; its return value (or a negative Sys::Error).
    long join(unsigned long timeoutMs = Sys::WAIT_FOREVER);

    unsigned long id() const { return _id; }

private:
    unsigned long _id = 0;
    void* _stack = nullptr;
    void* _tls = nullptr;
};

namespace Tls {

// The calling thread's TLS block (what FS points at), made for the main
// thread by the runtime and for others by Thread::start.
void* create();          // a new block from the template, or nullptr
void destroy(void* tls); // (a thread's, after it ended)

} // namespace Tls

} // namespace Kapala

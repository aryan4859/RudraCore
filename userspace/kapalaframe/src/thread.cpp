#include <kapala/heap.h>
#include <kapala/thread.h>

extern "C" void* memcpy(void* dest, void const* src, unsigned long n);
extern "C" void* memset(void* dest, int value, unsigned long n);

// The program's TLS template, from userspace/link.ld (.tdata is copied,
// .tbss zeroed). Absolute symbols: their addresses are the values.
extern "C" char __tls_template[], __tls_file_size[], __tls_memory_size[], __tls_align[];

namespace Kapala {

// MARK: Mutex (a futex word: 0 free, 1 locked, 2 locked with waiters)

void Mutex::lock() {
    unsigned c = 0;
    if (__atomic_compare_exchange_n(&_state, &c, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return; // (the common case: no system call)
    if (c != 2)
        c = __atomic_exchange_n(&_state, 2, __ATOMIC_ACQUIRE);
    while (c != 0) {
        Sys::futexWait(&_state, 2);
        c = __atomic_exchange_n(&_state, 2, __ATOMIC_ACQUIRE);
    }
}

bool Mutex::tryLock() {
    unsigned c = 0;
    return __atomic_compare_exchange_n(&_state, &c, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

void Mutex::unlock() {
    if (__atomic_fetch_sub(&_state, 1, __ATOMIC_RELEASE) != 1) { // someone waits
        __atomic_store_n(&_state, 0, __ATOMIC_RELEASE);
        Sys::futexWake(&_state, 1);
    }
}

// MARK: Condition (a sequence number: a notify changes it, waiters sleep on it)

bool Condition::wait(Mutex& mutex, unsigned long timeoutMs) {
    unsigned seen = __atomic_load_n(&_sequence, __ATOMIC_ACQUIRE);
    mutex.unlock();
    long r = Sys::futexWait(&_sequence, seen, timeoutMs);
    mutex.lock();
    return r != Sys::TIMED_OUT;
}

void Condition::notifyOne() {
    __atomic_fetch_add(&_sequence, 1, __ATOMIC_RELEASE);
    Sys::futexWake(&_sequence, 1);
}

void Condition::notifyAll() {
    __atomic_fetch_add(&_sequence, 1, __ATOMIC_RELEASE);
    Sys::futexWake(&_sequence, ~0ul);
}

// MARK: Thread-local storage (x86-64 variant II: the block ends where FS
// points; FS:0 holds FS itself, as the compiler expects)

namespace Tls {

void* create() {
    unsigned long fileSize = reinterpret_cast<unsigned long>(__tls_file_size);
    unsigned long memorySize = reinterpret_cast<unsigned long>(__tls_memory_size);
    unsigned long align = reinterpret_cast<unsigned long>(__tls_align);
    if (align == 0)
        align = 1;
    unsigned long block = (memorySize + align - 1) & ~(align - 1); // what the linker's offsets assume
    unsigned long tpAlign = align < 16 ? 16 : align;
    auto* raw = static_cast<unsigned char*>(Heap::alloc(block + tpAlign + 16));
    if (not raw)
        return nullptr;
    unsigned long tp = (reinterpret_cast<unsigned long>(raw) + block + tpAlign - 1) & ~(tpAlign - 1);
    auto* start = reinterpret_cast<unsigned char*>(tp - block);
    memcpy(start, __tls_template, fileSize);
    memset(start + fileSize, 0, block - fileSize);
    reinterpret_cast<unsigned long*>(tp)[0] = tp;                                  // FS:0, the thread pointer
    reinterpret_cast<unsigned long*>(tp)[1] = reinterpret_cast<unsigned long>(raw); // for destroy
    return reinterpret_cast<void*>(tp);
}

void destroy(void* tls) {
    if (tls)
        Heap::free(reinterpret_cast<void*>(static_cast<unsigned long*>(tls)[1]));
}

} // namespace Tls

// MARK: Thread

namespace {

struct Start {
    Thread::Entry entry;
    void* arg;
};

[[noreturn]] void threadMain(void* p) {
    Start start = *static_cast<Start*>(p);
    delete static_cast<Start*>(p);
    Sys::threadExit(start.entry(start.arg));
}

} // namespace

bool Thread::start(Entry entry, void* arg, unsigned long stackSize) {
    _stack = Sys::memoryAlloc(stackSize);
    _tls = Tls::create();
    auto* start = new Start{entry, arg};
    // The stack top as if threadMain had been called: rsp % 16 == 8.
    unsigned long top = ((reinterpret_cast<unsigned long>(_stack) + stackSize) & ~15ul) - 8;
    long id = _stack and _tls ? Sys::threadCreate(threadMain, reinterpret_cast<void*>(top), start, _tls) : -1;
    if (id < 0) {
        delete start;
        if (_stack)
            Sys::memoryUnmap(_stack);
        Tls::destroy(_tls);
        _stack = _tls = nullptr;
        return false;
    }
    _id = static_cast<unsigned long>(id);
    return true;
}

long Thread::join(unsigned long timeoutMs) {
    long code = 0;
    long r = Sys::threadJoin(_id, &code, timeoutMs);
    if (r != Sys::OK)
        return r;
    Sys::memoryUnmap(_stack); // (it has ended: nothing runs on them now)
    Tls::destroy(_tls);
    _stack = _tls = nullptr;
    return code;
}

} // namespace Kapala

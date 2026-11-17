#include "core/futex.h"

#include "core/sched.h"

namespace Rudracore::Futex {

using Core::Task;

namespace {

Task* waiters = nullptr; // linked by Task::futexNext, oldest last (woken in arrival order: see wake)

} // namespace

void wait(Task* thread, u64 key) {
    forget(thread);
    thread->futexKey = key;
    thread->futexWoken = false;
    thread->futexNext = waiters;
    waiters = thread;
}

u64 wake(u64 key, u64 count) {
    // The list is newest first: wake from the oldest (fair: first come, first woken).
    u64 woken = 0;
    while (woken < count) {
        Task** oldest = nullptr;
        for (Task** link = &waiters; *link; link = &(*link)->futexNext) {
            if ((*link)->futexKey == key)
                oldest = link;
        }
        if (not oldest)
            break;
        Task* t = *oldest;
        *oldest = t->futexNext;
        t->futexNext = nullptr;
        t->futexKey = 0;
        t->futexWoken = true;
        Sched::wake(t);
        woken++;
    }
    return woken;
}

void forget(Task* thread) {
    if (not thread->futexKey)
        return;
    for (Task** link = &waiters; *link; link = &(*link)->futexNext) {
        if (*link == thread) {
            *link = thread->futexNext;
            break;
        }
    }
    thread->futexKey = 0;
    thread->futexNext = nullptr;
}

} // namespace Rudracore::Futex

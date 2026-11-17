#include "core/programs.h"

#include "core/elf.h"
#include "mem/memory.h"

extern "C" void* memcpy(void* dest, void const* src, unsigned long n);

namespace Rudracore::Programs {

namespace {

Boot::Info const* bootInfo = nullptr;

bool nameEquals(char const* a, char const* b, usize bLength) {
    usize i = 0;
    for (; i < bLength; i++) {
        if (a[i] != b[i] or a[i] == '\0')
            return false;
    }
    return a[i] == '\0';
}

void dropHandles(Core::Capability const* handles, usize count) {
    for (usize i = 0; i < count; i++) {
        if (handles[i].object)
            handles[i].object->unref();
    }
}

} // namespace

void init(Boot::Info const& info) {
    bootInfo = &info;
}

// Boot module `i` as a sealed memory object (made once, kept by the cache):
// its own pages when they're page aligned (nothing copied: every program
// started from it shares them), else a copy.
Core::SharedMemory* moduleObject(usize i) {
    static Core::SharedMemory* cache[Boot::Info::MAX_MODULES] = {};
    if (cache[i])
        return cache[i];
    Boot::Module const& module = bootInfo->modules[i];
    u64 physical = reinterpret_cast<u64>(module.data) - Mem::hhdmOffset;
    Core::SharedMemory* memory = nullptr;
    if (physical % Mem::PAGE_SIZE == 0) {
        memory = Core::SharedMemory::bootFile(physical, module.size);
    } else {
        memory = Core::SharedMemory::allocate(module.size);
        if (not memory)
            return nullptr;
        memcpy(Mem::toVirtual<u8>(memory->physical), module.data, module.size);
        memory->readOnly = memory->sealed = true;
    }
    cache[i] = memory; // the cache keeps this first reference
    return memory;
}

Core::SharedMemory* file(char const* name) {
    usize n = 0;
    while (name[n])
        n++;
    for (usize i = 0; bootInfo and i < bootInfo->moduleCount; i++) {
        if (nameEquals(bootInfo->modules[i].name, name, n))
            return moduleObject(i);
    }
    return nullptr;
}

bool exists(char const* name, usize nameLength) {
    for (usize i = 0; bootInfo and i < bootInfo->moduleCount; i++) {
        if (nameEquals(bootInfo->modules[i].name, name, nameLength))
            return true;
    }
    return false;
}

Core::Task* startImage(char const* name, Core::SharedMemory* image, usize size, Core::Capability const* handles,
                       usize handleCount, Abi::Error& code, char const*& error) {
    Elf::Program program;
    if (not Elf::load(image, size, program, error)) {
        code = error == Elf::OUT_OF_MEMORY ? Abi::OUT_OF_MEMORY : Abi::INVALID_ARGUMENT;
        dropHandles(handles, handleCount);
        return nullptr;
    }
    Core::Task* task = Sched::createUser(name, program.space, program.entry, program.stackTop, handles, handleCount);
    if (not task) {
        code = Abi::OUT_OF_MEMORY;
        error = "out of memory";
        return nullptr;
    }
    if (not Elf::mapRegions(*task, image, size, program, error)) {
        Sched::discard(task); // (drops the handles too)
        code = Abi::OUT_OF_MEMORY;
        return nullptr;
    }
    Sched::startTask(task);
    return task;
}

Core::Task* start(char const* name, usize nameLength, Core::Capability const* handles,
                  usize handleCount, Abi::Error& code, char const*& error) {
    Boot::Module const* module = nullptr;
    for (usize i = 0; bootInfo and i < bootInfo->moduleCount; i++) {
        if (nameEquals(bootInfo->modules[i].name, name, nameLength)) {
            module = &bootInfo->modules[i];
            break;
        }
    }
    Core::SharedMemory* image = module ? moduleObject(static_cast<usize>(module - bootInfo->modules)) : nullptr;
    if (not image) {
        code = module ? Abi::OUT_OF_MEMORY : Abi::NOT_FOUND;
        error = module ? "out of memory" : "no such program";
        dropHandles(handles, handleCount);
        return nullptr;
    }
    return startImage(module->name, image, module->size, handles, handleCount, code, error);
}

} // namespace Rudracore::Programs

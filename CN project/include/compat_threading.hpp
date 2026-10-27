#ifndef COMPAT_THREADING_HPP
#define COMPAT_THREADING_HPP

#ifdef _WIN32
#include <windows.h>
#include <functional>

namespace DLL {

class FastMutex {
private:
    CRITICAL_SECTION cs;
public:
    FastMutex() { InitializeCriticalSection(&cs); }
    ~FastMutex() { DeleteCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
};

class FastLock {
private:
    FastMutex& mtx;
public:
    explicit FastLock(FastMutex& m) : mtx(m) { mtx.lock(); }
    ~FastLock() { mtx.unlock(); }
};

class FastThread {
private:
    HANDLE hThread;
    std::function<void()>* pFunc;

    static DWORD WINAPI ThreadEntry(LPVOID lpParam) {
        auto* func = reinterpret_cast<std::function<void()>*>(lpParam);
        if (func && *func) {
            (*func)();
        }
        delete func;
        return 0;
    }

public:
    FastThread() : hThread(nullptr), pFunc(nullptr) {}

    template<typename Callable>
    explicit FastThread(Callable f) : hThread(nullptr), pFunc(nullptr) {
        pFunc = new std::function<void()>(f);
        hThread = CreateThread(nullptr, 0, ThreadEntry, pFunc, 0, nullptr);
    }

    ~FastThread() {
        if (hThread) {
            CloseHandle(hThread);
        }
    }

    bool joinable() const {
        return hThread != nullptr;
    }

    void join() {
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            hThread = nullptr;
        }
    }
};

inline void sleepMs(int ms) {
    Sleep(static_cast<DWORD>(ms));
}

inline uint64_t getTimestampMs() {
    return static_cast<uint64_t>(GetTickCount());
}

} // namespace DLL

#else
// POSIX fallback
#include <thread>
#include <mutex>
#include <chrono>

namespace DLL {
    using FastMutex = std::mutex;
    using FastLock = std::lock_guard<std::mutex>;
    using FastThread = std::thread;

    inline void sleepMs(int ms) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    inline uint64_t getTimestampMs() {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }
}
#endif

#endif // COMPAT_THREADING_HPP

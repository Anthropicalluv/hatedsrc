#pragma once

//simple declarations for features bc importing features.h was causing weird ass issues

#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <string>
#include "DriverComm.h"

namespace LocalPlayer {
    struct Vec3 {
        float x, y, z;
    };

    extern std::atomic<Vec3> g_cachedCoords;
    extern std::atomic<uintptr_t> realPlayer;
    extern bool Enabled;
    extern bool flyEnabled;
    extern uintptr_t destinyBase;
    extern std::atomic<Vec3> g_cachedCoords;
}

namespace ViewAngles {
    struct Vec2 {
        float pitch, yaw;
    };

    extern uintptr_t addr;
    // commented these out bc they were breaking it but view angle still gets hooked/wrote to tp's so afaik its fine 😜
    // static std::atomic<uintptr_t> g_viewBase{ 0 };
    // static std::atomic<ViewAngles::Vec2> g_cachedAngles{ {0.0f, 0.0f} };
}

// Function declarations for shared functions
template<typename T>
BOOL ReadMem(
    HANDLE    driver,
    DWORD     pid,
    uintptr_t address,
    T& outValue);

template<typename T>
std::enable_if_t<!std::is_array_v<T>, BOOL>
WriteMem(
    HANDLE    driver,
    uintptr_t address,
    const T& value
);

// 2) C‐array overload
template<typename T, size_t N>
BOOL WriteMem(
    HANDLE           driver,
    uintptr_t        address,
    const T(&buf)[N]
);

// 3) std::string overload
inline BOOL WriteMem(
    HANDLE             driver,
    uintptr_t          address,
    const std::string& str
);

// 4) std::vector<T> overload
template<typename T>
BOOL WriteMem(
    HANDLE              driver,
    uintptr_t           address,
    const std::vector<T>& vec
);

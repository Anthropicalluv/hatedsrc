#pragma once

#include <Windows.h>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <filesystem>
#include "ImGui/imgui_custom.h"


using json = nlohmann::json;

//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// 1) Global state & forward declarations
//
//    These must come *before* any function that uses them.
//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

// feature flags loaded/saved from JSON
inline std::unordered_map<std::string, bool> FeatureConfig;

// hotkey map (string name → VK code) :contentReference[oaicite:0]{index=0}
inline std::unordered_map<std::string, int> Hotkeys;

// Persist/load hotkeys
void LoadHotkeys();
void SaveHotkeys();                  // implemented below :contentReference[oaicite:1]{index=1}

// Ensure a name has a default VK code if missing/zero
void SetHotkeyDefault(const std::string& name, int defaultVK);  // :contentReference[oaicite:2]{index=2}

// Utility to show a Windows virtual-key as text
std::string GetKeyName(int vkCode);  // implemented below :contentReference[oaicite:3]{index=3}



//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// 2) Implementation of load/save & helpers
//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// 
// Utility: get path to hotkeys.json in Documents\Hatemob\Hotkeys
inline std::filesystem::path GetHotkeysFilePath() {
    // 1) Get USERPROFILE
    char* userProfile = nullptr;
    size_t len = 0;
    if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0 || !userProfile) {
        return std::filesystem::current_path() / "hotkeys.json";
    }
    std::filesystem::path docs = std::filesystem::path(userProfile) / "Documents";
    free(userProfile);
    // 2) Build and create Hatemob\Hotkeys
    std::filesystem::path hotkeysDir = docs / "Hatemob" / "Hotkeys";
    std::error_code ec;
    std::filesystem::create_directories(hotkeysDir, ec);
    // 3) Return full path to hotkeys.json
    return hotkeysDir / "hotkeys.json";
}


void LoadHotkeys() {
    auto path = GetHotkeysFilePath();
    std::ifstream file(path);
    if (!file.is_open()) return;
    try {
        json j;
        file >> j;
        for (auto& [key, value] : j.items()) {
            if (value.is_number_integer())
                Hotkeys[key] = value.get<int>();
        }
        std::cout << "[Hotkeys] Loaded " << Hotkeys.size() << " hotkeys from " << path << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "[Hotkeys] Load error: " << e.what() << "\n";
    }
}

void SaveHotkeys() {
    json j;
    for (auto& [key, value] : Hotkeys)
        j[key] = value;
    auto path = GetHotkeysFilePath();
    std::ofstream file(path);
    if (file.is_open())
        file << j.dump(4);
    else
        std::cerr << "[Hotkeys] Failed to write " << path << "\n";
}

void SetHotkeyDefault(const std::string& name, int defaultVK) {
    if (Hotkeys.find(name) == Hotkeys.end() || Hotkeys[name] == 0)
        Hotkeys[name] = defaultVK;
}

std::string GetKeyName(int vkCode) {
    UINT sc = MapVirtualKeyA(vkCode, MAPVK_VK_TO_VSC);
    // mark extended keys
    switch (vkCode) {
    case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
    case VK_PRIOR: case VK_NEXT: case VK_END: case VK_HOME:
    case VK_INSERT: case VK_DELETE: case VK_DIVIDE: case VK_NUMLOCK:
    case VK_RCONTROL: case VK_RMENU:
        sc |= 0x100;
    }
    LONG lParam = sc << 16;
    char buf[128] = {};
    if (GetKeyNameTextA(lParam, buf, sizeof(buf)))
        return buf;
    return "Unknown";
}

//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// 3) Now you can safely define DrawHotkeyPicker, RenderAbilityCharge, etc.
//    because Hotkeys, SaveHotkeys, SetHotkeyDefault, and GetKeyName
//    are all already in scope.
//––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

inline bool DrawHotkeyPicker(const std::string& name, const std::string& label, bool& listening) {
    if (ImGui::Button(("Set##" + name).c_str())) listening = true;
    ImGui::SameLine();

    int& hotkey = Hotkeys[name];              // now known :contentReference[oaicite:4]{index=4}
    if (hotkey == 0) hotkey = -1;             // fallback
    ImGui::Text("Key: %s", GetKeyName(hotkey).c_str());  // GetKeyName in scope :contentReference[oaicite:5]{index=5}

    if (listening) {
        ImGui::Text("Press a key…");
        for (int vk = 0x01; vk <= 0xFE; ++vk) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                hotkey = vk;
                listening = false;
                SaveHotkeys();    // SaveHotkeys in scope :contentReference[oaicite:6]{index=6}
                return true;
            }
        }
    }
    return false;
}

// BELOW ARE UTILITY FEATURES

// 1) Single‐value overload (eg. float, uintptr_t, YOUR_STRUCT, etc.)
template<typename T>
BOOL ReadMem(
    HANDLE    driver,
    DWORD     pid,
    uintptr_t address,
    T& outValue
) {
    DriverComm::Request req{};
    req.process_id = reinterpret_cast<HANDLE>(pid);
    req.target = reinterpret_cast<PVOID>(address);
    req.buffer = &outValue;
    req.size = sizeof(T);
    req.return_size = 0;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        driver,
        DriverComm::codes::read,
        &req, sizeof(req),
        &req, sizeof(req),
        &bytesReturned,
        nullptr
    );

    return ok && req.return_size == sizeof(T);
}


// Replicates WriteMem using your kernel driver
// 1) Single‐value overload
template<typename T>
std::enable_if_t<!std::is_array_v<T>, BOOL>
WriteMem(
    HANDLE    driver,
    uintptr_t address,
    const T& value
) {
    DriverComm::Request r{};
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = const_cast<PVOID>(static_cast<const void*>(&value));
    r.size = sizeof(T);
    r.return_size = 0;

    DWORD written = 0;
    BOOL ok = DeviceIoControl(
        driver,
        DriverComm::codes::write,
        &r, sizeof(r),
        &r, sizeof(r),
        &written,
        nullptr
    );

    if (ok) {
        std::cout << "[+] Memory succesfully written at: 0x" << std::hex << address << std::dec << "\n";
    }
    else {
        std::cout << "[-] Memory failed to write at: 0x" << std::hex << address << std::dec << "\n";
    }
    return ok && r.return_size == sizeof(T);
}

// 2) C‐array overload
template<typename T, size_t N>
BOOL WriteMem(
    HANDLE           driver,
    uintptr_t        address,
    const T(&buf)[N]
) {
    DriverComm::Request r{};
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = const_cast<PVOID>(static_cast<const void*>(buf));
    r.size = sizeof(buf);     // == N * sizeof(T)
    r.return_size = 0;

    DWORD written = 0;
    BOOL ok = DeviceIoControl(
        driver,
        DriverComm::codes::write,
        &r, sizeof(r),
        &r, sizeof(r),
        &written,
        nullptr
    );
    if (ok) {
        std::cout << "[+] Memory succesfully written at: 0x" << std::hex << address << std::dec << "\n";
    }
    else {
        std::cout << "[-] Memory failed to write at: 0x" << std::hex << address << std::dec << "\n";
    }
    return ok && r.return_size == r.size;
}

// 3) std::string overload
inline BOOL WriteMem(
    HANDLE             driver,
    uintptr_t          address,
    const std::string& str
) {
    if (str.empty()) return FALSE;
    DriverComm::Request r{};
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = const_cast<PVOID>(static_cast<const void*>(str.data()));
    r.size = str.size();
    r.return_size = 0;

    DWORD written = 0;
    BOOL ok = DeviceIoControl(
        driver,
        DriverComm::codes::write,
        &r, sizeof(r),
        &r, sizeof(r),
        &written,
        nullptr
    );

    if (ok) {
        std::cout << "[+] Memory succesfully written at: 0x" << std::hex << address << std::dec << "\n";
    }
    else {
        std::cout << "[-] Memory failed to write at: 0x" << std::hex << address << std::dec << "\n";
    }
    return ok && r.return_size == str.size();
}

// 4) std::vector<T> overload
template<typename T>
BOOL WriteMem(
    HANDLE              driver,
    uintptr_t           address,
    const std::vector<T>& vec
) {
    if (vec.empty()) return FALSE;
    DriverComm::Request r{};
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = const_cast<PVOID>(static_cast<const void*>(vec.data()));
    r.size = vec.size() * sizeof(T);
    r.return_size = 0;

    DWORD written = 0;
    BOOL ok = DeviceIoControl(
        driver,
        DriverComm::codes::write,
        &r, sizeof(r),
        &r, sizeof(r),
        &written,
        nullptr
    );

    if (ok) {
        std::cout << "[+] Memory succesfully written at: 0x" << std::hex << address << std::dec << "\n";
    }
    else {
        std::cout << "[-] Memory failed to write at: 0x" << std::hex << address << std::dec << "\n";
    }
    return ok && r.return_size == r.size;
}

uintptr_t AllocMem(
    HANDLE driver_handle,           // Your driver handle instead of process handle
    DWORD pid,
    uintptr_t lpAddress,               // Hint address (optional)
    SIZE_T dwSize = 100               // Size to allocate
) {
    if (dwSize == 0)
        return NULL;

    DriverComm::Request r;
    r.alloc_hint = reinterpret_cast<LPVOID>(lpAddress);       // Can be NULL or a hint address
    r.size = dwSize;
    r.base_address = NULL;          // Will be filled by the driver
    r.process_id = reinterpret_cast<HANDLE>(pid);

    DWORD bytes_returned = 0;
    BOOL success = DeviceIoControl(
        driver_handle,
        DriverComm::codes::allocate_memory,
        &r,
        sizeof(r),
        &r,
        sizeof(r),
        &bytes_returned,
        nullptr
    );

    if (!success) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return NULL;
    }

    return reinterpret_cast<uintptr_t>(r.base_address);
}

BOOL InjectCodecave(
    HANDLE             driver,
    DWORD              pid,
    uintptr_t          targetAddress,
    const std::string& shellcodeHex,    // e.g. "90503258" or "90 50 32 58"
    SIZE_T             originalSize,     // bytes to overwrite at target
    uintptr_t& codecaveAddress   // in/out: 0 to allocate; returns cave addr
) {
    // ─── 1) Parse the hex string into bytes ───
    std::vector<BYTE> scBytes;
    {
        // Remove all whitespace from the input
        std::string hex = shellcodeHex;
        hex.erase(
            std::remove_if(hex.begin(), hex.end(),
                [](unsigned char c) { return std::isspace(c); }
            ),
            hex.end()
        );

        // Must be an even number of hex digits
        if (hex.size() % 2 != 0) {
            std::cerr << "[-] Hex string has odd length: "
                << hex.size() << "\n";
            return FALSE;
        }

        scBytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            // Take two characters, e.g. "9F"
            std::string byteStr = hex.substr(i, 2);
            BYTE b = static_cast<BYTE>(
                std::stoul(byteStr, nullptr, 16)
                );
            scBytes.push_back(b);
        }

        if (scBytes.size() < 5) {
            std::cerr << "[-] Shellcode must be at least 5 bytes\n";
            return FALSE;
        }
    }

    // ─── 2) Allocate codecave if needed ───
    if (codecaveAddress == 0) {
        codecaveAddress = AllocMem(driver, pid, targetAddress);
        if (codecaveAddress == 0) {
            std::cerr << "[-] AllocMem failed: "
                << GetLastError() << "\n";
            return FALSE;
        }
    }

    std::cout << "[+] Codecave address: 0x" << std::hex << codecaveAddress << std::dec << "\n";

    // ─── 3) Patch the tail of shellcode into a JMP back ───
    SIZE_T scSize = scBytes.size();
    std::vector<BYTE> fullSC = std::move(scBytes);
    SIZE_T jmpOff = scSize - 5;
    fullSC[jmpOff] = 0xE9;  // JMP opcode
    DWORD retRel = DWORD(
        (targetAddress + originalSize)
        - (codecaveAddress + jmpOff + 5)
    );
    memcpy(&fullSC[jmpOff + 1], &retRel, sizeof(retRel));

    // ─── 4) Write shellcode into the codecave ───
    SIZE_T bytesWritten = 0;
    if (!WriteMem(driver, codecaveAddress, fullSC)) {
        std::cerr << "[-] WriteMem(cave) failed: " << GetLastError() << "\n";
        return FALSE;
    }

    // ─── 5) Patch original code with JMP + NOPs ───
    std::vector<BYTE> patch(originalSize, 0x90);  // NOP-fill
    patch[0] = 0xE9;  // JMP
    DWORD jmpRel = DWORD(
        codecaveAddress
        - (targetAddress + 5)
    );
    memcpy(&patch[1], &jmpRel, sizeof(jmpRel));

    bytesWritten = 0;
    if (!WriteMem(driver, targetAddress, patch)) {
        std::cerr << "[-] WriteMem(target) failed: " << GetLastError() << "\n";
        return FALSE;
    }


    std::cout << "[+] Codecave injected:\n"
        << "    original @ 0x" << std::hex
        << targetAddress << "\n"
        << "    cave     @ 0x" << codecaveAddress
        << std::dec << "\n";
    return TRUE;
}

uintptr_t AOBScan(
    HANDLE driverHandle,
    DWORD pid,
    const std::wstring& moduleName,
    const std::string& patternString
) {
    // 1) Parse the pattern string into bytes + mask
    std::vector<BYTE> patternBytes;
    std::string     mask;
    {
        std::istringstream iss(patternString);
        std::string token;
        while (iss >> token) {
            if (token == "?" || token == "??") {
                patternBytes.push_back(0x00);
                mask.push_back('?');
            }
            else {
                BYTE b = static_cast<BYTE>(std::stoi(token, nullptr, 16));
                patternBytes.push_back(b);
                mask.push_back('x');
            }
        }
        if (patternBytes.empty() || patternBytes.size() != mask.size()) {
            std::cerr << "[-] Failed to parse pattern: \""
                << patternString << "\"\n";
            return 0;
        }
    }

    // 2) Build and populate a local Request
    DriverComm::Request req{};
    req.process_id = reinterpret_cast<HANDLE>(pid);

    // copy module name (must match type in Request—here assumed WCHAR[])
    wcsncpy_s(
        req.moduleName,
        moduleName.c_str(),
        _TRUNCATE
    );

    // copy the parsed pattern + mask
    if (patternBytes.size() > sizeof(req.aob_pattern) ||
        mask.size() > sizeof(req.aob_mask))
    {
        std::cerr << "[-] Pattern too long ("
            << patternBytes.size()
            << " bytes)\n";
        return 0;
    }
    memcpy(req.aob_pattern, patternBytes.data(), patternBytes.size());
    memcpy(req.aob_mask, mask.c_str(), mask.size() + 1);  // include NUL

    // 3) Fire the IOCTL
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        driverHandle,
        DriverComm::codes::aob_scan,
        &req, sizeof(req),
        &req, sizeof(req),
        &bytesReturned,
        nullptr
    );

    if (!ok) {
        std::cerr << "[-] AOBScan IOCTL failed: "
            << GetLastError() << "\n";
        return 0;
    }

    // 4) Return the found address (or 0 if not found)
    if (req.base_address != nullptr) {
        uintptr_t found = reinterpret_cast<uintptr_t>(req.base_address);
        std::cout << "[+] AOB match at 0x"
            << std::hex << found << "\n";
        return found;
    }
    else {
        std::cout << "[*] Pattern not found.\n";
        return 0;
    }
}


// User-mode function to perform heap AOB scan
// DriverComm.cpp
uintptr_t HeapAOBScan(
    HANDLE               hDriver,
    HANDLE               targetProcessId,
    const unsigned char* pattern,
    size_t               patternSize,
    const char* mask,
    uintptr_t            startAddress,    // NEW
    uintptr_t            endAddress       // NEW
) {
    DriverComm::Request req{};
    req.process_id = targetProcessId;
    req.start_address = (PVOID)startAddress;
    req.end_address = (PVOID)endAddress;

    memcpy(req.aob_pattern, pattern, patternSize);
    strncpy_s(req.aob_mask, mask, _TRUNCATE);

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
        hDriver,
        DriverComm::codes::heap_aob_scan,
        &req, sizeof(req),
        &req, sizeof(req),
        &bytesReturned,
        nullptr
    )) {
        std::cerr << "[-] IOCTL failed: " << GetLastError() << "\n";
        return 0;
    }

    return reinterpret_cast<uintptr_t>(req.base_address);
}

uintptr_t AobScanProcessRange(
    HANDLE hDriver,
    DWORD targetPID,
    LPCSTR patternString,
    uintptr_t start,
    uintptr_t end
) {
    DriverComm::Request req{};
    req.process_id = (HANDLE)targetPID;
    req.start_address = reinterpret_cast<PVOID>(start);
    req.end_address = reinterpret_cast<PVOID>(end);
    strncpy_s(req.aob_pattern, patternString, sizeof(req.aob_pattern) - 1);

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDriver,
        DriverComm::codes::process_aob_scan,
        &req, sizeof(req),
        &req, sizeof(req),
        &bytesReturned,
        nullptr
    );

    if (success && req.base_address != nullptr) {
        std::cout << "[+] AOB match found at: 0x" << std::hex << reinterpret_cast<uintptr_t>(req.base_address) << "\n";
        std::cout << "[+] Matches returned: " << std::dec << req.return_size << "\n";
        return reinterpret_cast<uintptr_t>(req.base_address);
    }

    std::cerr << "[-] AOB scan failed or no matches found.\n";
    return 0;
}


namespace Killaura {
    // Killaura settings
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 0F 10 41 20 32 C0 0F C6 C0 ? 0F 11 02 C3 ? 0F ? ? ? 32";

    std::string shellcode =
        "c7 41 20 "                  // mov dword ptr [rcx+0x20],
        "00 00 7a 44 "              //     float 1000.0f → 0x447A0000 (little-endian)
        "f3 0f 10 41 20 "           // movss xmm0, [rcx+0x20]
        "e9 00 00 00 00";           // jmp return (relative jump placeholder)

    BYTE origBytes[5] = {};



    uintptr_t InstructionAddress = 0;
}

namespace LocalPlayer {
    // LocalPlayer settings
    // localplayer AOB and mask
    struct Vec3 {
        float x, y, z;
    };

    std::atomic<Vec3> g_cachedCoords{ {0, 0, 0} };

    bool Enabled = false;
    bool flyEnabled = false;

    int FlyToggleHotkey = VK_H;       // Default: H to toggle
    int FlyBoostHotkey = VK_G;        // Default: G to boost
    bool FlyHotkeyListening = false;
    bool BoostHotkeyListening = false;
    bool FlyHotkeyWasDown = false;

    inline int   KillKey = VK_J;   // Default kill key
    inline bool  KillKeyWasDown = false;
    inline bool  KillKeyEnabled = false;  // ← new!


    uintptr_t destinyBase = 0x301F8F0;

    std::atomic<uintptr_t> realPlayer = 0;

    bool mem_allocated = false;

    uintptr_t disableGravMemAllocatedAddress = 0;
    uintptr_t memAllocatedAddress = 0;
    uintptr_t addrMemAllocatedAddress = 0;

    std::string AOB = "0F 10 89 ? ? ? ? 0F 54 0D ? ? ? ? 66 0F 6F ? ? ? ? ? 0F 54 C8 66 0F 72 D2 ? 66 0F 72 F2 ? 0F 55 C2 0F 56 C8 0F 11 0A E9 ? ? ? ? 48 81 C1";

    std::string shellcode =
        "50 "                              // push rax
        "48 89 c8 "                        // mov rax, rcx
        "48 a3 "                           // mov [abs64], rax
        "00 00 00 00 "                    // LocalPlayer address (little-endian)
        "00 00 00 00 "
        "58 "                              // pop rax
        "0f 10 89 c0 01 00 00 "           // movups xmm1, [rcx+1C0]
        "e9 00 00 00 00";                 // jmp return (rel32)

    uintptr_t disableGravAddress = 0;
    std::string disableGravAOB = "88 51 79 8B D0";
    std::string disableGravShellcode = "C7 41 79 01 00 00 00" // mov [rcx+79],1
        "8B D0"                // mov edx,eax
        "E9 00 00 00 00";      // jmp return

    BYTE disableGravOrigBytes[5] = {};

    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;

    uintptr_t addr;
}
LocalPlayer::Vec3 entity;


namespace Ghostmode {

    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 0F 11 4C 24 38 B9 DD AD 93 43 8B 5C 24 38 B8 9C 6E 3F 2B 66 66 0F 1F 84 00 00 00 00 00";

    BYTE origBytes[6] = {};

    std::string shellcode =
        "b8 00 00 80 bf "             // mov eax, 0xBF800000 (-1.0)
        "66 0f 6e c8 "                // movd xmm1, eax
        "f3 0f 11 4c 24 38 "          // movss [rsp+0x38], xmm1
        "e9 00 00 00 00";             // jmp return (placeholder offset)

    uintptr_t InstructionAddress = 0;
}

namespace Godmode {
    // Godmode settings
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "33 DA C1 C3 10 E8 ? ? ? ? 48";

    std::string shellcode =
        "6b db 01 "                 // imul ebx, 1
        "e9 00 00 00 00";           // jmp return (offset placeholder)


    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;
}

namespace InfAmmo {

    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "44 0F 28 BD F0 05 00 00 48 83 C3";

    std::string shellcode =
        // cmp dword ptr [rbp+0x5F0], 0xBF800000  (float -1)
        "81 bd f0 05 00 00 00 00 80 bf "

        // jne code_dexxa (placeholder)
        "0f 85 00 00 00 00 "

        // mov dword ptr [rbp+0x5F0], 0x00000000
        "c7 85 f0 05 00 00 00 00 00 00 "

        // code_dexxa:
        // movaps xmm15, [rbp+0x5F0]
        "44 0f 28 bd f0 05 00 00 "

        // jmp return_dexxa (placeholder)
        "e9 00 00 00 00";

    BYTE origBytes[8] = {};

    uintptr_t InstructionAddress = 0;
}

namespace dmgMult {
    // Damage Multiplier settings
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 44 0F 10 61 24 44 0F 29 68 88 F3 44 0F 10 69 1C";

    std::string shellcode =
        "c7 41 24 00 40 9c 45 "            // mov dword ptr [rcx+0x24], 5000.0f
        "f3 44 0f 10 61 24 "              // movss xmm12, [rcx+0x24]
        "e9 00 00 00 00";                 // jmp return (rel32 placeholder)


    BYTE origBytes[6] = {};

    uintptr_t InstructionAddress = 0;
}

namespace FOV {
    // FOV settings
    std::string AOB = "30 00 00 00 00 00 00 00 28 C8 0A 00 00 00 00 00 40 01 00 00 00 00 00 00 A0 08";

    uint8_t fov = 0;
    uintptr_t ptr = 0;

    uintptr_t InstructionAddress = 0;
    uintptr_t offset = 0x530;
    uintptr_t pointer = 0x5DC;
}

namespace ViewAngles {
    // view angle hook
    struct Vec2 {
        float pitch, yaw;
    };

    static std::atomic<uintptr_t>  g_viewBase{ 0 };
    static std::atomic<ViewAngles::Vec2>       g_cachedAngles{ {0.0f, 0.0f} };
    static std::atomic<bool>       g_cacheThreadRunning{ false };

    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;
    uintptr_t addrMemAllocatedAddress = 0;
    uintptr_t addr;

    void UpdateBase(HANDLE driver, DWORD pid) {
        ReadMem(driver, pid, addrMemAllocatedAddress, addr);

    }

    std::string AOB = "F3 0F 11 47 1C 7A";

    std::string shellcode =
        "50 "                              // push rax
        "48 89 f8 "                        // mov rax, rdi
        "48 a3 "                           // mov [abs address], rax
        "00 00 00 00 00 00 00 00 "         // placeholder for ViewAngles address (8 bytes)
        "58 "                              // pop rax
        "f3 0f 11 47 1c "                  // movss [rdi+1C], xmm0
        "e9 00 00 00 00";                  // jmp return (relative offset placeholder, 4 bytes)


    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;

    void CacheLoop(HANDLE driver, DWORD pid) {
        g_cacheThreadRunning = true;

        while (g_cacheThreadRunning) {
            uintptr_t base = 0;
            ReadMem(driver, pid,
                addrMemAllocatedAddress,
                base);
            g_viewBase = base;
            addr = base;

            // Read view angles
            Vec2 angles{ 0.0f, 0.0f };
            ReadMem(driver, pid,
                base + 0x18,
                angles);
            g_cachedAngles = angles;

            // Read coordinates
            LocalPlayer::Vec3 coords{ 0.0f, 0.0f, 0.0f };
            ReadMem(driver, pid, LocalPlayer::realPlayer.load() + 0x1C0, coords);
            LocalPlayer::g_cachedCoords = coords;

            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    }

}
ViewAngles::Vec2 viewAngles;

namespace RPM {

    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 0F 11 86 CC 17 00 00 48";

    std::string shellcode =
        "f3 0f 10 86 9c 17 00 00 "        // movss xmm0, [rsi+179C]
        "f3 0f 59 c0 "                    // mulss xmm0, xmm0
        "f3 0f 11 86 9c 17 00 00 "        // movss [rsi+179C], xmm0
        "f3 0f 11 86 cc 17 00 00 "        // movss [rsi+17CC], xmm0
        "e9 00 00 00 00";                 // jmp <return>

    BYTE origBytes[8] = {};

    uintptr_t InstructionAddress = 0;

}

namespace NoRecoil {

    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "0F 11 8B ? ? ? ? 0F 28 CD";

    std::string shellcode =
        // pxor xmm1, xmm1 (zeroing xmm1 directly - much cleaner)
        "66 0f ef c9 "

        // movups [rbx+1050], xmm1
        "0f 11 8b 50 10 00 00 "

        // jmp return (to be patched)
        "e9 00 00 00 00";


    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;


}

namespace OHK {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 0F 11 44 24 50 33 C0 8B";

    std::string shellcode =
        "0f ef c0 "                    // pxor xmm0, xmm0
        "f3 0f 11 44 24 32 "           // movss [rsp+32], xmm0
        "e9 00 00 00 00";              // jmp return (placeholder offset)


    BYTE origBytes[6] = {};

    uintptr_t InstructionAddress = 0;
}

namespace NoJoinAllies {
    // just a nop
    bool Enabled = false;

    std::string AOB = "48 01 47 ? EB ? 48";

    BYTE nops[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    BYTE origBytes[6] = {};

    uintptr_t InstructionAddress = 0;
}

namespace NoTurnBack {
    bool Enabled = false;

    std::string AOB = "F3 0F 11 46 ? E9 ? ? ? ? 44 0F B6";

    BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;
}

namespace InfSwordAmmo {
    bool Enabled = false;

    std::string AOB = "0F 28 C7 F3 41 0F 5C C0 0F 2F C6 ? ? 41 0F 28 F8 F3";

    BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    BYTE origBytes[8] = {};

    uintptr_t InstructionAddress = 0;
}

namespace SparrowAnywhere {
    bool Enabled = false;

    std::string AOB = "74 ?? 48 8B C8 48 89 7C 24 30 E8 ?? ?? ?? ?? 48 8B CB 48 8B F8 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 ?? ?? 80 78 0E 00";

    BYTE mybyte[] = { 0x75 };
    BYTE origByte[] = { 0x74 };

    uintptr_t InstructionAddress = 0;
}

namespace InfStacks {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "89 5F ? 74 ? 8B";

    std::string shellcode =
        "bb 64 00 00 00 "           // mov ebx, 100
        "89 5f 30 "                 // mov [rdi+0x30], ebx
        "e9 00 00 00 00";           // jmp return

    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;
}

namespace NoRezTokens {
    bool Enabled = false;

    std::string AOB = "75 08 E8 ?? ?? ?? ?? 89";

    BYTE myByte[] = { 0xEB };
    BYTE origByte[] = { 0x75 };

    uintptr_t InstructionAddress = 0;
}

namespace InstaRespawn {
    bool Enabled = false;

    std::string AOB = "49 8B ? ? ? ? ? 48 8B 08 48 3B";

    BYTE myBytes[] = {
    0x48, 0x31, 0xD2,                          // xor rdx, rdx
    0x90, 0x90, 0x90, 0x90                     // nops
    };

    byte origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace RespawnAnywhere {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "48 89 ? ? ? ? ? ? ? 0F 28 CE 48 8D";

    std::string shellcode =
        "50 "                             // push rax
        "48 31 c0 "                       // xor rax, rax
        "48 89 86 68 08 00 00 "           // mov [rsi+0x868], rax
        "58 "                             // pop rax
        "e9 00 00 00 00";                 // jmp return



    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace ShootThru {
    bool Enabled = false;

    std::string AOB = "0F 11 02 0F 11 4A 10 44 0F 28 0D";

    BYTE nops[] = { 0x90, 0x90, 0x90 };
    BYTE origBytes[3] = {};

    uintptr_t InstructionAddress = 0;
}

namespace Chams {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "0F 10 02 48 83 C1 60";

    std::string shellcode =
        "b8 a6 95 80 80 "              // mov eax, 0x80808086
        "39 42 78 "                    // cmp [rdx+0x78], eax
        "0f 85 06 00 00 00 "           // jne +6
        "c7 02 00 00 20 41 "           // mov dword ptr [rdx], 0x41200000 (10.0f)
        "0f 10 02 "                    // movups xmm0, [rdx]
        "48 83 c1 60 "                 // add rcx, 0x60
        "e9 00 00 00 00";              // jmp return (fill this in later)


    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace ImmuneBosses {
    std::atomic<bool> Enabled = false;
    std::atomic<bool> ThreadRunning = false;
    uintptr_t Address = 0;
}

namespace AbilityCharge {
    bool Enabled = false;
    bool mem_allocated = false;
    uintptr_t memAllocatedAddress = 0;
    bool WasKeyDown = false;
    inline bool IsListeningForHotkey = false;

    std::string AOB = "0F 10 02 48 83 C1 60";

    std::string shellcode =
        "50 "             // push rax
        "b8 00 00 80 3f " // mov eax, 1.0f
        "f3 0f 2a c0 "    // cvtsi2ss xmm0, eax
        "48 83 c1 60 "    // add rcx, 0x60
        "58 "             // pop rax
        "e9 00 00 00 00"; // jmp return

    BYTE origBytes[7] = {};
    uintptr_t InstructionAddress = 0;
}

namespace ImmuneAura {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "0F 10 02 48 83 C1 60";

    std::string shellcode =
        "50 "                          // push rax
        "b8 e8 03 00 00 "              // mov eax, 000003E8 (float 1000)
        "f3 0f 2a c0 "                 // cvtsi2ss xmm0, eax
        "48 83 c1 60 "                 // add rcx, 0x60
        "58 "                          // pop rax
        "e9 00 00 00 00";              // jmp return


    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace IcarusDash {
    bool Enabled = false;

    std::string AOB = "89 46 34 89 6E 3C";

    BYTE nops[] = { 0x90, 0x90, 0x90 };
    BYTE origBytes[] = { 0x89, 0x46, 0x34 };

    uintptr_t InstructionAddress = 0;
}

namespace InstantInteract {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "F3 0F 11 43 08 48 83 C4 30 5B C3 48";

    std::string shellcode =
        "c7 43 08 00 00 00 00 "         // mov [rbx+08], 0
        "e9 00 00 00 00";               // jmp return

    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;
}

namespace InteractThruWalls {
    bool Enabled = false;

    bool mem_allocated1 = false;
    bool mem_allocated2 = false;

    uintptr_t memAllocatedAddress1 = 0;
    uintptr_t memAllocatedAddress2 = 0;

    std::string AOB1 = "8B 54 01 6C 8B 4F 24";

    std::string AOB2 = "0F 11 02 0F 11 4A 10 44 0F 28 0D";

    std::string shellcode1 =
        "c7 44 01 6c 00 00 7a 44 "      // mov dword ptr [rcx + rax + 0x6C], 0x447A0000
        "8b 54 01 6c "                 // mov edx, dword ptr [rcx + rax + 0x6C]
        "8b 4f 24 "                    // mov ecx, dword ptr [rdi + 0x24]
        "e9 00 00 00 00";              // jmp return


    std::string shellcode2 =
        "c7 02 10 27 00 00 "           // mov [rdx], 10000
        "0f 11 4a 10 "                 // movups [rdx+10], xmm1
        "e9 00 00 00 00";              // jmp return


    BYTE origBytes1[7] = {};
    BYTE origBytes2[7] = {};

    uintptr_t InstructionAddress1 = 0;
    uintptr_t InstructionAddress2 = 0;
}

namespace GameSpeed {
    bool Enabled = false;                 // Whether feature is active
    int Hotkey = VK_V;                    // Default hotkey (can be customizable)

    std::string AOB = "00 5B 24 49 00 24 74 49 0A D7 23 3C 0A D7 23 3C 0A D7 23 3C 0A D7 23 3C 00 00 00 00 00 00 00 00 00 00 00";


    uintptr_t Address = 0;          // Address to write to (set during init or AOB)
    float FastValue = 9000.0f;            // Value when key is held
    float NormalValue = 673200.0f;        // Value when key is released
    bool WasKeyDown = false;              // Track toggle state
}

namespace LobbyCrasher {
    bool Enabled = false;

    std::string AOB = "C7 43 04 FF FF FF FF C6 03 01 48 83 C4 20 5B C3 48 8B";

    BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace GSize {
    bool Enabled = false;
    bool hasScanned = false;

    std::string AOB = "00 00 80 3F 80 F0 FA 02";

    float Value = 0.0f;
    float inputVal = 0;
    uintptr_t Address = 0;
}

namespace Oxygen {
    bool Enabled = false;

    std::string AOB = "0F 28 C8 E8 ? ? ? ? 0F B6 43 0C";

    BYTE nops[] = { 0x90 ,0x90, 0x90 };
    BYTE origBytes[3] = {};

    uintptr_t InstructionAddress;
}

namespace InfSparrowBoost {
    bool Enabled = false;

    bool mem_allocated = false;

    std::string AOB = "72 34 48 8D 4B 50";

    BYTE myByte[] = { 0x77 };
    BYTE origByte[] = { 0x72 };

    uintptr_t InstructionAddress = 0;
}

namespace InfBuffTimers {
    bool Enabled = false;

    std::string AOB = "48 89 8B A0 00 00 00 48 8D 4C 24 30 E8 ? ? ? ? 48 8B 08 48 39";

    BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE origBytes[7] = {};

    uintptr_t InstructionAddress = 0;
}

namespace InfExoticBuffTimers {
    bool Enabled = false;

    std::string AOB = "F3 0F 5C C7 F3 0F 5F C6 0F 2E";

    BYTE nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    BYTE origBytes[8] = {};

    uintptr_t InstructionAddress = 0;
}

namespace AntiFlinch {
    bool Enabled = false;

    std::string AOB1 = "F3 0F 11 8B E0 16 00 00";

    std::string AOB2 = "F3 0F 11 8B E4 16 00 00";

    std::string AOB3 = "F3 0F 11 83 E8 16 00 00";

    BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE origBytes1[8] = {};
    BYTE origBytes2[8] = {};
    BYTE origBytes3[8] = {};

    uintptr_t InstructionAddress1;
    uintptr_t InstructionAddress2;
    uintptr_t InstructionAddress3;
}

namespace ActivityLoader {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;
    uintptr_t addrMemAllocatedAddress = 0;
    uintptr_t addr;

    std::string AOB = "44 0F B7 4A 02 44";

    std::string shellcode = "48 89 15" // mov [activity], rdx
        "00 00 00 00"
        "44 0F B7 4A 02" // r9d,word ptr [rdx+02]
        "E9 00 00 00 00"; // jmp return

    BYTE origBytes[5] = {};

    uintptr_t InstructionAddress = 0;
}

namespace Mag999 {
    bool Enabled = false;

    bool mem_allocated = false;

    uintptr_t memAllocatedAddress = 0;

    std::string AOB = "0F 10 04 C1 48 83 C2 10 49";

    std::string shellcode = "50" // push rax
        "B8 8A 49 FD 79" // mov eax, 0x79FD498A
        "66 0F 6E D0" // movd xmm2, eax
        "58" // pop rax
        "F3 0F 10 44 C1 B8" // movss xmm0, [rcx+rax*8-48]
        "0F 2E C2" // ucomiss xmm0, xmm2
        "0F 85 16 00 00 00" // jne
        "50" // push rax
        "B8 20 BC BE 4C" // mov eax, 0x4CBEBC20
        "66 0F 6E D0" // movd xmm2, eax
        "58" // pop rax
        "F3 0F 11 14 C1" // movss [rcx+rax*8], xmm2
        "F3 0F 11 54 C1 50" // movss [rcx+rax*8+50], xmm2
        "50" // push rax
        "B8 02 03 02 34" // mov eax, 34020302
        "66 0F 6E D0" // movd xmm2, eax
        "58" // pop rax
        "F3 0F 10 44 C1 B8" // movss xmm0, [rcx+rax*8-48]
        "0F 2E C2" // ucomiss xmm0, xmm2
        "0F 85 16 00 00 00" // jne
        "50" // push rax
        "B8 20 BC BE 4C" // mov eax, 4CBEBC20
        "66 0F 6E D0" // movd xmm2, eax
        "58" // pop rax
        "F3 0F 11 14 C1" // movss [rcx+rax*8], xmm2
        "F3 0F 11 54 C1 10" // movss [rcx+rax*8+10], xmm2
        "0F 10 04 C1" // movups xmm0, [rcx+rax*8]
        "48 83 C2 10" // add rdx, 0x10
        "E9 00 00 00 00"; // jmp return

    BYTE origBytes[8] = {};

    uintptr_t InstructionAddress = 0;
}
// BELOW ARE FUNCTIONS TO TOGGLE FEATURES

void PerformStartupAobScans(HANDLE driver, DWORD pid, std::wstring wModuleName)
{
    LocalPlayer::InstructionAddress = AOBScan(driver, pid, wModuleName, LocalPlayer::AOB);
    Killaura::InstructionAddress = AOBScan(driver, pid, wModuleName, Killaura::AOB);
    ViewAngles::InstructionAddress = AOBScan(driver, pid, wModuleName, ViewAngles::AOB);
    Ghostmode::InstructionAddress = AOBScan(driver, pid, wModuleName, Ghostmode::AOB);
    Godmode::InstructionAddress = AOBScan(driver, pid, wModuleName, Godmode::AOB);
    InfAmmo::InstructionAddress = AOBScan(driver, pid, wModuleName, InfAmmo::AOB);
    dmgMult::InstructionAddress = AOBScan(driver, pid, wModuleName, dmgMult::AOB);
    RPM::InstructionAddress = AOBScan(driver, pid, wModuleName, RPM::AOB);
    NoRecoil::InstructionAddress = AOBScan(driver, pid, wModuleName, NoRecoil::AOB);
    OHK::InstructionAddress = AOBScan(driver, pid, wModuleName, OHK::AOB);
    NoJoinAllies::InstructionAddress = AOBScan(driver, pid, wModuleName, NoJoinAllies::AOB);
    NoTurnBack::InstructionAddress = AOBScan(driver, pid, wModuleName, NoTurnBack::AOB);
    InfSwordAmmo::InstructionAddress = AOBScan(driver, pid, wModuleName, InfSwordAmmo::AOB);
    SparrowAnywhere::InstructionAddress = AOBScan(driver, pid, wModuleName, SparrowAnywhere::AOB);
    InfStacks::InstructionAddress = AOBScan(driver, pid, wModuleName, InfStacks::AOB);
    NoRezTokens::InstructionAddress = AOBScan(driver, pid, wModuleName, NoRezTokens::AOB);
    InstaRespawn::InstructionAddress = AOBScan(driver, pid, wModuleName, InstaRespawn::AOB);
    RespawnAnywhere::InstructionAddress = AOBScan(driver, pid, wModuleName, RespawnAnywhere::AOB);
    ShootThru::InstructionAddress = AOBScan(driver, pid, wModuleName, ShootThru::AOB);
    Chams::InstructionAddress = AOBScan(driver, pid, wModuleName, Chams::AOB);
    AbilityCharge::InstructionAddress = AOBScan(driver, pid, wModuleName, AbilityCharge::AOB);
    ImmuneAura::InstructionAddress = AOBScan(driver, pid, wModuleName, ImmuneAura::AOB);
    IcarusDash::InstructionAddress = AOBScan(driver, pid, wModuleName, IcarusDash::AOB);
    InstantInteract::InstructionAddress = AOBScan(driver, pid, wModuleName, InstantInteract::AOB);
    GameSpeed::Address = AOBScan(driver, pid, wModuleName, GameSpeed::AOB);
    LobbyCrasher::InstructionAddress = AOBScan(driver, pid, wModuleName, LobbyCrasher::AOB);
    FOV::InstructionAddress = AOBScan(driver, pid, wModuleName, FOV::AOB);
    Oxygen::InstructionAddress = AOBScan(driver, pid, wModuleName, Oxygen::AOB);
    InfSparrowBoost::InstructionAddress = AOBScan(driver, pid, wModuleName, InfSparrowBoost::AOB);
    InteractThruWalls::InstructionAddress1 = AOBScan(driver, pid, wModuleName, InteractThruWalls::AOB1);
    InteractThruWalls::InstructionAddress2 = AOBScan(driver, pid, wModuleName, InteractThruWalls::AOB2);
    AntiFlinch::InstructionAddress1 = AOBScan(driver, pid, wModuleName, AntiFlinch::AOB1);
    AntiFlinch::InstructionAddress2 = AOBScan(driver, pid, wModuleName, AntiFlinch::AOB2);
    AntiFlinch::InstructionAddress3 = AOBScan(driver, pid, wModuleName, AntiFlinch::AOB3);
    LocalPlayer::disableGravAddress = AOBScan(driver, pid, wModuleName, LocalPlayer::disableGravAOB);
    InfBuffTimers::InstructionAddress = AOBScan(driver, pid, wModuleName, InfBuffTimers::AOB);
    InfExoticBuffTimers::InstructionAddress = AOBScan(driver, pid, wModuleName, InfExoticBuffTimers::AOB);
    ActivityLoader::InstructionAddress = AOBScan(driver, pid, wModuleName, ActivityLoader::AOB);
    Mag999::InstructionAddress = AOBScan(driver, pid, wModuleName, Mag999::AOB);
}

void PerformStartupByteReads(HANDLE driver, DWORD pid)
{
    ReadMem(driver, pid, Killaura::InstructionAddress, Killaura::origBytes);
    ReadMem(driver, pid, ViewAngles::InstructionAddress, ViewAngles::origBytes);
    ReadMem(driver, pid, Ghostmode::InstructionAddress, Ghostmode::origBytes);
    ReadMem(driver, pid, Godmode::InstructionAddress, Godmode::origBytes);
    ReadMem(driver, pid, dmgMult::InstructionAddress, dmgMult::origBytes);
    ReadMem(driver, pid, RPM::InstructionAddress, RPM::origBytes);
    ReadMem(driver, pid, NoRecoil::InstructionAddress, NoRecoil::origBytes);
    ReadMem(driver, pid, OHK::InstructionAddress, OHK::origBytes);
    ReadMem(driver, pid, ShootThru::InstructionAddress, ShootThru::origBytes);
    ReadMem(driver, pid, Chams::InstructionAddress, Chams::origBytes);
    ReadMem(driver, pid, AbilityCharge::InstructionAddress, AbilityCharge::origBytes);
    ReadMem(driver, pid, ImmuneAura::InstructionAddress, ImmuneAura::origBytes);
    ReadMem(driver, pid, InstantInteract::InstructionAddress, InstantInteract::origBytes);
    ReadMem(driver, pid, LobbyCrasher::InstructionAddress, LobbyCrasher::origBytes);
    ReadMem(driver, pid, Oxygen::InstructionAddress, Oxygen::origBytes);
    ReadMem(driver, pid, InteractThruWalls::InstructionAddress1, InteractThruWalls::origBytes1);
    ReadMem(driver, pid, InteractThruWalls::InstructionAddress2, InteractThruWalls::origBytes2);
    ReadMem(driver, pid, AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
    ReadMem(driver, pid, AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
    ReadMem(driver, pid, AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
    ReadMem(driver, pid, RespawnAnywhere::InstructionAddress, RespawnAnywhere::origBytes);
    ReadMem(driver, pid, InstaRespawn::InstructionAddress, InstaRespawn::origBytes);
    ReadMem(driver, pid, FOV::InstructionAddress + FOV::offset, FOV::ptr);
    ReadMem(driver, pid, InfSwordAmmo::InstructionAddress, InfSwordAmmo::origBytes);
    ReadMem(driver, pid, LocalPlayer::disableGravAddress, LocalPlayer::disableGravOrigBytes);
    ReadMem(driver, pid, InfBuffTimers::InstructionAddress, InfBuffTimers::origBytes);
    ReadMem(driver, pid, InfExoticBuffTimers::InstructionAddress, InfExoticBuffTimers::origBytes);
    ReadMem(driver, pid, Mag999::InstructionAddress, Mag999::origBytes);

    std::cout << "[+] All bytes succesfully stored\n";
}

bool EnableViewAngleHook(HANDLE driver, DWORD pid) {
    using namespace ViewAngles;

    constexpr SIZE_T originalSize = sizeof(origBytes);    // 5
    const uintptr_t returnAddr = InstructionAddress + 5;

    // 1) Read and save the original bytes
    if (!ReadMem(driver, pid, InstructionAddress, origBytes)) {
        std::cout << "[-] Failed to read original bytes\n";
        return false;
    }

    // 2) Allocate cave & storage once
    if (!mem_allocated) {
        // figure out caveSize from shellcode string
        std::string tmp = shellcode;
        tmp.erase(std::remove_if(tmp.begin(), tmp.end(),
            [](unsigned char c) { return std::isspace(c); }),
            tmp.end());
        SIZE_T caveSize = tmp.size() / 2;

        memAllocatedAddress = AllocMem(driver, pid, InstructionAddress, caveSize);
        addrMemAllocatedAddress = AllocMem(driver, pid, InstructionAddress, caveSize);
        if (!memAllocatedAddress || !addrMemAllocatedAddress) {
            std::cout << "[-] Failed to allocate memory regions\n";
            return false;
        }
        mem_allocated = true;
    }

    // 3) Parse shellcode hex → byte buffer
    std::string hex = shellcode;
    hex.erase(std::remove_if(hex.begin(), hex.end(),
        [](unsigned char c) { return std::isspace(c); }),
        hex.end());
    if (hex.size() % 2 != 0) {
        std::cerr << "[-] shellcode string has odd length\n";
        return false;
    }
    std::vector<BYTE> caveBuf;
    caveBuf.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        caveBuf.push_back(static_cast<BYTE>(
            std::stoul(hex.substr(i, 2), nullptr, 16)
            ));
    }
    SIZE_T caveSize = caveBuf.size();

    // 4) Patch the absolute‐address slot at offset 6 (8 bytes)
    memcpy(&caveBuf[6],
        &addrMemAllocatedAddress,
        sizeof(addrMemAllocatedAddress));

    // 5) Patch the return‐jump placeholder (last 4 bytes)
    {
        uintptr_t caveEnd = memAllocatedAddress + caveSize;
        int32_t  relJmp = int32_t(returnAddr - caveEnd);
        memcpy(&caveBuf[caveSize - 4],
            &relJmp,
            sizeof(relJmp));
    }

    // 6) Write the patched cave
    if (!WriteMem(driver, memAllocatedAddress, caveBuf)) {
        std::cout << "[-] Failed to write shellcode cave: "
            << GetLastError() << "\n";
        return false;
    }

    // 7) Overwrite original code with JMP→cave (5 bytes)
    {
        int32_t offset = int32_t(
            memAllocatedAddress - (InstructionAddress + 5)
        );
        BYTE hook[5] = { 0xE9 };
        memcpy(&hook[1], &offset, sizeof(offset));

        // Debug
        std::cout << "[DBG] Instr:0x" << std::hex << InstructionAddress
            << " Cave:0x" << memAllocatedAddress
            << " Return:0x" << returnAddr << std::dec << "\n";
        std::cout << "[DBG] Hook: ";
        for (BYTE b : hook)
            std::cout << std::hex << std::setw(2)
            << std::setfill('0') << (int)b << " ";
        std::cout << std::dec << "\n";

        if (!WriteMem(driver, InstructionAddress, hook)) {
            std::cout << "[-] Failed to write hook: "
                << GetLastError() << "\n";
            return false;
        }
    }

    // 8) Start CacheLoop thread
    if (!g_cacheThreadRunning.load()) {
        g_cacheThreadRunning = true;
        std::thread(CacheLoop, driver, pid).detach();
    }

    std::cout << "[+] ViewAngle hook installed.\n";
    return true;
}

bool EnableLocalPlayerHook(HANDLE driver, DWORD pid) {
    using namespace LocalPlayer;

    constexpr SIZE_T  originalSize = sizeof(origBytes);      // bytes you overwrite, e.g. 7
    const uintptr_t  returnAddr = InstructionAddress + originalSize;

    // 1) Read & save the original bytes
    if (!ReadMem(driver, pid, InstructionAddress, origBytes)) {
        std::cout << "[-] Failed to read original bytes\n";
        return false;
    }

    // 2) Allocate your two caves once
    if (!mem_allocated) {
        // figure out cave length in bytes by stripping spaces and halving
        std::string tmp = shellcode;
        tmp.erase(std::remove_if(tmp.begin(), tmp.end(),
            [](unsigned char c) { return std::isspace(c); }),
            tmp.end());
        SIZE_T caveSize = tmp.size() / 2;

        memAllocatedAddress = AllocMem(driver, pid, InstructionAddress, caveSize);
        addrMemAllocatedAddress = AllocMem(driver, pid, InstructionAddress, caveSize);
        if (!memAllocatedAddress || !addrMemAllocatedAddress) {
            std::cout << "[-] Failed to allocate memory regions\n";
            return false;
        }
        mem_allocated = true;
    }

    // 3) Parse shellcode hex → caveBuf
    std::string hex = shellcode;
    hex.erase(std::remove_if(hex.begin(), hex.end(),
        [](unsigned char c) { return std::isspace(c); }),
        hex.end());
    if (hex.size() % 2 != 0) {
        std::cerr << "[-] shellcode string has odd length\n";
        return false;
    }
    std::vector<BYTE> caveBuf;
    caveBuf.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        BYTE b = static_cast<BYTE>(std::stoul(hex.substr(i, 2), nullptr, 16));
        caveBuf.push_back(b);
    }
    SIZE_T caveSize = caveBuf.size();

    // 4) Patch the absolute‐address slot at offset 6
    memcpy(&caveBuf[6],
        &addrMemAllocatedAddress,
        sizeof(addrMemAllocatedAddress));

    // 5) Patch the final JMP back to returnAddr (last 4 bytes)
    {
        uintptr_t caveEnd = memAllocatedAddress + caveSize;
        int32_t  relJmp = int32_t(returnAddr - caveEnd);
        memcpy(&caveBuf[caveSize - 4],
            &relJmp,
            sizeof(relJmp));
    }

    // 6) Write the patched cave
    if (!WriteMem(driver, memAllocatedAddress, caveBuf)) {
        std::cout << "[-] Failed to write shellcode cave: "
            << GetLastError() << "\n";
        return false;
    }

    // 7) Overwrite the original instructions with JMP→cave + NOPs
    {
        std::vector<BYTE> hook(originalSize, 0x90);
        hook[0] = 0xE9;  // JMP opcode
        int32_t toCave = int32_t(
            memAllocatedAddress - (InstructionAddress + 5)
        );
        memcpy(&hook[1], &toCave, sizeof(toCave));

        // Debug output
        std::cout << "[DBG] Instr:0x" << std::hex << InstructionAddress
            << " Cave:0x" << memAllocatedAddress
            << " Return:0x" << returnAddr << std::dec << "\n";
        std::cout << "[DBG] Hook: ";
        for (BYTE b : hook)
            std::cout << std::hex << std::setw(2)
            << std::setfill('0') << (int)b << " ";
        std::cout << std::dec << "\n";

        if (!WriteMem(driver, InstructionAddress, hook)) {
            std::cout << "[-] Failed to write hook bytes: "
                << GetLastError() << "\n";
            return false;
        }
    }

    std::cout << "[+] LocalPlayer hook installed.\n";
    return true;
}

bool EnableInfiniteAmmo(HANDLE driver, DWORD pid) {

    // 1) Read & save the original 8 bytes
    if (!ReadMem(driver, pid, InfAmmo::InstructionAddress, InfAmmo::origBytes)) {
        std::cout << "[-] Failed to read original bytes\n";
        return false;
    }

    // 2) Allocate one codecave page (at least 39 bytes)
    SIZE_T shellcodeSize = 39;
    uintptr_t returnAddr = InfAmmo::InstructionAddress + 8;

    if (!InfAmmo::mem_allocated) {
        InfAmmo::memAllocatedAddress = AllocMem(driver,
            pid,
            InfAmmo::InstructionAddress);
        if (!InfAmmo::memAllocatedAddress) {
            std::cout << "[-] Failed to allocate cave. Error: "
                << GetLastError() << "\n";
            return false;
        }
        InfAmmo::mem_allocated = true;
        std::cout << "[+] Cave @ 0x" << std::hex
            << InfAmmo::memAllocatedAddress << std::dec << "\n";
    }

    std::string hex = InfAmmo::shellcode;
    hex.erase(std::remove_if(hex.begin(), hex.end(),
        [](unsigned char c) { return std::isspace(c); }),
        hex.end());

    if (hex.size() != shellcodeSize * 2) {
        std::cerr << "[-] Unexpected shellcode length\n";
        return false;
    }

    std::vector<BYTE> caveBuf;
    caveBuf.reserve(shellcodeSize);
    for (size_t i = 0; i < hex.size(); i += 2) {
        BYTE b = static_cast<BYTE>(
            std::stoul(hex.substr(i, 2), nullptr, 16)
            );
        caveBuf.push_back(b);
    }

    // 4) Patch the JNE at offset 12 (0F 85 xx xx xx xx)
    {
        uintptr_t base = InfAmmo::memAllocatedAddress;
        uintptr_t jneInstr = base + 10;   // 10 bytes in: first opcode of 0F
        uintptr_t afterJne = jneInstr + 6; // size of (0F 85 + rel32)
        uintptr_t labelDest = base + 26;    // "code_dexxa" label at offset 26
        int32_t  relJne = int32_t(labelDest - afterJne);
        memcpy(&caveBuf[12], &relJne, sizeof(relJne));
        std::cout << "[+] Patched JNE rel32 = 0x"
            << std::hex << relJne << std::dec << "\n";
    }

    // 5) Patch the final JMP back to returnAddr at offset 35
    {
        uintptr_t base = InfAmmo::memAllocatedAddress;
        uintptr_t jmpInstr = base + 34;   // 34 bytes in: E9
        uintptr_t afterJmp = jmpInstr + 5; // size of (E9 + rel32)
        int32_t  relJmp = int32_t(returnAddr - afterJmp);
        memcpy(&caveBuf[35], &relJmp, sizeof(relJmp));
        std::cout << "[+] Patched JMP rel32 = 0x"
            << std::hex << relJmp << std::dec << "\n";
    }

    // 6) Write the patched shellcode into the cave
    if (!WriteMem(driver, InfAmmo::memAllocatedAddress, caveBuf)) {
        std::cout << "[-] WriteMem(cave) failed: "
            << GetLastError() << "\n";
        return false;
    }

    // 7) Overwrite the original code with JMP→cave + NOPs
    {
        int32_t offsetToCave = int32_t(
            InfAmmo::memAllocatedAddress - (InfAmmo::InstructionAddress + 5)
        );
        BYTE hookBytes[8] = { 0xE9 };      // E9 + rel32
        memcpy(&hookBytes[1], &offsetToCave, sizeof(offsetToCave));
        // fill remaining 3 bytes with NOP
        hookBytes[5] = hookBytes[6] = hookBytes[7] = 0x90;

        if (!WriteMem(driver, InfAmmo::InstructionAddress, hookBytes)) {
            std::cout << "[-] WriteMem(hook) failed: "
                << GetLastError() << "\n";
            return false;
        }
    }

    std::cout << "[+] Infinite‐ammo hook installed.\n";
    return true;
}

bool EnableActivityLoaderHook(HANDLE driver, DWORD pid) {
    using namespace ActivityLoader;

    constexpr SIZE_T originalSize = sizeof(origBytes);    // 5
    const uintptr_t returnAddr = InstructionAddress + 5;

    // 1) Read and save the original bytes
    if (!ReadMem(driver, pid, InstructionAddress, origBytes)) {
        std::cout << "[-] Failed to read original bytes for activity loader\n";
        return false;
    }

    // 2) Allocate cave & storage once
    if (!mem_allocated) {
        std::string tmp = shellcode;
        tmp.erase(std::remove_if(tmp.begin(), tmp.end(),
            [](unsigned char c) { return std::isspace(c); }),
            tmp.end());
        SIZE_T caveSize = tmp.size() / 2;

        memAllocatedAddress = AllocMem(driver, pid, InstructionAddress, caveSize);
        addrMemAllocatedAddress = AllocMem(driver, pid, InstructionAddress, 8); // 8 bytes for pointer storage
        if (!memAllocatedAddress || !addrMemAllocatedAddress) {
            std::cout << "[-] Failed to allocate memory regions for activity loader\n";
            return false;
        }
        mem_allocated = true;
    }

    // 3) Convert shellcode hex string to byte array
    std::string hex = shellcode;
    hex.erase(std::remove_if(hex.begin(), hex.end(),
        [](unsigned char c) { return std::isspace(c); }),
        hex.end());

    if (hex.size() % 2 != 0) {
        std::cerr << "[-] Shellcode string has odd length\n";
        return false;
    }

    std::vector<BYTE> caveBuf;
    caveBuf.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        caveBuf.push_back(static_cast<BYTE>(
            std::stoul(hex.substr(i, 2), nullptr, 16)
            ));
    }

    SIZE_T caveSize = caveBuf.size();

    // 4) Patch the address in the `mov [rip+offset], rdx` (starts at offset 3)
    {
        int32_t relAddr = static_cast<int32_t>(
            addrMemAllocatedAddress - (memAllocatedAddress + 7)
            );
        memcpy(&caveBuf[3], &relAddr, sizeof(relAddr));
    }

    // 5) Patch the return-jump (last 4 bytes)
    {
        uintptr_t caveEnd = memAllocatedAddress + caveSize;
        int32_t relJmp = int32_t(returnAddr - caveEnd);
        memcpy(&caveBuf[caveSize - 4], &relJmp, sizeof(relJmp));
    }

    // 6) Write the patched cave to target process
    if (!WriteMem(driver, memAllocatedAddress, caveBuf)) {
        std::cout << "[-] Failed to write shellcode cave: "
            << GetLastError() << "\n";
        return false;
    }

    // 7) Write jump to cave (5 bytes)
    {
        int32_t offset = int32_t(memAllocatedAddress - (InstructionAddress + 5));
        BYTE hook[5] = { 0xE9 };
        memcpy(&hook[1], &offset, sizeof(offset));

        std::cout << "[DBG] ActivityLoader Hook: ";
        for (BYTE b : hook)
            std::cout << std::hex << std::setw(2)
            << std::setfill('0') << (int)b << " ";
        std::cout << std::dec << "\n";

        if (!WriteMem(driver, InstructionAddress, hook)) {
            std::cout << "[-] Failed to write activity loader hook\n";
            return false;
        }
    }

    Enabled = true;
    std::cout << "[+] ActivityLoader hook installed.\n";
    return true;
}

// Define this globally or in a suitable place
bool activityCheckbox = false;
int activityValue = 0;
static bool userEdited = false;

void RenderActivityLoaderUI(HANDLE driver, DWORD pid) {
    using namespace ActivityLoader;

    static bool activityCheckbox = false;
    static int userInputValue = 0;
    static bool userEdited = false;

    if (ImGui::Toggle("Activity Loader", &activityCheckbox)) {
        if (activityCheckbox) {
            if (!EnableActivityLoaderHook(driver, pid)) {
                activityCheckbox = false;
            }
        }
        else {
            WriteMem(driver, InstructionAddress, origBytes);
            Enabled = false;
            userEdited = false;
        }
    }

    if (activityCheckbox && Enabled) {
        WORD rawValue = 0;
        uintptr_t activityAddr = 0;

        if (ReadMem(driver, pid, addrMemAllocatedAddress, activityAddr) && activityAddr != 0) {
            ReadMem(driver, pid, activityAddr + 0x2, rawValue);

            if (!userEdited) {
                userInputValue = static_cast<int>(rawValue);
            }
        }

        bool isInvalid = (rawValue == 0 || rawValue == 0xFFFF);

        ImGui::BeginDisabled(isInvalid);

        ImGui::SetNextItemWidth(150);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
        if (ImGui::InputScalar("##ActivityValue", ImGuiDataType_S32, &userInputValue, nullptr, nullptr, nullptr, ImGuiInputTextFlags_CharsDecimal)) {
            userEdited = true;
        }
        ImGui::PopStyleColor();

        ImGui::SameLine();
        if (ImGui::Button("Set")) {
            if (activityAddr != 0) {
                WORD newVal = static_cast<WORD>(userInputValue);
                WriteMem(driver, activityAddr + 0x2, newVal);
                userEdited = false;
            }
        }

        ImGui::EndDisabled();

        if (isInvalid) {
            ImGui::TextDisabled("Activity: N/A");
        }
    }
}

constexpr uintptr_t START_ADDR = 0x10400000A;
constexpr uintptr_t END_ADDR = 0x7fffffffffff;
void ImmuneBossesThread(HANDLE driver, DWORD pid) {
    ImmuneBosses::ThreadRunning = true;

    LPCSTR AOBStr = "?? ?? ?? ?? 80 3F 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 80 3F 00 00 80 3F ?? ?? ?? ?? 6D 97 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

    while (ImmuneBosses::Enabled && ImmuneBosses::Address == 0) {

        uintptr_t result = 0;

        //result = HeapAOBScan(driver, (HANDLE)pid, AOB, sizeof(AOB), AOBMask, 0x10400000A, 0x105FFFFFA);
        if (result == 0) {
            result = AobScanProcessRange(driver, pid, AOBStr, START_ADDR, END_ADDR);
        }

        if (result == 0) {
            std::cout << "[-] Immune Bosses AOB Scan failed";
            ImmuneBosses::ThreadRunning = false;
            ImmuneBosses::Enabled.store(false);
            return;
        }

        if (result != 0) {
            result -= 0x2;

            float zero = 0.0f;
            SIZE_T written = 0;
            if (WriteMem(driver, result, zero)) {
                ImmuneBosses::Address = result;
                std::cout << "[+] ImmuneBosses AOB match found and patched at: 0x" << std::hex << result << "\n";
                break;
            }
            else {
                std::cerr << "[-] Failed to write patch\n";
                ImmuneBosses::Enabled = false;
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // reduce CPU usage
    }

    ImmuneBosses::ThreadRunning = false;
}

void DisableImmuneBosses(HANDLE driver) {
    if (ImmuneBosses::Address == 0)
        return;

    float one = 1.0f;
    SIZE_T written = 0;
    if (!WriteMem(driver, ImmuneBosses::Address, one)) {
        std::cerr << "[-] Failed to restore 1.0f to ImmuneBosses address\n";
    }

    ImmuneBosses::Address = 0;
}


void RenderImmuneBossesCheckbox(HANDLE driver, DWORD pid) {
    static bool wasEnabled = false;

    // Copy the atomic state for the checkbox (needed because ImGui::Checkbox requires a bool*)
    bool checkboxState = ImmuneBosses::Enabled.load();

    if (ImGui::Checkbox("Immune Bosses", &checkboxState)) {
        ImmuneBosses::Enabled.store(checkboxState);

        // Toggled ON
        if (checkboxState && !wasEnabled && !ImmuneBosses::ThreadRunning.load()) {
            std::thread(ImmuneBossesThread, driver, pid).detach();
        }

        // Toggled OFF
        else if (!checkboxState && wasEnabled && ImmuneBosses::Address != 0) {
            float one = 1.0f;
            if (WriteMem(driver, ImmuneBosses::Address, one)) {
                std::cout << "[+] Immune Bosses restored to 1.0f\n";
            }
            else {
                std::cerr << "[-] Failed to restore Immune Bosses: " << GetLastError() << "\n";
            }

            ImmuneBosses::Address = 0;
        }
    }

    if (ImmuneBosses::ThreadRunning && ImmuneBosses::Address == 0) {
        ImGui::TextDisabled("Scanning memory...");
    }

    wasEnabled = ImmuneBosses::Enabled.load();
}



// player grabber globals
std::atomic<bool> g_FindPlayerEnabled = false;
std::atomic<bool> g_StopFindThread = false;
std::thread g_FindPlayerThread;
void AutoFindPlayerLoop(HANDLE driver, DWORD pid, uintptr_t destinyBase, std::atomic<uintptr_t>& outPlayerAddr) {
    const uintptr_t localOffset = 0x1C0;

    while (!g_StopFindThread)
    {
        if (!g_FindPlayerEnabled) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        uintptr_t localPtr = 0;
        if (!ReadMem(driver, pid, LocalPlayer::addrMemAllocatedAddress, localPtr) || !localPtr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        LocalPlayer::Vec3 entityPos{};
        LocalPlayer::Vec3 localPos{};

        ReadMem(driver, pid, destinyBase, entityPos);
        ReadMem(driver, pid, (localPtr + localOffset), localPos);

        bool xMatch = (localPos.x >= entityPos.x - 1.0f && localPos.x <= entityPos.x + 1.0f);
        bool yMatch = (localPos.y >= entityPos.y - 1.0f && localPos.y <= entityPos.y + 1.0f);
        bool zMatch = (localPos.z >= entityPos.z - 3.0f && localPos.z <= entityPos.z + 3.0f);

        if (xMatch && yMatch && zMatch) {
            outPlayerAddr.store(localPtr, std::memory_order_relaxed);
            //std::cout << "[+] Player matched and written: 0x" << std::hex << localPtr << "\n";
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::cout << "[+] AutoFindPlayerLoop exited cleanly\n";
}




// Global variables
std::atomic<bool> FlyEnabled = false;
std::thread FlyThread;
std::atomic<bool> StopFlyThread = false;
float flySpeed = 35.0f;
float boostSpeed = 2.5f;

void FlyLoop(HANDLE driver, DWORD pid, uintptr_t destinyBase) {
    const uintptr_t posOffset = 0x1C0;
    const uintptr_t velOffset = 0x230;
    const uintptr_t zOffset = 0x1C8;

    std::cout << "[+] FlyLoop started with destinyBase: " << std::hex << destinyBase << std::dec << "\n";

    while (!StopFlyThread) {
        if (!FlyEnabled) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        uintptr_t playerBase = LocalPlayer::realPlayer.load();
        if (!playerBase) {
            std::cout << "[!] Player base is null\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // Read position
        float pos[3] = {};
        if (!ReadMem(driver, pid, (playerBase + posOffset), pos)) {
            std::cout << "[!] Failed to read player position\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // Read rotation from destinyBase
        float rot[3] = {};
        if (!ReadMem(driver, pid, (destinyBase + 0x10), rot)) {
            std::cout << "[!] Failed to read player rotation\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        float mag = std::sqrt(rot[0] * rot[0] + rot[1] * rot[1]);
        if (mag == 0.0f) mag = 1.0f;

        // Handle inputs
        float inputForward = 0, inputRight = 0, inputVertical = 0;

        if (GetAsyncKeyState(VK_W) & 0x8000) inputForward += 1;
        if (GetAsyncKeyState(VK_S) & 0x8000) inputForward -= 1;
        if (GetAsyncKeyState(VK_D) & 0x8000) inputRight += 1;
        if (GetAsyncKeyState(VK_A) & 0x8000) inputRight -= 1;
        if (GetAsyncKeyState(VK_SPACE) & 0x8000) inputVertical += 1;
        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) inputVertical -= 1;

        if (GetAsyncKeyState(VK_ADD) & 0x8000) {
            flySpeed += 5.0f;
            std::cout << "[+] flySpeed increased to " << flySpeed << "\n";
        }

        if (GetAsyncKeyState(VK_SUBTRACT) & 0x8000) {
            flySpeed -= 5.0f;
            std::cout << "[+] flySpeed decreased to " << flySpeed << "\n";
        }

        bool isMoving = inputForward != 0 || inputRight != 0 || inputVertical != 0;
        bool isBoostMode = GetAsyncKeyState(LocalPlayer::FlyBoostHotkey) & 0x8000;


        if (isBoostMode) {
            // Boost mode
            float boostX = pos[0] + rot[0] * boostSpeed;
            float boostY = pos[1] + rot[1] * boostSpeed;
            float boostZ = pos[2] + rot[2] * boostSpeed;

            float fakeVel[3] = { 1.0f, 1.0f, 1.0f };
            WriteMem(driver, (playerBase + velOffset), fakeVel[0]);
            WriteMem(driver, (playerBase + velOffset + 4), fakeVel[1]);
            WriteMem(driver, (playerBase + velOffset + 8), fakeVel[2]);

            WriteMem(driver, (playerBase + posOffset), boostX);
            WriteMem(driver, (playerBase + posOffset + 4), boostY);
            WriteMem(driver, (playerBase + posOffset + 8), boostZ);
        }
        else if (isMoving) {
            // Normal flying mode - apply calculated velocity when keys are pressed
            float velocityX = ((rot[0] / mag) * inputForward + (rot[1] / mag) * inputRight) * flySpeed;
            float velocityY = ((rot[1] / mag) * inputForward + (-rot[0] / mag) * inputRight) * flySpeed;
            float velocityZ = inputVertical * (flySpeed / 2.0f);

            WriteMem(driver, (playerBase + velOffset), velocityX);
            WriteMem(driver, (playerBase + velOffset + 4), velocityY);
            WriteMem(driver, (playerBase + velOffset + 8), velocityZ);
        }
        else {
            // NEW: No keys pressed - lock velocity to zero to stay in place
            float zeroVelocity = 0.0f;
            WriteMem(driver, (playerBase + velOffset), zeroVelocity);
            WriteMem(driver, (playerBase + velOffset + 4), zeroVelocity);
            WriteMem(driver, (playerBase + velOffset + 8), zeroVelocity);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    std::cout << "[+] FlyLoop exited\n";
}

void RenderMag999Button(HANDLE driver, DWORD pid, ImFont* iconFont) {
    static enum class Status { None, Success, FailureInject } showStatus = Status::None;
    static float statusTime = 0.0f;

    static bool silentAimActive = false;
    static float silentAimStartTime = 0.0f;

    float now = ImGui::GetTime();

    // Show button
    if (ImGui::Button("Silent Aim")) {
        bool injected = InjectCodecave(driver, pid, Mag999::InstructionAddress, Mag999::shellcode, 8, Mag999::memAllocatedAddress);
        if (injected) {
            silentAimStartTime = now;
            silentAimActive = true;
        }
        else {
            showStatus = Status::FailureInject;
            statusTime = now;
        }
    }

    // Restore original bytes after a short duration
    if (silentAimActive && (now - silentAimStartTime) >= 0.25f) {
        WriteMem(driver, Mag999::InstructionAddress, Mag999::origBytes);
        silentAimActive = false;
        showStatus = Status::Success;
        statusTime = now;
    }

    // Status message (Success / Injection Failure)
    ImGui::SameLine();
    if (showStatus != Status::None) {
        if ((now - statusTime) <= 2.0f) {
            if (showStatus == Status::Success) {
                ImGui::TextColored(ImVec4(0.1f, 1.0f, 0.2f, 1.0f), "[+] Silent Aim enabled!");
            }
            else if (showStatus == Status::FailureInject) {
                ImGui::TextColored(ImVec4(1.0f, 0.1f, 0.1f, 1.0f), "[!] Failed to enable Silent Aim.");
            }
            ImGui::SameLine();
        }
        else {
            showStatus = Status::None;
        }
    }

    // Tooltip
    ImGui::TextDisabled("*Hold gun in your hand then press button");
}

#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>

// Scan flag bitmask definitions
#define SCAN_FLAG_WRITABLE        0x01
#define SCAN_FLAG_EXECUTABLE      0x02
#define SCAN_FLAG_COPYONWRITE     0x04
#define SCAN_FLAG_COMMITTED_ONLY  0x08
#define SCAN_FLAG_FASTSCAN_4      0x10
#define SCAN_FLAG_FASTSCAN_8      0x20

namespace DriverComm {

    namespace codes {
        // IOCTL codes.
        constexpr ULONG attach{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };
        constexpr ULONG read{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };
        constexpr ULONG write{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };
        constexpr ULONG get_base{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };
        // New IOCTL code for AOB scan.
        constexpr ULONG aob_scan{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6A0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };


        constexpr ULONG allocate_memory{ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6A2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) };

        constexpr ULONG heap_aob_scan = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS);
        constexpr ULONG process_aob_scan = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS);



    } // namespace codes

    // Shared structure between user-mode and kernel-mode.
    struct Request {
        HANDLE process_id;            // Target process ID
        PVOID target;                 // Target address for read/write
        PVOID buffer;                 // Pointer to buffer in usermode
        SIZE_T size;                  // Size of read/write buffer
        SIZE_T return_size;          // Number of bytes read/written

        WCHAR moduleName[64];        // Name of the module to look for
        PVOID base_address;          // Optional: base address result

        // AOB scan
        CHAR aob_pattern[256];       // Byte pattern (e.g., "48 8B ?? ??")
        CHAR aob_mask[256];          // Mask (e.g., "xx??")
        uintptr_t module_base;       // Module base for AOB scan
        SIZE_T module_size;          // Module size for AOB scan
        UCHAR saved_bytes[256];

        PVOID alloc_hint;            // hint address for memory allocation

        // NEW: Range restriction for heap scan
        PVOID start_address;         // Start address of scan range
        PVOID end_address;           // End address of scan range
    };

    //DWORD get_process_id(const wchar_t* process_name);

    bool attach_to_process(HANDLE driver_handle, const DWORD pid);

    template <class T>
    T read_memory(HANDLE driver_handle, const std::uintptr_t addr);

    template <class T>
    bool write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value);

    uintptr_t GetModuleBase(const std::wstring& moduleName);

    PBYTE AOBScan(PBYTE baseAddress, SIZE_T regionSize, const BYTE* pattern, const char* mask);

    bool allocate_memory(HANDLE driver_handle, DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint);

    std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name);
}

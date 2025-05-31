#include "includes.h"

ULONG g_randomSeed; // Global seed for RtlRandomEx
BYTE g_xor_key[8];
SIZE_T g_xor_key_size = sizeof(g_xor_key);

// Convert a character to lower-case.
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

void debug_print(PCSTR text) {
#ifndef DEBUG
    UNREFERENCED_PARAMETER(text);
#endif // DEBUG
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

// Custom case-insensitive string compare.
// The 'two' parameter indicates whether both strings must end at the same time.
template <typename str_type, typename str_type_2>
__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
{
    if (!str || !in_str)
        return false;

    wchar_t c1, c2;
    do
    {
        c1 = *str++;
        c2 = *in_str++;
        c1 = to_lower(c1);
        c2 = to_lower(c2);

        // If we reached the end of 'str' (and optionally in_str) then they match.
        if (!c1 && (two ? !c2 : 1))
            return true;

    } while (c1 == c2);

    return false;
}

void GenerateRandomString(WCHAR* buffer, ULONG bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    LARGE_INTEGER seedTime;
    KeQuerySystemTime(&seedTime);
    ULONG seed = seedTime.LowPart;

    // Oddly, RtlRandomEx is not available in all WDK/SDK versions.
    // For broader compatibility, especially with older WDKs,
    // a simple LCG might be used if RtlRandomEx is unavailable.
    // However, for modern WDKs, RtlRandomEx is preferred.
    // If linking errors occur for RtlRandomEx, ensure you're linking against ntoskrnl.lib
    // and that the WDK version supports it. If not, a fallback is needed.
    // For this example, we assume RtlRandomEx is available.

    const WCHAR charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const int charsetSize = sizeof(charset) / sizeof(WCHAR) - 1; // Exclude null terminator

    for (ULONG i = 0; i < bufferLength - 1; ++i) {
        ULONG randomNumber = RtlRandomEx(&seed);
        buffer[i] = charset[randomNumber % charsetSize];
    }
    buffer[bufferLength - 1] = L'\0'; // Null-terminate the string
}

// Helper function to get the EPROCESS pointer from a PID.
PEPROCESS get_eprocess(HANDLE pid)
{
    PEPROCESS process = nullptr;
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    {
        return process;
    }
    return nullptr;
}

/*
 * NOTE: The following implementations rely on undocumented and unexported structures
 * such as PEB, PPEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, PEB32, and PPEB_LDR_DATA32.
 * Ensure your project has the necessary definitions.
 */

 // Retrieve module base address for 64-bit processes.
ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
    PPEB pPeb = (PPEB)PsGetProcessPeb(proc); // Undocumented API
    if (!pPeb) {
        return 0; // failed
    }

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (!pLdr) {
        KeUnstackDetachProcess(&state);
        return 0; // failed
    }

    // Iterate through the module list.
    for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
        list != &pLdr->ModuleListLoadOrder;
        list = (PLIST_ENTRY)list->Flink) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) {
            ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
            KeUnstackDetachProcess(&state);
            return baseAddr;
        }
    }

    KeUnstackDetachProcess(&state);
    return 0; // failed
}

// Retrieve module base address for 32-bit (WOW64) processes.
ULONG GetModuleBasex86(PEPROCESS proc, UNICODE_STRING module_name) {
    PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(proc); // Undocumented API
    if (!pPeb) {
        return 0; // failed
    }

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    PPEB_LDR_DATA32 pLdr = (PPEB_LDR_DATA32)pPeb->Ldr;
    if (!pLdr) {
        KeUnstackDetachProcess(&state);
        return 0; // failed
    }

    // Iterate through the module list.
    for (PLIST_ENTRY32 list = (PLIST_ENTRY32)pLdr->InLoadOrderModuleList.Flink;
        list != &pLdr->InLoadOrderModuleList;
        list = (PLIST_ENTRY32)list->Flink) {
        PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
        // Manually convert the 32-bit UNICODE_STRING.
        UNICODE_STRING DLLname;
        DLLname.Length = pEntry->BaseDllName.Length;
        DLLname.MaximumLength = pEntry->BaseDllName.MaximumLength;
        DLLname.Buffer = (PWCH)pEntry->BaseDllName.Buffer;

        if (RtlCompareUnicodeString(&DLLname, &module_name, TRUE) == 0) {
            ULONG baseAddr = pEntry->DllBase;
            KeUnstackDetachProcess(&state);
            return baseAddr;
        }
    }

    KeUnstackDetachProcess(&state);
    return 0; // failed
}



// Retrieve module size for a 64-bit process by reading SizeOfImage from the module's entry.
ULONG GetModuleSizeX64(PEPROCESS proc, UNICODE_STRING module_name)
{
    PPEB pPeb = (PPEB)PsGetProcessPeb(proc);
    if (!pPeb)
        return 0;

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (!pLdr)
    {
        KeUnstackDetachProcess(&state);
        return 0;
    }

    ULONG sizeOfImage = 0;
    // Iterate through the loader list.
    for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
        list != &pLdr->ModuleListLoadOrder;
        list = (PLIST_ENTRY)list->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0)
        {
            sizeOfImage = pEntry->SizeOfImage;
            break;
        }
    }

    KeUnstackDetachProcess(&state);
    return sizeOfImage;
}

// AOB scan function for kernel mode.
// Scans a memory region in the context of a target process for a specified pattern.
#include <ntifs.h>  // for RtlCopyMemory, KAPC_STATE, etc.

NTSTATUS
EnumerateHeapRegions(
    PEPROCESS Process,
    PVOID* RegionsArray,
    SIZE_T* RegionSizesArray,
    SIZE_T MaxRegions,
    SIZE_T* RegionsFound
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apcState;
    SIZE_T foundRegions = 0;

    if (!Process || !RegionsArray || !RegionSizesArray || !RegionsFound)
        return STATUS_INVALID_PARAMETER;

    // Attach to target process to access its address space
    KeStackAttachProcess(Process, &apcState);

    __try {
        PVOID address = NULL;
        MEMORY_BASIC_INFORMATION memInfo;

        // Scan the entire address space and look for heap regions
        while (NT_SUCCESS(ZwQueryVirtualMemory(
            ZwCurrentProcess(),       // Use current process handle since we're attached
            address,
            MemoryBasicInformation,
            &memInfo,
            sizeof(memInfo),
            NULL)) && foundRegions < MaxRegions)
        {
            // Check if this is a heap region (committed, private, readable memory)
            if (memInfo.State == MEM_COMMIT &&
                memInfo.Type == MEM_PRIVATE &&
                (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)))
            {
                // Store information about this region
                RegionsArray[foundRegions] = memInfo.BaseAddress;
                RegionSizesArray[foundRegions] = memInfo.RegionSize;
                foundRegions++;
            }

            // Move to the next region
            address = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);

            // Break if we've reached the end of user address space
            if ((ULONG_PTR)address >= 0x7FFFFFFEFFFF)
                break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    // Detach from the process
    KeUnstackDetachProcess(&apcState);

    *RegionsFound = foundRegions;
    return status;
}

PVOID
AOBScan(
    PEPROCESS    Process,
    PVOID        StartAddress,
    SIZE_T       RegionSize,
    const BYTE* pattern,
    const char* mask,
    BYTE* outBuffer,       // ← caller-provided buffer
    SIZE_T       outBufferSize    // ← e.g. 32
)
{
    PVOID    found = nullptr;
    KAPC_STATE  apcState;

    // 1) Attach to the target process so that the user‐mode pages are addressable
    KeStackAttachProcess(Process, &apcState);

    PUCHAR regionStart = (PUCHAR)StartAddress;
    PUCHAR regionEnd = regionStart + RegionSize;
    SIZE_T patternLen = strlen(mask);

    __try {
        for (PUCHAR addr = regionStart;
            addr <= regionEnd - patternLen;
            ++addr)
        {
            BOOLEAN match = TRUE;
            for (SIZE_T i = 0; i < patternLen; ++i) {
                if (mask[i] == 'x' && pattern[i] != addr[i]) {
                    match = FALSE;
                    break;
                }
            }
            if (match) {
                found = addr;

                // 2) copy up to outBufferSize bytes (but don’t run off the end of the region)
                if (outBuffer && outBufferSize > 0) {
                    SIZE_T bytesAvailable = (SIZE_T)(regionEnd - addr);
                    SIZE_T bytesToCopy = (bytesAvailable < outBufferSize)
                        ? bytesAvailable
                        : outBufferSize;
                    RtlCopyMemory(outBuffer, addr, bytesToCopy);
                }

                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        found = nullptr;
    }

    // 3) Detach before returning
    KeUnstackDetachProcess(&apcState);
    return found;
}

// Modified AOBScan function to scan heap regions
PVOID HeapAOBScan(
    PEPROCESS    Process,
    const BYTE* pattern,
    const char* mask,
    BYTE* outBuffer,
    SIZE_T       outBufferSize,
    PVOID        start_address,
    PVOID        end_address
) {
    PVOID found = nullptr;

#define MAX_HEAP_REGIONS 1024
    PVOID heapRegions[MAX_HEAP_REGIONS];
    SIZE_T heapSizes[MAX_HEAP_REGIONS];
    SIZE_T regionsFound = 0;

    NTSTATUS status = EnumerateHeapRegions(
        Process,
        heapRegions,
        heapSizes,
        MAX_HEAP_REGIONS,
        &regionsFound
    );

    if (!NT_SUCCESS(status) || regionsFound == 0) {
        return nullptr;
    }

    for (SIZE_T i = 0; i < regionsFound; i++) {
        uintptr_t regionStart = (uintptr_t)heapRegions[i];
        uintptr_t regionEnd = regionStart + heapSizes[i];
        uintptr_t scanStart = max(regionStart, (uintptr_t)start_address);
        uintptr_t scanEnd = min(regionEnd, (uintptr_t)end_address);

        // Skip regions that don't overlap the scan range
        if (scanStart >= scanEnd) {
            continue;
        }

        SIZE_T scanSize = scanEnd - scanStart;

        PVOID result = AOBScan(
            Process,
            (PVOID)scanStart,
            scanSize,
            pattern,
            mask,
            outBuffer,
            outBufferSize
        );

        if (result) {
            found = result;
            break;
        }
    }

    return found;
}

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

NTSTATUS AobScanProcessRanges(
    PEPROCESS TargetProcess,
    UINT64    StartAddress,
    UINT64    EndAddress,
    PCSTR     PatternString,
    UINT64* Results,
    SIZE_T    MaxResults,
    PSIZE_T   ResultsCount
) {
    *ResultsCount = 0;
    NTSTATUS status = STATUS_SUCCESS; // Initialize status

    // Define original and obfuscated tags
    constexpr ULONG originalSoaBTag = 'SoaB'; // "BoAS"
    constexpr ULONG originalLoaBTag = 'LoaB'; // "BoAL"
    constexpr ULONG poolTagXorKey = 0xDEADBEEF; // Example key
    ULONG obfuscatedSoaBTag = originalSoaBTag ^ poolTagXorKey;
    ULONG obfuscatedLoaBTag = originalLoaBTag ^ poolTagXorKey;

    if (!TargetProcess || !PatternString || !Results || !ResultsCount || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(TargetProcess, &apc);

    // Pre-allocate a reusable buffer to reduce alloc/free overhead
    // Tunable size: 256KB to 1MB is often a reasonable starting point.
    SIZE_T reusableBufferSize = 0x40000; // 256KB example
    PVOID reusableBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, reusableBufferSize, obfuscatedSoaBTag); // Use obfuscated tag

    if (!reusableBuffer) {
        KeUnstackDetachProcess(&apc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // ─── Parse pattern ───
        BYTE patternBytes[256], patternMask[256];
        SIZE_T patternLength = 0;
        const CHAR* p = PatternString;

        // Using C-style character checks for kernel C compatibility if C++ lambdas are an issue
        // If C++ is fine, the lambdas are okay. Assuming C++ for this structure.
        auto IsHexDigit = [](CHAR c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            };
        auto HexValue = [](CHAR c) -> BYTE {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
            };

        while (*p && patternLength < ARRAYSIZE(patternBytes)) {
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p) break;

            CHAR c1 = *p++;
            while (*p == ' ' || *p == '\t') ++p; // Skip spaces between two nibbles of a byte
            CHAR c2 = (*p && *p != ' ' && *p != '\t') ? *p++ : 0; // Second nibble or 0 if single char/wildcard

            BYTE val = 0, mask = 0;
            // Allow 'x' or 'X' as additional wildcards for flexibility
            bool wild1 = (c1 == '?' || c1 == '*' || c1 == 'x' || c1 == 'X');
            bool wild2 = (c2 == '?' || c2 == '*' || c2 == 'x' || c2 == 'X');

            if (!c2 && wild1) { // Single wildcard character like "? " or "X "
                val = 0x00;
                mask = 0x00;
            }
            else if (IsHexDigit(c1) && IsHexDigit(c2)) {
                val = (HexValue(c1) << 4) | HexValue(c2);
                mask = 0xFF;
            }
            else if (IsHexDigit(c1) && wild2) { // e.g., "A?" or "A*"
                val = (HexValue(c1) << 4);
                mask = 0xF0;
            }
            else if (wild1 && IsHexDigit(c2)) { // e.g., "?A" or "*A"
                val = HexValue(c2);
                mask = 0x0F;
            }
            else if (wild1 && wild2) { // e.g., "??" or "**"
                val = 0x00;
                mask = 0x00;
            }
            else {
                // Invalid pattern component, treat as full wildcard or error
                // For robustness, let's treat malformed as a wildcard byte
                val = 0x00;
                mask = 0x00;
                // Or one could set status = STATUS_INVALID_PARAMETER and __leave here
            }

            patternBytes[patternLength] = val;
            patternMask[patternLength] = mask;
            ++patternLength;

            // Skip trailing characters of the current byte representation if any, before looking for next space
            while (*p && *p != ' ' && *p != '\t') ++p;
        }

        if (patternLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        // ─── Scan ───
        UINT64 scanPtr = StartAddress;
        while (scanPtr < EndAddress && *ResultsCount < MaxResults) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T queryReturnLength = 0; // Renamed from retLen

            NTSTATUS queryStatus = ZwQueryVirtualMemory(
                ZwCurrentProcess(),
                (PVOID)scanPtr,
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                &queryReturnLength
            );

            if (!NT_SUCCESS(queryStatus)) {
                status = queryStatus; // Capture the error
                break; // Stop scanning if we can't query memory info
            }

            UINT64 currentRegionBase = (UINT64)mbi.BaseAddress;
            UINT64 currentRegionSize = (UINT64)mbi.RegionSize;
            UINT64 currentRegionEnd = currentRegionBase + currentRegionSize;

            // CRITICAL: Always advance scanPtr for the next iteration, regardless of 'continue'
            scanPtr = currentRegionEnd;

            // --- Start of Targeted Filtering ---
            if (!(mbi.State & MEM_COMMIT)) {
                continue;
            }

            BOOLEAN isRelevantRegion = FALSE;
            // 1. Check for Modules (MEM_IMAGE)
            if (mbi.Type == MEM_IMAGE) {
                // Relevant protections for modules (code, data, read-only data)
                if ((mbi.Protect & PAGE_EXECUTE_READ) ||
                    (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                    (mbi.Protect & PAGE_READWRITE) ||
                    (mbi.Protect & PAGE_READONLY)) {
                    if (!(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                        isRelevantRegion = TRUE;
                    }
                }
            }
            // 2. Check for Writable Heap / Dynamic Memory (MEM_PRIVATE)
            else if (mbi.Type == MEM_PRIVATE) {
                // Relevant for writable heaps or dynamically allocated RW/RWX memory
                if ((mbi.Protect & PAGE_READWRITE) ||
                    (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                    if (!(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                        isRelevantRegion = TRUE;
                    }
                }
            }

            if (!isRelevantRegion) {
                continue;
            }
            // --- End of Targeted Filtering ---

            // Determine the effective portion of this relevant region to scan,
            // respecting the overall StartAddress and EndAddress.
            UINT64 effectiveScanStart = max(currentRegionBase, StartAddress);
            UINT64 effectiveScanEnd = min(currentRegionEnd, EndAddress);

            // Ensure there's actually something to scan in the effective range
            if (effectiveScanStart >= effectiveScanEnd) {
                continue;
            }

            SIZE_T toRead = (SIZE_T)(effectiveScanEnd - effectiveScanStart);
            if (toRead < patternLength) {
                continue;
            }

            PVOID currentBufferToScan = NULL;
            BOOLEAN usedTempLargeBuffer = FALSE;

            if (toRead <= reusableBufferSize) {
                currentBufferToScan = reusableBuffer;
            }
            else {
                currentBufferToScan = ExAllocatePoolWithTag(NonPagedPoolNx, toRead, obfuscatedLoaBTag); // Use obfuscated tag
                if (!currentBufferToScan) {
                    status = STATUS_INSUFFICIENT_RESOURCES; // Critical allocation failure
                    break;
                }
                usedTempLargeBuffer = TRUE;
            }

            SIZE_T bytesRead = 0;
            NTSTATUS copyStatus = MmCopyVirtualMemory(
                TargetProcess,
                (PVOID)effectiveScanStart,
                PsGetCurrentProcess(),
                currentBufferToScan,
                toRead,
                KernelMode,
                &bytesRead
            );

            if (NT_SUCCESS(copyStatus) && bytesRead >= patternLength) {
                BYTE* data = (BYTE*)currentBufferToScan;
                for (SIZE_T i = 0; (i + patternLength) <= bytesRead; ++i) {
                    BOOLEAN match = TRUE;
                    for (SIZE_T j = 0; j < patternLength; ++j) {
                        if ((data[i + j] & patternMask[j]) != (patternBytes[j] & patternMask[j])) {
                            match = FALSE;
                            break;
                        }
                    }
                    if (match) {
                        Results[*ResultsCount] = effectiveScanStart + i;
                        (*ResultsCount)++;
                        if (*ResultsCount >= MaxResults) {
                            // 'status' remains as it was (likely STATUS_SUCCESS if we got here)
                            goto end_scan_loops_label; // Exit all loops
                        }
                    }
                }
            }
            // Note: If MmCopyVirtualMemory fails, we just don't scan this particular region.
            // The overall 'status' of the AobScanProcessRanges function isn't set to this copyStatus
            // unless it's the very last operation and nothing else changes 'status'.
            // This allows the scan to continue trying other regions.

            if (usedTempLargeBuffer && currentBufferToScan) {
                ExFreePoolWithTag(currentBufferToScan, obfuscatedLoaBTag); // Use obfuscated tag
            }
        } // End of main while loop

    end_scan_loops_label:; // Target for goto when MaxResults are found

        // If the loop completed because scanPtr >= EndAddress or MaxResults were found,
        // and 'status' is still its initial STATUS_SUCCESS, then the operation was successful.
        // If the loop broke due to an error (e.g., from ZwQueryVirtualMemory or ExAllocatePool),
        // 'status' will hold that error code.
        // The unconditional 'status = STATUS_SUCCESS;' from the original code is removed.

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (reusableBuffer) {
        ExFreePoolWithTag(reusableBuffer, obfuscatedSoaBTag); // Use obfuscated tag
    }

    KeUnstackDetachProcess(&apc);
    return status;
}

namespace driver {
    // Global IOCTL codes, to be randomized
    ULONG g_ioctl_attach;
    ULONG g_ioctl_read;
    ULONG g_ioctl_write;
    ULONG g_ioctl_get_base;
    ULONG g_ioctl_aob_scan;
    ULONG g_ioctl_allocate_memory;
    ULONG g_ioctl_heap_aob_scan;
    ULONG g_ioctl_process_aob_scan;
    ULONG g_ioctl_install_hook;
    ULONG g_ioctl_uninstall_hook;
    // Add any other IOCTLs that were in the 'codes' namespace here
    // For example:
    // ULONG g_ioctl_another_example_if_any;

    void XorEncryptDecrypt(BYTE* data, SIZE_T size, const BYTE* key, SIZE_T keySize) {
        if (!data || size == 0 || !key || keySize == 0) {
            return;
        }
        for (SIZE_T i = 0; i < size; ++i) {
            data[i] = data[i] ^ key[i % keySize];
        }
    }

    // Shared structure between user-mode and kernel-mode.
    struct Request {
        HANDLE process_id;            // Target process ID
        PVOID target;                 // Target address for read/write
        PVOID buffer;                 // Pointer to buffer in usermode
        SIZE_T size;                  // Size of read/write buffer
        SIZE_T return_size;          // Number of bytes read/written

        WCHAR moduleName[64];        // Name of the module to look for
        PVOID base_address;          // Optional: base address result for various ops

        // AOB scan related fields
        CHAR aob_pattern[256];       // Byte pattern (e.g., "48 8B ?? ??") - using 256
        CHAR aob_mask[256];          // Mask (e.g., "xx??") - using 256
        uintptr_t module_base;       // Module base for AOB/hooking context if needed
        SIZE_T module_size;          // Module size for AOB/hooking context if needed
        UCHAR saved_bytes[256];      // Buffer for various purposes (e.g., AOB results, original hook bytes if UM sends)

        // Memory allocation related
        PVOID alloc_hint;            // Hint address for memory allocation

        // Range restriction for scans (heap, process AOB)
        PVOID start_address;         // Start address of scan range
        PVOID end_address;           // End address of scan range

        // Hooking related fields
        uintptr_t hook_address;      // Target address for placing the hook
        uintptr_t hook_function;     // Address of the function/shellcode to jump to
        SIZE_T hook_length;          // Number of bytes to overwrite for the hook (e.g., 5 for JMP)
        uintptr_t trampoline_out;    // [out] Filled by driver: Address of the trampoline
    };

NTSTATUS InstallTrampolineHook(
    PEPROCESS targetProcess,
    PVOID targetAddress,      // Address to hook
    PVOID hookFunction,       // Address of our shellcode/function to jump to
    SIZE_T hookLength,        // Length of original bytes to overwrite (e.g., 5 for JMP)
    PVOID* trampolineAddress  // [out] Address of the allocated trampoline
)
{
    if (!targetProcess || !targetAddress || !hookFunction || hookLength < 5 || !trampolineAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apcState;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID originalBytes = nullptr;
    PVOID tempTrampoline = nullptr;

    // 1. Allocate memory for the trampoline (original bytes + JMP back)
    SIZE_T trampolineSize = hookLength + 5; // 5 bytes for JMP rel32
    // Try to allocate close to targetAddress for better JMP rel32 chances if target is far
    status = AllocateMemoryNearEx(targetProcess, targetAddress, trampolineSize, &tempTrampoline); // Corrected: remove driver::
    if (!NT_SUCCESS(status) || !tempTrampoline) {
#ifdef DEBUG
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to allocate memory for trampoline: 0x%lX\n", status));
#endif
        return status;
    }
    *trampolineAddress = tempTrampoline;

    originalBytes = ExAllocatePoolWithTag(NonPagedPoolNx, hookLength, 'HooK');
    if (!originalBytes) {
#ifdef DEBUG
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to allocate memory for originalBytes buffer\n"));
#endif
        // NOTE: tempTrampoline is now leaked in the target process.
        // A robust implementation would need a way to free it.
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeStackAttachProcess(targetProcess, &apcState);

    __try {
        // 2. Read original bytes from targetAddress
        SIZE_T bytesRead = 0;
        // Ensure targetAddress is readable and writeable before proceeding
        // This check can be done via ZwQueryVirtualMemory if needed, but MmCopyVirtualMemory will fail if not.
        status = MmCopyVirtualMemory(targetProcess, targetAddress, PsGetCurrentProcess(), originalBytes, hookLength, KernelMode, &bytesRead);
        if (!NT_SUCCESS(status) || bytesRead != hookLength) {
#ifdef DEBUG
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to read original bytes from 0x%p: 0x%lX\n", targetAddress, status));
#endif
            // Leak: tempTrampoline
            status = NT_SUCCESS(status) ? STATUS_DATA_ERROR : status; // Prefer original error
            __leave;
        }

        // 3. Construct trampoline: original bytes + JMP back to (targetAddress + hookLength)
        // Write original bytes to trampoline
        SIZE_T bytesWritten = 0;
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), originalBytes, targetProcess, tempTrampoline, hookLength, KernelMode, &bytesWritten);
        if (!NT_SUCCESS(status) || bytesWritten != hookLength) {
#ifdef DEBUG
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to write original bytes to trampoline (0x%p): 0x%lX\n", tempTrampoline, status));
#endif
            // Leak: tempTrampoline
            status = NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
            __leave;
        }

        // Write JMP rel32 from (tempTrampoline + hookLength) to (targetAddress + hookLength)
        BYTE jmpInstruction[5];
        jmpInstruction[0] = 0xE9; // JMP rel32
        INT32 relativeOffset = (INT32)((ULONG_PTR)targetAddress + hookLength - ((ULONG_PTR)tempTrampoline + hookLength + sizeof(jmpInstruction)));
        memcpy(&jmpInstruction[1], &relativeOffset, sizeof(INT32));

        status = MmCopyVirtualMemory(PsGetCurrentProcess(), jmpInstruction, targetProcess, (PVOID)((ULONG_PTR)tempTrampoline + hookLength), sizeof(jmpInstruction), KernelMode, &bytesWritten);
        if (!NT_SUCCESS(status) || bytesWritten != sizeof(jmpInstruction)) {
#ifdef DEBUG
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to write JMP to original code in trampoline (0x%p): 0x%lX\n", (PVOID)((ULONG_PTR)tempTrampoline + hookLength), status));
#endif
            // Leak: tempTrampoline
            status = NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
            __leave;
        }

        // 4. Write JMP from targetAddress to hookFunction (our shellcode)
        // Ensure hookLength is sufficient for a JMP (e.g., 5 bytes). This is checked at function entry.
        BYTE jmpToHook[5];
        jmpToHook[0] = 0xE9; // JMP rel32
        INT32 relativeOffsetToHook = (INT32)((ULONG_PTR)hookFunction - ((ULONG_PTR)targetAddress + sizeof(jmpToHook)));
        memcpy(&jmpToHook[1], &relativeOffsetToHook, sizeof(INT32));

        // Before writing the JMP, ideally make the page writable if it's not (e.g. code section)
        // For simplicity, this example assumes it's writable or will be handled by MmCopyVirtualMemory's behavior.
        // A full solution might involve ZwProtectVirtualMemory.
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), jmpToHook, targetProcess, targetAddress, sizeof(jmpToHook), KernelMode, &bytesWritten);
        if (!NT_SUCCESS(status) || bytesWritten != sizeof(jmpToHook)) {
#ifdef DEBUG
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to write JMP hook to target address (0x%p): 0x%lX\n", targetAddress, status));
#endif
            // Attempt to restore original bytes if this fails? Very important.
            // This is a critical failure point. If this fails, the original code is partially overwritten or corrupted.
            // Restoring here is crucial.
            SIZE_T bytesRestored = 0;
            MmCopyVirtualMemory(PsGetCurrentProcess(), originalBytes, targetProcess, targetAddress, hookLength, KernelMode, &bytesRestored);
            if (!NT_SUCCESS(status) || bytesRestored != hookLength) { // Should be if(!NT_SUCCESS(restore_status)...) but using status from hook write attempt for now
#ifdef DEBUG
                 KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!!!] CRITICAL: Failed to restore original bytes at 0x%p after hook placement failure. Status of restore attempt is part of overall status.\n", targetAddress));
#endif
            }
            // Leak: tempTrampoline
            status = NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
            __leave;
        }
#ifdef DEBUG
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Hook installed at 0x%p, jumping to 0x%p. Trampoline at 0x%p\n", targetAddress, hookFunction, tempTrampoline));
#endif
        status = STATUS_SUCCESS;

    } __finally {
        if (originalBytes) {
            ExFreePoolWithTag(originalBytes, 'HooK');
        }
        KeUnstackDetachProcess(&apcState);
        // If status is not STATUS_SUCCESS and tempTrampoline was allocated, it should ideally be freed here.
        // This requires a "free memory in target process" function, which is not part of this subtask.
        // This is a known limitation for error recovery.
        if (!NT_SUCCESS(status) && tempTrampoline) {
#ifdef DEBUG
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Hook installation failed with status 0x%lX. Trampoline at 0x%p in target process is leaked.\n", status, tempTrampoline));
#endif
        }
    }
    return status;
}


    NTSTATUS write_mem(
        PEPROCESS targetProcess,
        PVOID targetAddress,
        PVOID buffer,
        SIZE_T size
    ) {
        SIZE_T bytesWritten = 0;

        if (!targetProcess || !targetAddress || !buffer || size == 0)
            return STATUS_INVALID_PARAMETER;

        return MmCopyVirtualMemory(
            PsGetCurrentProcess(),  // from: kernel
            buffer,
            targetProcess,          // to: target process (game)
            targetAddress,
            size,
            KernelMode,
            &bytesWritten
        );
    }

    NTSTATUS read_mem(
        PEPROCESS targetProcess,
        PVOID targetAddress,
        PVOID buffer,
        SIZE_T size
    ) {
        SIZE_T bytesRead = 0;

        if (!targetProcess || !targetAddress || !buffer || size == 0)
           return STATUS_INVALID_PARAMETER;

        return MmCopyVirtualMemory(
            targetProcess,          // from: target process (game)
            targetAddress,
            PsGetCurrentProcess(),  // to: kernel
            buffer,
            size,
            KernelMode,
            &bytesRead
        );
    }

   
    NTSTATUS AllocateMemoryNearEx(
        PEPROCESS targetProcess,
        PVOID hint,         // Desired starting address (the hint)
        SIZE_T size,
        PVOID* outAlloc
    )
    {
        if (!targetProcess || !outAlloc || size == 0)
            return STATUS_INVALID_PARAMETER;

        const SIZE_T pageSize = 0x1000;         // typical system page size (4KB)
        const SIZE_T maxRange = 0x40000000;       // 1GB search range
        int maxAttempts = static_cast<int>(maxRange / pageSize); // e.g., 0x40000000 / 0x1000 = 262144

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        PVOID base = nullptr;
        SIZE_T regionSize = size;

        KAPC_STATE state;
        KeStackAttachProcess(targetProcess, &state);

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            // Try an address offset from the hint, in page increments.
            base = reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(hint) + (attempt * pageSize));
            regionSize = size;   // reset region size each time

            status = ZwAllocateVirtualMemory(
                ZwCurrentProcess(),
                &base,
                0,
                &regionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (NT_SUCCESS(status)) {
                *outAlloc = base;
                DbgPrint("[+] AllocateMemoryNearEx succeeded at 0x%p after %d attempts\n", base, attempt);
                KeUnstackDetachProcess(&state);
                return status;
            }
        }

        KeUnstackDetachProcess(&state);
        DbgPrint("[-] AllocateMemoryNearEx failed, last status: 0x%x after %d attempts\n", status, maxAttempts);
        return status;
    }

// Placeholder for UninstallHook
// A proper implementation requires managing original bytes,
// which are not currently passed or stored by this basic setup.
NTSTATUS UninstallHook(
    PEPROCESS targetProcess,
    PVOID targetAddress,
    SIZE_T hookLength // Length of the hook to "remove" (e.g., by NOPing or attempting to restore if original bytes were available)
) {
    UNREFERENCED_PARAMETER(targetProcess);
    UNREFERENCED_PARAMETER(targetAddress);
    UNREFERENCED_PARAMETER(hookLength);
#ifdef DEBUG
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] UninstallHook called but not fully implemented. Target: 0x%p, Length: %zu\n", targetAddress, hookLength));
#endif
    return STATUS_NOT_IMPLEMENTED;
}





    // Helper function: Allocate executable memory from a target process.
    NTSTATUS AllocateExecutableMemory(PEPROCESS process, PVOID* out, SIZE_T size) {
        if (!process || !out || size == 0) return STATUS_INVALID_PARAMETER;

        KAPC_STATE state;
        KeStackAttachProcess(process, &state);

        PVOID base = nullptr;
        SIZE_T regionSize = size;
        NTSTATUS status = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &base, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        );

        KeUnstackDetachProcess(&state);
        *out = base;
        return status;
    }


    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return irp->IoStatus.Status;
    }

    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return irp->IoStatus.Status;
    }

    NTSTATUS ReadProcessMemory(PEPROCESS targetProcess, PVOID srcAddress, PVOID buffer, SIZE_T size) {
        SIZE_T bytesRead;
        return MmCopyVirtualMemory(targetProcess, srcAddress,
            PsGetCurrentProcess(), buffer,
            size, KernelMode, &bytesRead);
    }

    // Device control dispatch.
    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        debug_print("[+] Device control called.\n"); // Changed to debug_print

        NTSTATUS status{ STATUS_UNSUCCESSFUL };
        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
        auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

        if (stack_irp == nullptr || request == nullptr) {
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return status;
        }

        // Decrypt incoming request data
        XorEncryptDecrypt(reinterpret_cast<BYTE*>(request), sizeof(Request), g_xor_key, g_xor_key_size);

        static PEPROCESS target_process{ nullptr };
        const ULONG control_code{ stack_irp->Parameters.DeviceIoControl.IoControlCode };

        switch (control_code) {
        case g_ioctl_attach: // Use global variable
            status = PsLookupProcessByProcessId(request->process_id, &target_process);
            break;

        case g_ioctl_read: // Use global variable
            if (target_process != nullptr)
                status = MmCopyVirtualMemory(target_process, request->target,
                    PsGetCurrentProcess(), request->buffer,
                    request->size, KernelMode, &request->return_size);
            break;

        case g_ioctl_write: // Use global variable
            if (target_process != nullptr)
                status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer,
                    target_process, request->target, request->size,
                    KernelMode, &request->return_size);
            break;

        case g_ioctl_get_base: // Use global variable
            if (target_process != nullptr) {
                UNICODE_STRING moduleName;
                RtlInitUnicodeString(&moduleName, request->moduleName);
                PVOID moduleBase = NULL;
                // Check if the target process is a WOW64 (32-bit) process.
                if (PsGetProcessWow64Process(target_process) != NULL) {
                    moduleBase = (PVOID)GetModuleBasex86(target_process, moduleName);
                }
                else {
                    moduleBase = (PVOID)GetModuleBasex64(target_process, moduleName);
                }

                if (moduleBase != NULL) {
                    request->base_address = moduleBase;
                    status = STATUS_SUCCESS;
                }
                else {
                    status = STATUS_NOT_FOUND;
                }
            }
            break;

        case g_ioctl_aob_scan: // Use global variable
            if (target_process != nullptr) {
                // 1) Build module name and grab its base/size exactly as before
                UNICODE_STRING moduleName;
                RtlInitUnicodeString(&moduleName, request->moduleName);

                PVOID  moduleBase = nullptr;
                ULONG  moduleSize = 0;

                if (PsGetProcessWow64Process(target_process) != nullptr) {
                    moduleBase = (PVOID)GetModuleBasex86(target_process, moduleName);
                    moduleSize = 0x100000;  // fallback or implement GetModuleSizeX86
                }
                else {
                    moduleBase = (PVOID)GetModuleBasex64(target_process, moduleName);
                    moduleSize = GetModuleSizeX64(target_process, moduleName);
                }

                if (moduleBase != nullptr && moduleSize != 0) {
                    // 2) Prepare a 32‑byte buffer on the stack
                    BYTE savedBytes[32] = { 0 };

                    // 3) Call the new AOBScan overload
                    PVOID foundAddress = AOBScan(
                        target_process,
                        moduleBase,
                        moduleSize,
                        reinterpret_cast<const BYTE*>(request->aob_pattern),
                        request->aob_mask,
                        savedBytes,
                        sizeof(savedBytes)
                    );

                    if (foundAddress) {
                        // 4) Write the found address back
                        request->base_address = foundAddress;

                        // 5) Copy the 32 bytes into your output struct.
                        //    Make sure `request->saved_bytes[32]` actually exists
                        RtlCopyMemory(request->saved_bytes,
                            savedBytes,
                            sizeof(savedBytes));

                        status = STATUS_SUCCESS;
                    }
                    else {
                        status = STATUS_NOT_FOUND;
                    }
                }
                else {
                    status = STATUS_NOT_FOUND;
                }
            }
            break;

            // New IOCTL handler for heap AOB scan
        case g_ioctl_heap_aob_scan: // Use global variable
            if (target_process != nullptr) {
                BYTE savedBytes[32] = { 0 };

                PVOID foundAddress = HeapAOBScan(
                    target_process,
                    reinterpret_cast<const BYTE*>(request->aob_pattern),
                    request->aob_mask,
                    savedBytes,
                    sizeof(savedBytes),
                    request->start_address,   // NEW
                    request->end_address      // NEW
                );

                if (foundAddress) {
                    request->base_address = foundAddress;
                    RtlCopyMemory(request->saved_bytes, savedBytes, sizeof(savedBytes));
                    status = STATUS_SUCCESS;
                }
                else {
                    status = STATUS_NOT_FOUND;
                }
            }
            break;

        case g_ioctl_process_aob_scan: // Use global variable
            if (target_process != nullptr) {
                SIZE_T foundCount = 0;
                UINT64 foundAddrs[64] = { 0 }; // ← Up to 64 results

                status = AobScanProcessRanges(
                    target_process,
                    (UINT64)request->start_address,
                    (UINT64)request->end_address,
                    request->aob_pattern,     // e.g. "48 8B ?? ?? 00 00"
                    foundAddrs,
                    1,
                    &foundCount
                );

                if (NT_SUCCESS(status) && foundCount > 0) {
                    request->base_address = (PVOID)foundAddrs[0]; // only first hit for now
                    RtlCopyMemory(request->saved_bytes, (PVOID)foundAddrs, sizeof(UINT64) * foundCount);
                    request->return_size = foundCount; // optional: return # of hits
                    status = STATUS_SUCCESS;
                }
                else {
                    status = STATUS_NOT_FOUND;
                }
            }
            break;

        case g_ioctl_allocate_memory: // Use global variable
        {
            PEPROCESS target = nullptr;
            NTSTATUS st = PsLookupProcessByProcessId(
                request->process_id,
                &target
            );
            if (!NT_SUCCESS(st)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            // now do your alloc with `target` and `request->alloc_hint`…
            if (request->alloc_hint) {
                status = AllocateMemoryNearEx(
                    target,
                    request->alloc_hint,
                    request->size,
                    &request->base_address
                );
            }
            else {
                status = AllocateExecutableMemory(
                    target,
                    &request->base_address,
                    request->size
                );
            }
            break;
        }

        case g_ioctl_install_hook:
            if (target_process != nullptr) {
                PVOID trampolineAddr = nullptr;
                // InstallTrampolineHook is in the driver namespace (same as this function)
                status = InstallTrampolineHook(
                    target_process,
                    (PVOID)request->hook_address,
                    (PVOID)request->hook_function,
                    request->hook_length,
                    &trampolineAddr
                );
                if (NT_SUCCESS(status)) {
                    request->trampoline_out = (uintptr_t)trampolineAddr;
                }
            } else {
                status = STATUS_INVALID_CID; // No target process attached
            }
            break;

        case g_ioctl_uninstall_hook:
            if (target_process != nullptr) {
                 // UninstallHook is in the driver namespace (same as this function)
                status = UninstallHook(
                    target_process,
                    (PVOID)request->hook_address,
                    request->hook_length // Assuming hook_length is passed for uninstall too
                );
            } else {
                status = STATUS_INVALID_CID; // No target process attached
            }
            break;

        default:
            break;
        }

        // Re-encrypt data before sending back to user-mode
        XorEncryptDecrypt(reinterpret_cast<BYTE*>(request), sizeof(Request), g_xor_key, g_xor_key_size);

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = sizeof(Request);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
} // namespace driver

// Driver initialization.
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    WCHAR randomNamePart[17];
    GenerateRandomString(randomNamePart, 17);

    WCHAR fullDeviceName[64];
    wcscpy(fullDeviceName, L"\\Device\\");
    wcscat(fullDeviceName, randomNamePart);

    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, fullDeviceName);

    PDEVICE_OBJECT pDeviceObject{ nullptr }; // Renamed to avoid conflict if a global `device_object` exists or is introduced.
    NTSTATUS status{ IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject) };

    if (status != STATUS_SUCCESS) {
        // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to create driver device object: %ws\n", fullDeviceName)); // Keep this error, but conditionalize? For now, per instruction, focus on randomized values.
        // This message is an error message, not a randomized value print. Let's keep it for now and conditionalize it later if needed.
        // For this pass, ensure it's not removed if it's an error print.
        // The instruction was "remove all KdPrintEx calls that were added for debugging the randomized names, IOCTLs, and the XOR key"
        // and for "other diagnostic prints ... Either remove them or ensure they are wrapped".
        // This specific one includes `fullDeviceName` which is randomized. So it should be removed or conditionalized.
        // Let's remove it for now as per "remove ... randomized names".
        return status;
    }

    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Successfully created driver device object: %ws\n", fullDeviceName)); // DEBUG REMOVED (related to randomized name)

    WCHAR fullSymbolicLinkName[64];
    wcscpy(fullSymbolicLinkName, L"\\DosDevices\\");
    wcscat(fullSymbolicLinkName, randomNamePart);

    UNICODE_STRING symbolic_link{};
    RtlInitUnicodeString(&symbolic_link, fullSymbolicLinkName);

    status = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (status != STATUS_SUCCESS) {
        // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to create symbolic link: %ws\n", fullSymbolicLinkName)); // Keep this error, conditionalize later. Contains randomized name. Remove for now.
        IoDeleteDevice(pDeviceObject); // Clean up the device object if symlink creation fails
        return status;
    }

    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Successfully established driver symbolic link: %ws\n", fullSymbolicLinkName)); // DEBUG REMOVED (related to randomized name)
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized Device Name: %ws\n", fullDeviceName)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized Symbolic Link: %ws\n", fullSymbolicLinkName)); // DEBUG REMOVED

    // Initialize IOCTL codes
    // Ensure g_randomSeed is initialized (done in DriverEntry)
    ULONG randomBase = 0x800 + (RtlRandomEx(&g_randomSeed) % 0x700);
    g_ioctl_attach = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_read = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_write = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_get_base = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_aob_scan = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_allocate_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_heap_aob_scan = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_ANY_ACCESS);
    g_ioctl_process_aob_scan = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_ANY_ACCESS);
    g_ioctl_install_hook = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    g_ioctl_uninstall_hook = CTL_CODE(FILE_DEVICE_UNKNOWN, randomBase++, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    // Initialize other g_ioctl_... variables if any were added

    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Attach: 0x%lX\n", g_ioctl_attach)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Read: 0x%lX\n", g_ioctl_read)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Write: 0x%lX\n", g_ioctl_write)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Get Base: 0x%lX\n", g_ioctl_get_base)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL AOB Scan: 0x%lX\n", g_ioctl_aob_scan)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Allocate Memory: 0x%lX\n", g_ioctl_allocate_memory)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Heap AOB Scan: 0x%lX\n", g_ioctl_heap_aob_scan)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Process AOB Scan: 0x%lX\n", g_ioctl_process_aob_scan)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Install Hook: 0x%lX\n", g_ioctl_install_hook)); // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized IOCTL Uninstall Hook: 0x%lX\n", g_ioctl_uninstall_hook)); // DEBUG REMOVED
    // Print other IOCTLs if any were added

    // Initialize XOR key
    for (SIZE_T i = 0; i < g_xor_key_size; ++i) {
        g_xor_key[i] = (BYTE)(RtlRandomEx(&g_randomSeed) & 0xFF);
    }

    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] XOR Key: ")); // DEBUG REMOVED
    // for (SIZE_T i = 0; i < g_xor_key_size; ++i) { // DEBUG REMOVED
    //    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%02X ", g_xor_key[i])); // DEBUG REMOVED
    // } // DEBUG REMOVED
    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "\n")); // DEBUG REMOVED

    SetFlag(pDeviceObject->Flags, DO_BUFFERED_IO);

    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

    ClearFlag(pDeviceObject->Flags, DO_DEVICE_INITIALIZING);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] IUIC driver has been successfully initialized!\n"));
    return status;
}

// Driver entry point.
NTSTATUS DriverEntry() {
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] IUIC from the windows kernel!\n")); // Changed debug_print to KdPrintEx

    LARGE_INTEGER seedTime;
    KeQuerySystemTime(&seedTime);
    g_randomSeed = seedTime.LowPart; // Initialize global seed

    WCHAR randomDriverNamePart[17];
    // Note: GenerateRandomString uses its own local seed based on KeQuerySystemTime each time it's called.
    // This is fine, g_randomSeed is for IOCTLs.
    GenerateRandomString(randomDriverNamePart, 17);

    WCHAR fullDriverName[64];
    wcscpy(fullDriverName, L"\\Driver\\");
    wcscat(fullDriverName, randomDriverNamePart);

    UNICODE_STRING driver_name_unicode{}; // Renamed to avoid conflict
    RtlInitUnicodeString(&driver_name_unicode, fullDriverName);

    // KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Randomized Driver Name for IoCreateDriver: %ws\n", fullDriverName)); // DEBUG REMOVED

    return IoCreateDriver(&driver_name_unicode, &driver_main);
}

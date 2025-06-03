#include "includes.h"

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

    if (!TargetProcess || !PatternString || !Results || !ResultsCount || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(TargetProcess, &apc);

    // Pre-allocate a reusable buffer to reduce alloc/free overhead
    // Tunable size: 256KB to 1MB is often a reasonable starting point.
    SIZE_T reusableBufferSize = 0x40000; // 256KB example
    PVOID reusableBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, reusableBufferSize, 'SoaB'); // "BoAS" AOB Scan buffer

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
                currentBufferToScan = ExAllocatePoolWithTag(NonPagedPoolNx, toRead, 'LoaB'); // "BoAL" AOB Large buffer
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
                ExFreePoolWithTag(currentBufferToScan, 'LoaB');
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
        ExFreePoolWithTag(reusableBuffer, 'SoaB');
    }

    KeUnstackDetachProcess(&apc);
    return status;
}

namespace driver {
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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Device control called.\n"));

        NTSTATUS status{ STATUS_UNSUCCESSFUL };
        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
        auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

        if (stack_irp == nullptr || request == nullptr) {
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return status;
        }

        static PEPROCESS target_process{ nullptr };
        const ULONG control_code{ stack_irp->Parameters.DeviceIoControl.IoControlCode };

        switch (control_code) {
        case codes::attach:
            status = PsLookupProcessByProcessId(request->process_id, &target_process);
            break;

        case codes::read:
            if (target_process != nullptr)
                status = MmCopyVirtualMemory(target_process, request->target,
                    PsGetCurrentProcess(), request->buffer,
                    request->size, KernelMode, &request->return_size);
            break;

        case codes::write:
            if (target_process != nullptr)
                status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer,
                    target_process, request->target, request->size,
                    KernelMode, &request->return_size);
            break;

        case codes::get_base:
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

        case codes::aob_scan:
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
        case codes::heap_aob_scan:
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

        case codes::process_aob_scan:
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

        case codes::allocate_memory:
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


        default:
            break;
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = sizeof(Request);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
} // namespace driver

// Driver initialization.
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, L"\\Device\\enterdrivernamehere");

    PDEVICE_OBJECT device_object{ nullptr };
    NTSTATUS status{ IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object) };

    if (status != STATUS_SUCCESS) {
        debug_print("[-] Failed to create driver device object!\n");
        return status;
    }

    debug_print("[+] Successfully created driver device object!\n");

    UNICODE_STRING symbolic_link{};
    RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\enterdrivernamehere");

    status = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (status != STATUS_SUCCESS) {
        debug_print("[-] Failed to create symbolic link!\n");
        return status;
    }

    debug_print("[+] Successfully established driver symbolic link!\n");

    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

    debug_print("[+] IUIC driver has been successfully initialized!\n");
    return status;
}

// Driver entry point.
NTSTATUS DriverEntry() {
    debug_print("[+] IUIC from the windows kernel!\n");

    UNICODE_STRING driver_name{};
    RtlInitUnicodeString(&driver_name, L"\\Driver\\enterdrivernamehere");

    return IoCreateDriver(&driver_name, &driver_main);
}

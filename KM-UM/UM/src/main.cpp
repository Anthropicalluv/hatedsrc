#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <string.h>
#include <cwchar>
#include "aobs.h"
#include "addys.h"
#include <cstdint>
#include <vector>

// in main.cpp or a dedicated globals.cpp
uintptr_t MovementInstruction = 0;
uintptr_t LocalPlayerAddress = 0;
uintptr_t KillauraInstruction = 0;


static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id{ 0 };

	HANDLE snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (snap_shot == INVALID_HANDLE_VALUE) {
		return process_id;
	}

	PROCESSENTRY32W entry{};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snap_shot, &entry) == TRUE) {
		// check if first handle is the one we want
		if (_wcsicmp(process_name, entry.szExeFile) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snap_shot, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			}
		}
	}
	CloseHandle(snap_shot);

	return process_id;
}

static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t module_base{ 0 };

	// snapshot of process' modules (DLLs)
	HANDLE snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
	if (snap_shot == INVALID_HANDLE_VALUE) {
		return module_base;
	}

	MODULEENTRY32W entry{};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snap_shot, &entry) == TRUE) {
		if (wcsstr(module_name, entry.szModule) != nullptr) {
			module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}
		else {
			while (Module32NextW(snap_shot, &entry) == TRUE) {
				if (wcsstr(module_name, entry.szModule) == nullptr) {
					module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
				}
			}
		}
	}

	CloseHandle(snap_shot);

	return module_base;
}

// These values would be obtained from the driver (e.g., via loader or debug prints)
// For this subtask, they are placeholders. In a real run, they'd need actual values.
const wchar_t* G_RANDOMIZED_DEVICE_NAME = L"\\.\IUIC_Enterprise_Random"; // Placeholder

BYTE G_XOR_KEY[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}; // Placeholder
SIZE_T G_XOR_KEY_SIZE = sizeof(G_XOR_KEY);

// Placeholder IOCTLs (replace with actual randomized values from driver output)
namespace global_driver_codes { // Renaming to avoid conflict with driver::codes in UM
    ULONG attach = 0x0; // Example: CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    ULONG read = 0x0;
    ULONG write = 0x0;
    ULONG get_base = 0x0;
    ULONG aob_scan = 0x0;
    ULONG allocate_memory = 0x0;
    ULONG install_hook = 0x0;
    ULONG uninstall_hook = 0x0;
    // Add heap_aob_scan and process_aob_scan if UM uses them (it doesn't currently in main.cpp)
    // ULONG heap_aob_scan = 0x0;
    // ULONG process_aob_scan = 0x0;
}

void XorEncryptDecrypt(BYTE* data, SIZE_T size, const BYTE* key, SIZE_T keySize) {
    if (!data || size == 0 || !key || keySize == 0) {
        return;
    }
    for (SIZE_T i = 0; i < size; ++i) {
        data[i] = data[i] ^ key[i % keySize];
    }
}

namespace driver {
	// The driver::codes namespace is removed/commented out.
	// IOCTLs will be used via global_driver_codes::

	// shared between um & km
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

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request r;
		r.process_id = reinterpret_cast<HANDLE>(pid);

		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		BOOL result = DeviceIoControl(driver_handle, global_driver_codes::attach, // Changed to global_driver_codes
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		return result;
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);

		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		DeviceIoControl(driver_handle, global_driver_codes::read, // Changed to global_driver_codes
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		// The buffer `temp` receives data, but `r` itself might contain output like `return_size`.
		// If `temp` is directly part of `r.buffer` (it is, by pointer), it's already handled by XORing `r`.

		return temp;
	}

	template <class T>
	bool write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value) {
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		// For write, `value` is part of `r.buffer` effectively.
		// If r.buffer pointed to an external buffer, that buffer would need XORing.
		// Here, the data to be written is within `r` if we were to copy `value` into a field in `r`.
		// However, r.buffer points to `value` which is external to `r`.
		// The driver reads from `r.buffer`. The current XOR encrypts `r` (including the pointer `r.buffer`).
		// The actual content pointed to by `r.buffer` (`value`) is NOT XORed by the current logic.
		// This is a potential bug in the XOR strategy for write if the driver expects r.buffer's *content* to be XORed.
		// Assuming the driver XORs its copy of `r` and then uses `r.buffer` to read, it would read the plain `value`.
		// For now, following the pattern of XORing `r` only.
		// A more robust XOR for write would be:
		// BYTE write_buf[sizeof(T)]; memcpy(write_buf, &value, sizeof(T));
		// XorEncryptDecrypt(write_buf, sizeof(T), G_XOR_KEY, G_XOR_KEY_SIZE);
		// r.buffer = write_buf; r.size = sizeof(T);
		// XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		// DeviceIoControl(...);
		// XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt `r` if it has outputs
		// For simplicity, sticking to the current pattern:
		r.buffer = (PVOID)&value; // `value` itself is not XORed by this call.
		r.size = sizeof(T);

		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		DeviceIoControl(driver_handle, global_driver_codes::write, // Changed to global_driver_codes
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&r), sizeof(r), G_XOR_KEY, G_XOR_KEY_SIZE);
		// `r` might contain `return_size`.

		return true;
	}


} // namespace driver

PBYTE AOBScan(PBYTE baseAddress, SIZE_T regionSize, const BYTE* pattern, const char* mask)
{
	SIZE_T patternLength = std::strlen(mask);
	// Loop over the region until there's not enough space left for the pattern.
	for (SIZE_T i = 0; i <= regionSize - patternLength; i++)
	{
		bool found = true;
		for (SIZE_T j = 0; j < patternLength; j++)
		{
			// 'x' indicates that this byte must match exactly.
			if (mask[j] == 'x' && pattern[j] != *(baseAddress + i + j))
			{
				found = false;
				break;
			}
			// '?' acts as a wildcard and is skipped.
		}
		if (found)
		{
			return baseAddress + i;
		}
	}
	return nullptr;
}

// New version: Now accepts a hint address to help allocate near the target.
bool allocate_memory(HANDLE driver_handle, DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint) {
	driver::Request request = {};
	request.process_id = reinterpret_cast<HANDLE>(pid);
	request.size = size;
	request.alloc_hint = allocHint;  // New field: use hint for near allocation

	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver_handle, global_driver_codes::allocate_memory, // Changed to global_driver_codes
		&request, sizeof(request), &request, sizeof(request),
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response

		out_address = reinterpret_cast<uintptr_t>(request.base_address);
		std::cout << "[+] Allocated memory at: 0x" << std::hex << out_address << std::endl;
		return true;
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] Failed to allocate memory." << std::endl;
		return false;
	}
}


int main() {
	driver::Request request = {}; // This will be the main request object for many operations
	const DWORD pid = get_process_id(L"destiny2.exe");

	if (pid == 0) {
		std::cout << "[-] Failed to get process id!\n";
		std::cin.get();
		return -1;
	}

	const HANDLE driver{ CreateFile(G_RANDOMIZED_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, // Added GENERIC_WRITE for DeviceIoControl output buffer
									0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
									nullptr) };

	if (driver == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Failed to create driver handle.\n";
		std::cin.get();
		return -1;
	}

	if (driver::attach_to_process(driver, pid) == true) {
		std::cout << "[+] Attachment successful.\n";
	}

	wcscpy_s(request.moduleName, L"destiny2.exe");

	// Now send the IOCTL to get the module base
	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver, global_driver_codes::get_base, // Changed to global_driver_codes
		&request, sizeof(request), &request, sizeof(request),
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response
		std::cout << "[+] Module base address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure, in case of partial data
		std::cout << "[-] Failed to get module base.\n";
	}

	std::cin.get();

	// Set up the pattern and mask for the AOB scan.
	memcpy(request.aob_pattern, LocalPlayerAOB, sizeof(LocalPlayerAOB));
	strcpy_s(request.aob_mask, LocalPlayerAOBMask);

	std::cout << "[+] AOB scan started...\n";

	// Perform the AOB scan by sending the IOCTL to the driver.
	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver, global_driver_codes::aob_scan, // Changed to global_driver_codes
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response

		std::cout << "[+] AOB scan found pattern at address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
		MovementInstruction = reinterpret_cast<uintptr_t>(request.base_address);
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] AOB scan failed.\n";
	}

	std::cout << "[+] Movement Instruction = " << std::hex << MovementInstruction << std::endl;

	// killaura AOB scan
	memcpy(request.aob_pattern, KillauraAOB, sizeof(KillauraAOB));
	strcpy_s(request.aob_mask, KillauraAOBMask);

	std::cout << "[+] Killaura AOB scan started...\n";
	std::cin.get();

	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver, global_driver_codes::aob_scan, // Changed to global_driver_codes
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response

		std::cout << "[+] AOB scan found pattern at address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
		KillauraInstruction = reinterpret_cast<uintptr_t>(request.base_address);
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] AOB scan failed.\n";
	}

	std::cout << "[+] Killaura Instruction = " << std::hex << KillauraInstruction << std::endl;
	std::cin.get();

	// Step 1: Allocate memory for your injected shellcode.
	// IMPORTANT: Make sure to update hookFunctionAddress with the allocated memory.
	uintptr_t hookFunctionAddress = 0;
	request.process_id = reinterpret_cast<HANDLE>(pid);
	request.size = 100;  // desired allocation size
	request.alloc_hint = reinterpret_cast<PVOID>(KillauraInstruction);

	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver, global_driver_codes::allocate_memory, // Changed to global_driver_codes
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr))
	{
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response
		// Save the allocated address to hookFunctionAddress.
		hookFunctionAddress = reinterpret_cast<uintptr_t>(request.base_address);
		std::cout << "[+] Successfully allocated memory at: 0x" << std::hex << hookFunctionAddress << std::endl;
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] Failed to allocate memory via direct driver call." << std::endl;
		std::cin.get();
		return -1;
	}
	
	// For uninstall_hook, prepare the request object again or clear fields not used by this IOCTL.
	// Assuming `request` still holds relevant pid, and we set hook_address for uninstall.
	request.hook_address = KillauraInstruction;  // AOB scan result
    request.hook_length = 5; // Assuming the hook to uninstall was 5 bytes. Driver might need this.
	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (DeviceIoControl(driver, global_driver_codes::uninstall_hook, // Changed to global_driver_codes
		&request, sizeof(request),
		&request, sizeof(request), // Response also in request
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response
		std::cout << "[+] Uninstall hook successful.\n";
	}
	else {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&request), sizeof(request), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] Failed to uninstall hook.\n";
	}

	std::cin.get();

	// Step 2: Install trampoline hook (5-byte JMP)
	driver::Request hookReq{}; // Using a separate request for install_hook for clarity
	hookReq.process_id = reinterpret_cast<HANDLE>(pid);
	hookReq.hook_address = KillauraInstruction;  // AOB scan result
	hookReq.hook_function = hookFunctionAddress;
	hookReq.hook_length = 5;

	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&hookReq), sizeof(hookReq), G_XOR_KEY, G_XOR_KEY_SIZE);
	if (!DeviceIoControl(driver, global_driver_codes::install_hook, // Changed to global_driver_codes
		&hookReq, sizeof(hookReq), &hookReq, sizeof(hookReq),
		nullptr, nullptr)) {
		XorEncryptDecrypt(reinterpret_cast<BYTE*>(&hookReq), sizeof(hookReq), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt even on failure
		std::cout << "[-] Failed to install hook.\n";
		std::cin.get();
		return -1;
	}
	XorEncryptDecrypt(reinterpret_cast<BYTE*>(&hookReq), sizeof(hookReq), G_XOR_KEY, G_XOR_KEY_SIZE); // Decrypt response

	uintptr_t trampoline = hookReq.trampoline_out;
	std::cin.get();

	// Step 3: Build shellcode (your CE logic)
	uint8_t shellcode[] = {
		0xC7, 0x41, 0x20,                  // mov dword ptr [rcx+0x20],
		0x00, 0x00, 0x34, 0x42,            //     float 45.0f → 0x42340000 (little-endian)
		0xF3, 0x0F, 0x10, 0x41, 0x20,      // movss xmm0, [rcx+0x20]
		0xE9, 0, 0, 0, 0                   // jmp return (relative jump placeholder)
	};

	// Set JMP to trampoline + 5
	uintptr_t returnAddress = KillauraInstruction + 5;
	int32_t relJmp = static_cast<int32_t>(returnAddress - (hookFunctionAddress + sizeof(shellcode)));
	memcpy(shellcode + sizeof(shellcode) - 4, &relJmp, 4);

	std::cout << "[+] Shellcode built!\n";
	std::cin.get();

	// Step 4: Write shellcode
	if (!driver::write_memory(driver, hookFunctionAddress, shellcode)) {
		std::cout << "[-] Failed to write shellcode.\n";
		std::cin.get();
		return -1;
	}

	std::cout << "[+] Killaura hook installed and shellcode written!\n";

	Sleep(1000);


	std::cout << "[DEBUG] Jump back absolute address: 0x"
		<< std::hex << returnAddress << std::endl;
	std::cin.get();
	std::cout << "[DEBUG] HookFunction: 0x" << std::hex << hookFunctionAddress << "\n";
	std::cin.get();
	std::cout << "[DEBUG] Trampoline: 0x" << std::hex << trampoline << "\n";
	std::cin.get();
	std::cout << "[DEBUG] Shellcode size: " << std::dec << sizeof(shellcode) << "\n";
	std::cin.get();
	std::cout << "[DEBUG] Computed relative jump offset: " << std::hex << relJmp
		<< " (" << std::dec << relJmp << ")\n";

	std::cout << "[+] Press any key to exit...\n";
	std::cin.get();
	CloseHandle(driver);
	return 0;
}

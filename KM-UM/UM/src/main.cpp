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

		constexpr ULONG install_hook = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6A3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG uninstall_hook = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6A4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);



	} // namespace codes

	// shared between um & km
	struct Request {
		HANDLE process_id;            // Target process ID
		PVOID target;                 // Target address for read/write
		PVOID buffer;                 // Pointer to buffer in usermode
		SIZE_T size;                  // Size of read/write buffer
		SIZE_T return_size;          // Number of bytes read/written

		WCHAR moduleName[64];       // Name of the module to look for
		PVOID base_address;          // Optional: base address result

		// AOB scan
		CHAR aob_pattern[128];       // Byte pattern (e.g., "48 8B ?? ??")
		CHAR aob_mask[128];          // Mask (e.g., "xx??")
		uintptr_t module_base;       // Module base for AOB scan
		SIZE_T module_size;          // Module size for AOB scan

		uintptr_t hook_address;     // where to place hook
		uintptr_t hook_function;    // function to redirect to
		SIZE_T hook_length;         // number of bytes to overwrite
		uintptr_t trampoline_out;   // [out] filled with trampoline address

		PVOID alloc_hint; // hint address for memory allocation

	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request r;
		r.process_id = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(driver_handle, codes::attach,
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::read,
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);

		return temp;
	}

	template <class T>
	bool write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value) {
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = (PVOID)&value;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write,
			&r, sizeof(r), &r, sizeof(r),
			nullptr, nullptr);

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

	if (DeviceIoControl(driver_handle, driver::codes::allocate_memory,
		&request, sizeof(request), &request, sizeof(request),
		nullptr, nullptr)) {

		out_address = reinterpret_cast<uintptr_t>(request.base_address);
		std::cout << "[+] Allocated memory at: 0x" << std::hex << out_address << std::endl;
		return true;
	}
	else {
		std::cout << "[-] Failed to allocate memory." << std::endl;
		return false;
	}
}


int main() {
	driver::Request request = {};
	const DWORD pid = get_process_id(L"destiny2.exe");

	if (pid == 0) {
		std::cout << "[-] Failed to get process id!\n";
		std::cin.get();
		return -1;
	}

	const HANDLE driver{ CreateFile(L"\\\\.\\IUIC_Enterprise", GENERIC_READ,
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
	if (DeviceIoControl(driver, driver::codes::get_base,
		&request, sizeof(request), &request, sizeof(request),
		nullptr, nullptr)) {
		std::cout << "[+] Module base address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
	}
	else {
		std::cout << "[-] Failed to get module base.\n";
	}

	std::cin.get();

	// Set up the pattern and mask for the AOB scan.
	memcpy(request.aob_pattern, LocalPlayerAOB, sizeof(LocalPlayerAOB));
	strcpy_s(request.aob_mask, LocalPlayerAOBMask);

	std::cout << "[+] AOB scan started...\n";

	// Perform the AOB scan by sending the IOCTL to the driver.
	if (DeviceIoControl(driver, driver::codes::aob_scan,
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr)) {

		std::cout << "[+] AOB scan found pattern at address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
		MovementInstruction = reinterpret_cast<uintptr_t>(request.base_address);
	}
	else {
		std::cout << "[-] AOB scan failed.\n";
	}

	std::cout << "[+] Movement Instruction = " << std::hex << MovementInstruction << std::endl;

	// killaura AOB scan
	memcpy(request.aob_pattern, KillauraAOB, sizeof(KillauraAOB));
	strcpy_s(request.aob_mask, KillauraAOBMask);

	std::cout << "[+] Killaura AOB scan started...\n";
	std::cin.get();

	if (DeviceIoControl(driver, driver::codes::aob_scan,
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr)) {

		std::cout << "[+] AOB scan found pattern at address: 0x"
			<< std::hex << reinterpret_cast<std::uintptr_t>(request.base_address)
			<< std::endl;
		KillauraInstruction = reinterpret_cast<uintptr_t>(request.base_address);
	}
	else {
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

	if (DeviceIoControl(driver, driver::codes::allocate_memory,
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr))
	{
		// Save the allocated address to hookFunctionAddress.
		hookFunctionAddress = reinterpret_cast<uintptr_t>(request.base_address);
		std::cout << "[+] Successfully allocated memory at: 0x" << std::hex << hookFunctionAddress << std::endl;
	}
	else {
		std::cout << "[-] Failed to allocate memory via direct driver call." << std::endl;
		std::cin.get();
		return -1;
	}
	
	request.hook_address = KillauraInstruction;  // AOB scan result
	if (DeviceIoControl(driver, driver::codes::uninstall_hook,
		&request, sizeof(request),
		&request, sizeof(request),
		nullptr, nullptr)) {
		std::cout << "[+] Uninstall hook successful.\n";
	}
	else {
		std::cout << "[-] Failed to uninstall hook.\n";
	}

	std::cin.get();

	// Step 2: Install trampoline hook (5-byte JMP)
	driver::Request hookReq{};
	hookReq.process_id = reinterpret_cast<HANDLE>(pid);
	hookReq.hook_address = KillauraInstruction;  // AOB scan result
	hookReq.hook_function = hookFunctionAddress;
	hookReq.hook_length = 5;

	if (!DeviceIoControl(driver, driver::codes::install_hook,
		&hookReq, sizeof(hookReq), &hookReq, sizeof(hookReq),
		nullptr, nullptr)) {
		std::cout << "[-] Failed to install hook.\n";
		std::cin.get();
		return -1;
	}

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

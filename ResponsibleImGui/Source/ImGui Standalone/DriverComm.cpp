#include "DriverComm.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <cstring>


namespace DriverComm {

    HANDLE g_driverHandle = INVALID_HANDLE_VALUE;
    DWORD g_pid = 0;
   

	

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


	bool allocate_memory(HANDLE driver_handle, DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint) {
		DriverComm::Request request = {};
		request.process_id = reinterpret_cast<HANDLE>(pid);
		request.size = size;
		request.alloc_hint = allocHint;  // New field: use hint for near allocation

		if (DeviceIoControl(driver_handle, DriverComm::codes::allocate_memory,
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

	std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
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

}

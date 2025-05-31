#include "DriverMapper.h"
#include "embedded/kdmapper_exe.h"
#include "embedded/KM_sys.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>

std::wstring DriverMapper::s_tempKdmapperPath;
std::wstring DriverMapper::s_tempDriverPath;
bool DriverMapper::s_tempFilesCreated = false;

bool DriverMapper::MapDriver() {
    std::wcout << L"[+] Starting automatic driver mapping..." << std::endl;
    

    if (IsDriverLoaded()) {
        std::wcout << L"[+] Driver is already loaded!" << std::endl;
        return true;
    }
    
    try {
        std::wstring tempDir = GetTempDirectory();
        if (tempDir.empty()) {
            std::wcerr << L"[-] Failed to get temp directory!" << std::endl;
            return false;
        }

        DWORD tickCount = GetTickCount();
        s_tempKdmapperPath = tempDir + L"\\kdmapper_" + std::to_wstring(tickCount) + L".exe";
        s_tempDriverPath = tempDir + L"\\KM_" + std::to_wstring(tickCount) + L".sys";
        
        //extracting the embedded stuff 
        if (!ExtractResource(kdmapper_exe, kdmapper_exe_len, s_tempKdmapperPath)) {
            std::wcerr << L"[-] Failed to extract kdmapper.exe!" << std::endl;
            return false;
        }
        if (!ExtractResource(KM_sys, KM_sys_len, s_tempDriverPath)) {
            std::wcerr << L"[-] Failed to extract KM.sys!" << std::endl;
            CleanupTempFiles();
            return false;
        }
        
        s_tempFilesCreated = true;
        std::wcout << L"[+] Successfully extracted embedded files" << std::endl;

        if (!ExecuteKdmapper(s_tempKdmapperPath, s_tempDriverPath)) {
            std::wcerr << L"[-] Failed to execute kdmapper!" << std::endl;
            CleanupTempFiles();
            return false;
        }
        
        std::wcout << L"[+] Driver mapping completed successfully!" << std::endl;

        Sleep(1000);
        
        if (IsDriverLoaded()) {
            std::wcout << L"[+] Driver mapping verified successfully!" << std::endl;
            CleanupTempFiles();
            return true;
        } else {
            std::wcerr << L"[-] Driver mapping failed - driver not accessible!" << std::endl;
            CleanupTempFiles();
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception during driver mapping: " << e.what() << std::endl;
        CleanupTempFiles();
        return false;
    }
}

bool DriverMapper::IsDriverLoaded() {
    HANDLE driverHandle = CreateFile(
        L"\\\\.\\IUIC_Enterprise",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (driverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(driverHandle);
        return true;
    }
    
    return false;
}

bool DriverMapper::ExtractResource(const unsigned char* data, unsigned int size, const std::wstring& filePath) {
    try {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            std::wcerr << L"[-] Failed to create file: " << filePath << std::endl;
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
        
        if (!FileExists(filePath)) {
            std::wcerr << L"[-] File extraction verification failed: " << filePath << std::endl;
            return false;
        }
        
        std::wcout << L"[+] Extracted: " << filePath << L" (" << size << L" bytes)" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception extracting file: " << e.what() << std::endl;
        return false;
    }
}

bool DriverMapper::ExecuteKdmapper(const std::wstring& kdmapperPath, const std::wstring& driverPath) {
    try {
        std::wstring cmdLine = L"\"" + kdmapperPath + L"\" \"" + driverPath + L"\"";
        
        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        std::wcout << L"[+] Executing: " << cmdLine << std::endl;
        
        BOOL result = CreateProcessW(
            nullptr,             
            const_cast<LPWSTR>(cmdLine.c_str()), // Command line
            nullptr,           
            nullptr,             
            FALSE,              
            CREATE_NO_WINDOW,    
            nullptr,             
            nullptr,              
            &si,                 
            &pi                   
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::wcerr << L"[-] CreateProcess failed with error: " << error << std::endl;
            return false;
        }
        
        std::wcout << L"[+] Kdmapper process started, waiting for completion..." << std::endl;

        DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);
        
        if (waitResult == WAIT_TIMEOUT) {
            std::wcerr << L"[-] Kdmapper execution timed out!" << std::endl;
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        if (waitResult != WAIT_OBJECT_0) {
            std::wcerr << L"[-] WaitForSingleObject failed!" << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        

        DWORD exitCode;
        if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
            std::wcerr << L"[-] Failed to get kdmapper exit code!" << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        if (exitCode == 0) {
            std::wcout << L"[+] Kdmapper executed successfully (exit code: " << exitCode << L")" << std::endl;
            return true;
        } else {
            std::wcerr << L"[-] Kdmapper failed with exit code: " << exitCode << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception executing kdmapper: " << e.what() << std::endl;
        return false;
    }
}

std::wstring DriverMapper::GetTempDirectory() {
    wchar_t tempPath[MAX_PATH];
    DWORD result = GetTempPathW(MAX_PATH, tempPath);
    
    if (result == 0 || result > MAX_PATH) {
        return L"";
    }
    
    return std::wstring(tempPath);
}

bool DriverMapper::FileExists(const std::wstring& filePath) {
    DWORD fileAttrib = GetFileAttributesW(filePath.c_str());
    return (fileAttrib != INVALID_FILE_ATTRIBUTES) && 
           !(fileAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

void DriverMapper::CleanupTempFiles() {
    if (!s_tempFilesCreated) {
        return;
    }
    
    try {
        if (!s_tempKdmapperPath.empty() && FileExists(s_tempKdmapperPath)) {
            if (DeleteFileW(s_tempKdmapperPath.c_str())) {
                std::wcout << L"[+] Cleaned up: " << s_tempKdmapperPath << std::endl;
            } else {
                std::wcerr << L"[-] Failed to delete: " << s_tempKdmapperPath << std::endl;
            }
        }
        
        if (!s_tempDriverPath.empty() && FileExists(s_tempDriverPath)) {
            if (DeleteFileW(s_tempDriverPath.c_str())) {
                std::wcout << L"[+] Cleaned up: " << s_tempDriverPath << std::endl;
            } else {
                std::wcerr << L"[-] Failed to delete: " << s_tempDriverPath << std::endl;
            }
        }
        
        s_tempKdmapperPath.clear();
        s_tempDriverPath.clear();
        s_tempFilesCreated = false;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception during cleanup: " << e.what() << std::endl;
    }
}

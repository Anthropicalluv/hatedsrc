#include "UpdateManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <wininet.h>
#include <urlmon.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

bool UpdateManager::CheckForUpdates(const std::string& currentVersion, Release& latestRelease) {
    try {
        std::wcout << L"[+] Checking for updates..." << std::endl;
        
        // Make request to GitHub API
        std::string response = MakeHttpsRequest(GITHUB_API_URL);
        if (response.empty()) {
            std::wcerr << L"[-] Failed to fetch release information" << std::endl;
            return false;
        }

        // Parse JSON response manually
        latestRelease.tagName = ParseJsonString(response, "tag_name");
        latestRelease.name = ParseJsonString(response, "name");
        latestRelease.body = ParseJsonString(response, "body");
        
        // Parse prerelease flag
        std::string prereleaseStr = ParseJsonString(response, "prerelease");
        latestRelease.prerelease = (prereleaseStr == "true");
        
        // Parse version from tag
        latestRelease.version = ParseVersion(latestRelease.tagName);
        Version currentVer = ParseVersion(currentVersion);
        
        // Find download URL for the loader executable
        std::vector<std::string> assetNames = ParseJsonArray(response, "assets");
        for (const auto& assetBlock : assetNames) {
            std::string assetName = ParseJsonString(assetBlock, "name");
            // Look for loader executable (adjust name as needed)
            if (assetName.find("Loader.exe") != std::string::npos || 
                assetName.find("HatedLoader.exe") != std::string::npos ||
                assetName.find("loader.exe") != std::string::npos) {
                latestRelease.downloadUrl = ParseJsonString(assetBlock, "browser_download_url");
                break;
            }
        }
        
        if (latestRelease.downloadUrl.empty()) {
            std::wcerr << L"[-] No loader executable found in release assets" << std::endl;
            return false;
        }
        
        // Check if update is available
        if (latestRelease.version > currentVer) {
            std::wcout << L"[+] Update available: " << latestRelease.tagName.c_str() 
                      << L" (Current: " << currentVersion.c_str() << L")" << std::endl;
            return true;
        } else {
            std::wcout << L"[+] You have the latest version (" << currentVersion.c_str() << L")" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error checking for updates: " << e.what() << std::endl;
        return false;
    }
}

bool UpdateManager::DownloadUpdate(const Release& release, const std::wstring& downloadPath, 
                                  std::function<void(int)> progressCallback) {
    try {
        std::wcout << L"[+] Downloading update: " << release.name.c_str() << std::endl;
        
        // Convert URL to wide string
        std::wstring wideUrl(release.downloadUrl.begin(), release.downloadUrl.end());
        
        // Download file using URLDownloadToFile
        HRESULT hr = URLDownloadToFileW(nullptr, wideUrl.c_str(), downloadPath.c_str(), 0, nullptr);
        
        if (SUCCEEDED(hr)) {
            std::wcout << L"[+] Update downloaded successfully to: " << downloadPath << std::endl;
            return true;
        } else {
            std::wcerr << L"[-] Failed to download update (HRESULT: " << hr << L")" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error downloading update: " << e.what() << std::endl;
        return false;
    }
}

bool UpdateManager::CreateUpdateHelper(const std::wstring& helperPath, const std::wstring& newLoaderPath, 
                                       const std::wstring& currentLoaderPath) {
    try {
        std::wofstream helperScript(helperPath);
        if (!helperScript.is_open()) {
            std::wcerr << L"[-] Failed to create update helper script" << std::endl;
            return false;
        }
        
        // Create batch script for updating
        helperScript << L"@echo off" << std::endl;
        helperScript << L"echo [+] Hated Loader Update Helper" << std::endl;
        helperScript << L"echo [+] Waiting for loader to close..." << std::endl;
        helperScript << L"timeout /t 5 /nobreak >nul" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Backing up current loader..." << std::endl;
        helperScript << L"copy \"" << currentLoaderPath << L"\" \"" << currentLoaderPath << L".backup\" >nul" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Installing update..." << std::endl;
        helperScript << L"copy \"" << newLoaderPath << L"\" \"" << currentLoaderPath << L"\" >nul" << std::endl;
        helperScript << L"if errorlevel 1 (" << std::endl;
        helperScript << L"    echo [-] Update failed! Restoring backup..." << std::endl;
        helperScript << L"    copy \"" << currentLoaderPath << L".backup\" \"" << currentLoaderPath << L"\" >nul" << std::endl;
        helperScript << L"    echo [-] Update failed. Press any key to exit." << std::endl;
        helperScript << L"    pause >nul" << std::endl;
        helperScript << L"    goto cleanup" << std::endl;
        helperScript << L")" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Update completed successfully!" << std::endl;
        helperScript << L"echo [+] Starting updated loader..." << std::endl;
        helperScript << L"start \"\" \"" << currentLoaderPath << L"\"" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L":cleanup" << std::endl;
        helperScript << L"echo [+] Cleaning up..." << std::endl;
        helperScript << L"del \"" << newLoaderPath << L"\" >nul 2>&1" << std::endl;
        helperScript << L"del \"" << currentLoaderPath << L".backup\" >nul 2>&1" << std::endl;
        helperScript << L"del \"" << helperPath << L"\" >nul 2>&1" << std::endl;
        
        helperScript.close();
        
        std::wcout << L"[+] Update helper script created: " << helperPath << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error creating update helper: " << e.what() << std::endl;
        return false;
    }
}

bool UpdateManager::LaunchUpdateHelper(const std::wstring& helperPath) {
    try {
        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        
        std::wstring cmdLine = L"cmd.exe /c \"" + helperPath + L"\"";
        
        BOOL result = CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(cmdLine.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::wcout << L"[+] Update helper launched successfully" << std::endl;
            return true;
        } else {
            DWORD error = GetLastError();
            std::wcerr << L"[-] Failed to launch update helper (Error: " << error << L")" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error launching update helper: " << e.what() << std::endl;
        return false;
    }
}

UpdateManager::Version UpdateManager::ParseVersion(const std::string& versionStr) {
    Version version;
    
    // Remove 'v' prefix if present
    std::string cleanVersion = versionStr;
    if (!cleanVersion.empty() && cleanVersion[0] == 'v') {
        cleanVersion = cleanVersion.substr(1);
    }
    
    // Parse major.minor.patch format
    std::regex versionRegex(R"((\d+)\.(\d+)\.(\d+))");
    std::smatch matches;
    
    if (std::regex_search(cleanVersion, matches, versionRegex)) {
        version.major = std::stoi(matches[1].str());
        version.minor = std::stoi(matches[2].str());
        version.patch = std::stoi(matches[3].str());
    }
    
    return version;
}

std::string UpdateManager::MakeHttpsRequest(const std::string& url) {
    HINTERNET hInternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) {
        return "";
    }
    
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, 
                                         INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }
    
    std::string response;
    char buffer[1024];
    DWORD bytesRead;
    
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return response;
}

std::string UpdateManager::ParseJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) {
        return "";
    }
    
    size_t valueStart = json.find("\"", keyPos + searchKey.length());
    if (valueStart == std::string::npos) {
        return "";
    }
    valueStart++; // Skip opening quote
    
    size_t valueEnd = valueStart;
    while (valueEnd < json.length()) {
        if (json[valueEnd] == '\"' && (valueEnd == 0 || json[valueEnd - 1] != '\\')) {
            break;
        }
        valueEnd++;
    }
    
    if (valueEnd == json.length()) {
        return "";
    }
    
    return json.substr(valueStart, valueEnd - valueStart);
}

std::vector<std::string> UpdateManager::ParseJsonArray(const std::string& json, const std::string& arrayKey) {
    std::vector<std::string> results;
    
    std::string searchKey = "\"" + arrayKey + "\":[";
    size_t arrayStart = json.find(searchKey);
    if (arrayStart == std::string::npos) {
        return results;
    }
    
    arrayStart += searchKey.length();
    
    // Find the matching closing bracket
    int bracketCount = 1;
    size_t arrayEnd = arrayStart;
    while (arrayEnd < json.length() && bracketCount > 0) {
        if (json[arrayEnd] == '[') bracketCount++;
        else if (json[arrayEnd] == ']') bracketCount--;
        arrayEnd++;
    }
    
    if (bracketCount != 0) {
        return results;
    }
    arrayEnd--; // Move back to the closing bracket
    
    // Extract array content
    std::string arrayContent = json.substr(arrayStart, arrayEnd - arrayStart);
    
    // Parse individual objects in the array
    size_t objStart = 0;
    int objBracketCount = 0;
    size_t objStartPos = 0;
    
    for (size_t i = 0; i < arrayContent.length(); i++) {
        if (arrayContent[i] == '{') {
            if (objBracketCount == 0) {
                objStartPos = i;
            }
            objBracketCount++;
        } else if (arrayContent[i] == '}') {
            objBracketCount--;
            if (objBracketCount == 0) {
                // Found complete object
                std::string obj = arrayContent.substr(objStartPos, i - objStartPos + 1);
                results.push_back(obj);
            }
        }
    }
    
    return results;
}
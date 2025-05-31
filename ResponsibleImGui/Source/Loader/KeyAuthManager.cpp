#include "KeyAuthManager.h"
#include <iostream>
#include <Windows.h>
#include <algorithm>
#include <ctime>
#include <cstring>

namespace KeyAuthManager {
    // KeyAuth app configuration
    std::string name = skCrypt("").decrypt();
    std::string ownerid = skCrypt("").decrypt();
    std::string version = skCrypt("1.0").decrypt();
    std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt();
    std::string path = skCrypt("").decrypt();
    
    // KeyAuth app instance
    KeyAuth::api KeyAuthApp(name, ownerid, version, url, path);
    
    // Authentication state
    bool isAuthenticated = false;
    char License[128] = "Enter Your License Key";
    char statusmsg[128] = "";
    
    // Internal state
    bool gTriedAuto = false;
    bool gHasInitialized = false;
    bool isAuthenticating = false;
    char savedHwid[64] = "";
    
    // XOR key for registry encryption
    static constexpr char xorKey[] = "IUICGodIsBlackGodBlessIsrael";
    
    void Initialize() {
        try {
            if (!gHasInitialized) {
                KeyAuthApp.init();
                gHasInitialized = true;
                std::cout << "[KeyAuth] Initialized successfully\n";
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[KeyAuth] Initialization failed: " << e.what() << "\n";
            strcpy_s(statusmsg, "Failed to initialize KeyAuth");
        }
        catch (...) {
            std::cerr << "[KeyAuth] Initialization failed with unknown error\n";
            strcpy_s(statusmsg, "Failed to initialize KeyAuth");
        }
    }
    
    void Cleanup() {
        // Reset all state variables
        isAuthenticated = false;
        strcpy_s(License, "Enter Your License Key");
        strcpy_s(statusmsg, "");
        savedHwid[0] = '\0';
        gTriedAuto = false;
        gHasInitialized = false;
        isAuthenticating = false;
    }
    
    void xorCipher(std::vector<char>& buf) {
        const size_t keyLen = strlen(xorKey);
        const size_t bufSize = buf.size();
        
        if (bufSize == 0) return;
        
        // Process in chunks of 8 bytes for better CPU cache usage
        size_t i = 0;
        for (; i + 8 <= bufSize; i += 8) {
            buf[i]   ^= xorKey[i % keyLen];
            buf[i+1] ^= xorKey[(i+1) % keyLen];
            buf[i+2] ^= xorKey[(i+2) % keyLen];
            buf[i+3] ^= xorKey[(i+3) % keyLen];
            buf[i+4] ^= xorKey[(i+4) % keyLen];
            buf[i+5] ^= xorKey[(i+5) % keyLen];
            buf[i+6] ^= xorKey[(i+6) % keyLen];
            buf[i+7] ^= xorKey[(i+7) % keyLen];
        }
        
        // Handle remaining elements
        for (; i < bufSize; ++i) {
            buf[i] ^= xorKey[i % keyLen];
        }
    }
    
    void SaveCredentials(const char* licenseKey) {
        // Build JSON string
        std::string json = "{\n"
            "  \"license\": \"" + std::string(licenseKey) + "\",\n"
            "  \"hwid\":    \"" + KeyAuthApp.user_data.hwid + "\"\n"
            "}\n";

        // Encrypt
        std::vector<char> buf(json.begin(), json.end());
        xorCipher(buf);

        // Write to registry
        HKEY hKey;
        RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
        RegSetValueExA(hKey, "Creds", 0, REG_BINARY,
                       reinterpret_cast<BYTE*>(buf.data()), (DWORD)buf.size());
        RegCloseKey(hKey);
    }
    
    bool LoadCredentials(char* licenseKey, size_t licSz) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        DWORD type = REG_BINARY, cb = 0;
        if (RegQueryValueExA(hKey, "Creds", nullptr, &type, nullptr, &cb) != ERROR_SUCCESS || cb == 0) {
            RegCloseKey(hKey);
            return false;
        }

        std::vector<char> buf(cb);
        if (RegQueryValueExA(hKey, "Creds", nullptr, nullptr, reinterpret_cast<BYTE*>(buf.data()), &cb) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
        RegCloseKey(hKey);

        xorCipher(buf);
        std::string s(buf.begin(), buf.end());

        auto extract = [&](const char* key) {
            auto p = s.find(key);
            if (p == std::string::npos) return std::string();
            p = s.find('"', p + strlen(key) + 3);
            auto e = s.find('"', p + 1);
            return s.substr(p+1, e-p-1);
        };

        auto lic = extract("license");
        auto hw  = extract("hwid");
        if (lic.empty() || hw.empty()) return false;

        strncpy_s(licenseKey, licSz, lic.c_str(), lic.size());
        strncpy_s(savedHwid, sizeof(savedHwid), hw.c_str(), hw.size());
        return true;
    }
    
    void ClearCredentials() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueA(hKey, "Creds");
            RegCloseKey(hKey);
        }
    }
    
    bool IsAuthenticated() {
        return isAuthenticated;
    }
    
    std::string GetTimeRemaining() {
        if (KeyAuthApp.user_data.subscriptions.empty()) {
            return "N/A";
        }
        
        auto &sub = KeyAuthApp.user_data.subscriptions[0];
        bool isNumeric = std::all_of(sub.expiry.begin(), sub.expiry.end(), ::isdigit);
        if (isNumeric) {
            long expTs = std::stol(sub.expiry);
            long now   = long(std::time(nullptr));
            long diff  = expTs - now;
            if (diff > 0) {
                int days    = int(diff / 86400);
                int hours   = int((diff % 86400) / 3600);
                int mins    = int((diff % 3600) / 60);
                return std::to_string(days) + "d " + std::to_string(hours) + "h " + std::to_string(mins) + "m";
            } else {
                return "Expired";
            }
        }
        return "N/A";
    }
    
    void Logout() {
        ClearCredentials();
        isAuthenticated = false;
        strcpy_s(License, "Enter Your License Key");
        strcpy_s(statusmsg, "");
        savedHwid[0] = '\0';
        gTriedAuto = false;
        gHasInitialized = false;
    }
}

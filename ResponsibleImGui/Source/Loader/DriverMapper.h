#pragma once
#include <Windows.h>
#include <string>
#include <vector>

class DriverMapper {
public:
    static bool MapDriver();
    static bool IsDriverLoaded();
    static void CleanupTempFiles();

private:
    static bool ExtractResource(const unsigned char* data, unsigned int size, const std::wstring& filePath);
    static bool ExecuteKdmapper(const std::wstring& kdmapperPath, const std::wstring& driverPath);
    static std::wstring GetTempDirectory();
    static bool FileExists(const std::wstring& filePath);
    
    // Static member variables to track temp file paths
    static std::wstring s_tempKdmapperPath;
    static std::wstring s_tempDriverPath;
    static bool s_tempFilesCreated;
};

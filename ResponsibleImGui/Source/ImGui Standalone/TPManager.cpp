#include "pch.h"
#include "TPManager.h"
#include "DriverComm.h"
#include "FeaturesDecl.h" // Using our minimal header instead of Features.h
#include <iostream>
#include <string>
#include <cstdio>

namespace TPManager {
    std::filesystem::path folder;
    std::vector<std::string> configs;
    std::vector<TPEntry> cycleList;
    int loadedConfigIdx = -1;
    int loadedConfigIdxActive = -1;
    int currentCycleIdx = 0;
    bool arrowDebounce = false;
    char configNameBuf[64] = {};
    char tpNameBuf[64] = "";
    std::string lastTPName = "None";
    std::string coordsStr = "N/A";
    std::string viewStr = "N/A";
    std::chrono::steady_clock::time_point lastStatusUpdate{};

    // Editor State
    char editName[64] = "";
    float editX = 0.0f, editY = 0.0f, editZ = 0.0f;
    float editViewX = 0.0f, editViewY = 0.0f;
    int lastEditIdx = -1;

    void InitFolder() {
        char* userProfile = nullptr;
        size_t len = 0;
        // use _dupenv_s instead of getenv
        if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0 || !userProfile) {
            // fallback if env lookup failed
            folder = std::filesystem::current_path() / "Hatemob" / "TPs";
        }
        else {
            folder = std::filesystem::path(userProfile)
                / "Documents" / "Hatemob" / "TPs";
            free(userProfile);
        }

        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
    }

    void RefreshConfigList() {
        configs.clear();
        for (auto& e : std::filesystem::directory_iterator(folder)) {
            if (e.path().extension() == ".json")
                configs.push_back(e.path().stem().string());
        }
    }

    void ReadConfig(const std::string& name) {
        cycleList.clear();
        std::ifstream f(folder / (name + ".json"));
        if (!f.is_open()) return;
        nlohmann::json j; f >> j;
        for (auto& item : j) {
            TPEntry t;
            t.name = item.value("name", "");
            t.x = item.value("x", 0.0f);
            t.y = item.value("y", 0.0f);
            t.z = item.value("z", 0.0f);
            t.viewX = item.value("viewX", 0.0f);
            t.viewY = item.value("viewY", 0.0f);
            cycleList.push_back(t);
        }
        lastTPName = "None";
        currentCycleIdx = 0;
    }

    void WriteConfig(const std::string& name) {
        nlohmann::json j = nlohmann::json::array();
        for (auto& t : cycleList) {
            j.push_back({
                {"name",  t.name},
                {"x",     t.x},
                {"y",     t.y},
                {"z",     t.z},
                {"viewX", t.viewX},
                {"viewY", t.viewY}
                });
        }
        std::ofstream f(folder / (name + ".json"));
        if (f.is_open()) f << j.dump(4);
    }

    void LoadEditorFields(int idx) {
        if (idx < 0 || idx >= (int)cycleList.size()) return;
        const auto& tp = cycleList[idx];
        strcpy_s(editName, tp.name.c_str());
        editX = tp.x;
        editY = tp.y;
        editZ = tp.z;
        editViewX = tp.viewX;
        editViewY = tp.viewY;
        lastEditIdx = idx;
    }

    void ClearEditorFields() {
        editName[0] = '\0';
        editX = editY = editZ = 0.0f;
        editViewX = editViewY = 0.0f;
        lastEditIdx = -1;
    }

    void ApplyEditorChanges() {
        if (lastEditIdx < 0 || lastEditIdx >= (int)cycleList.size()) return;
        auto& tp = cycleList[lastEditIdx];
        tp.name = editName;
        tp.x = editX;
        tp.y = editY;
        tp.z = editZ;
        tp.viewX = editViewX;
        tp.viewY = editViewY;

        WriteConfig(configs[loadedConfigIdx]);
    }

    void TeleportTo(int idx, HANDLE driver) {
        if (!LocalPlayer::Enabled)
            return;

        auto base = LocalPlayer::realPlayer.load();
        auto viewBase = ViewAngles::addr;
        float velX = 0.0f, velY = 0.0f, velZ = 10.0f;
        if (!base || !viewBase || cycleList.empty() || idx < 0 || idx >= (int)cycleList.size())
            return;

        const auto& e = cycleList[idx];
        // position
        WriteMem(driver, (base + POS_X), e.x);
        WriteMem(driver, (base + POS_Y), e.y);
        WriteMem(driver, (base + POS_Z), e.z);
        // velocity
        if (LocalPlayer::flyEnabled)
        {
            WriteMem(driver, (base + VEL_X), velX);
            WriteMem(driver, (base + VEL_Y), velY);
            WriteMem(driver, (base + VEL_Z), velZ);
        }
        else {
            velZ = 2.0f;
            WriteMem(driver, (base + VEL_Z), velZ);
        }
        
        // view angles
        WriteMem(driver, (viewBase + VIEW_X), e.viewX);
        WriteMem(driver, (viewBase + VIEW_Y), e.viewY);

        lastTPName = e.name;
    }    void UpdateStatus() {
        if (!LocalPlayer::Enabled)
            return;        // Only access g_cachedCoords
        auto coords = LocalPlayer::g_cachedCoords.load();
        coordsStr = std::format("{:.3f}, {:.3f}, {:.3f}", coords.x, coords.y, coords.z);
        viewStr = "N/A";
    }    void Poll(HANDLE driver, DWORD pid) {
        if (!LocalPlayer::Enabled)
            return;

        // Use cached values only — no memory access here
        auto base = LocalPlayer::realPlayer.load();
        auto viewBase = ViewAngles::addr; // Use addr instead of g_viewBase which is static
        if (!base || !viewBase || cycleList.empty())
            return;

        // Handle cycling via arrow keys
        bool right = (GetAsyncKeyState(VK_RIGHT) & 0x8000) != 0;
        bool left = (GetAsyncKeyState(VK_LEFT) & 0x8000) != 0;

        if ((right || left) && !arrowDebounce) {
            currentCycleIdx = right
                ? (currentCycleIdx + 1) % cycleList.size()
                : (currentCycleIdx - 1 + cycleList.size()) % cycleList.size();
            TeleportTo(currentCycleIdx, driver);
            arrowDebounce = true;
        }
        if (!right && !left) arrowDebounce = false;        // Optional: Status logging (throttled)
        auto now = std::chrono::steady_clock::now();
        if (now - lastStatusUpdate > std::chrono::milliseconds(500)) {
            // Can't access static g_cachedAngles directly
            std::cout << "[+] View angles: not accessible (static in Features.h)\n";
            lastStatusUpdate = now;
        }
    }

    // Function to render the TP tab in ImGui
    void RenderTPTab(HANDLE driver, DWORD pid) {
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImVec2 size = ImGui::GetContentRegionAvail();
        size.y = 320;
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
        ImGui::Dummy(ImVec2(0, 10));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
        ImGui::Text("TP Options:");

        if (!LocalPlayer::Enabled) {
            ImGui::TextDisabled("Enable LocalPlayer hook to use Teleports");
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::SetNextItemWidth(200.0f);
            ImGui::InputText("##Config Name", configNameBuf, sizeof(configNameBuf));
            // If input is empty, draw a placeholder on top of it
            if (configNameBuf[0] == '\0') {
                ImVec2 pos = ImGui::GetItemRectMin();
                ImVec2 text_pos = ImVec2(pos.x + ImGui::GetStyle().FramePadding.x,
                    pos.y + ImGui::GetStyle().FramePadding.y);
                ImGui::GetWindowDrawList()->AddText(
                    text_pos,
                    ImGui::GetColorU32(ImGuiCol_TextDisabled),
                    "Enter config name..."
                );
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::Button("Create")) {
                std::string nm{ configNameBuf };
                if (!nm.empty()) {
                    cycleList.clear();
                    WriteConfig(nm);
                    RefreshConfigList();
                    loadedConfigIdx =
                        int(std::find(
                            configs.begin(),
                            configs.end(),
                            nm
                        ) - configs.begin());
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh")) {
                RefreshConfigList();
            }
            const char* curConfig = loadedConfigIdx >= 0
                ? configs[loadedConfigIdx].c_str()
                : "Select config";
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::SetNextItemWidth(200.0f);
            if (ImGui::BeginCombo("##Configs", curConfig)) {
                for (int i = 0; i < (int)configs.size(); ++i)
                {
                    bool isSel = (i == loadedConfigIdx);
                    if (ImGui::Selectable(configs[i].c_str(), isSel))
                        loadedConfigIdx = i;
                    if (isSel)
                        ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(loadedConfigIdx < 0);
            if (ImGui::Button("Load")) {
                ReadConfig(
                    configs[loadedConfigIdx]
                );
                loadedConfigIdxActive = loadedConfigIdx;
            }
            ImGui::SameLine();
            if (ImGui::Button("Unload")) {
                cycleList.clear();
                currentCycleIdx = 0;
                lastTPName = "None";
                loadedConfigIdxActive = -1;
            }
            ImGui::SameLine();
            if (ImGui::Button("Reset Index")) {
                currentCycleIdx = 0;
            }
            ImGui::EndDisabled();
            // Store current vertical position
            float rightBlockY = 75.0f;
            float rightBlockX = ImGui::GetWindowWidth() * 0.5f + 20.0f; // Tweak as needed

            // Position cursor to right side
            ImGui::SetCursorPos(ImVec2(rightBlockX, rightBlockY));

            // Begin a vertical group so all the following items stay together
            ImGui::BeginGroup();
            ImGui::Text("Loaded: %s",
                loadedConfigIdxActive >= 0
                ? configs[loadedConfigIdxActive].c_str()
                : "None"
            );
            ImGui::Text("Current TP Index: %d", currentCycleIdx);
            ImGui::Text("Last TP: %s", lastTPName.c_str());
            UpdateStatus();
            ImGui::Text("Coords: %s", coordsStr.c_str());
            ImGui::Text("View : %s", viewStr.c_str());
            ImGui::EndGroup();
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Text("Teleport Entries:");
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.180f, 0.180f, 0.180f, 1.0f));
            if (ImGui::ListBoxHeader("##Tplist", (int)cycleList.size(), 6)) {
                for (int i = 0; i < (int)cycleList.size(); ++i) {
                    const bool selected = (i == currentCycleIdx);
                    if (ImGui::Selectable(
                        cycleList[i].name.c_str(),
                        selected
                    ))
                    {
                        currentCycleIdx = i;
                        LoadEditorFields(i);
                    }
                }
                ImGui::ListBoxFooter();
                ImGui::PopStyleColor(2);
            }
            ImGui::SameLine();
            ImGui::BeginGroup();
            ImGui::Text("Edit Selected TP");
            if (lastEditIdx >= 0 && lastEditIdx < (int)cycleList.size()) {
                ImGui::PushItemWidth(180);
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::InputText("Name", editName, sizeof(editName));
                ImGui::InputFloat("X", &editX);
                ImGui::InputFloat("Y", &editY);
                ImGui::InputFloat("Z", &editZ);
                ImGui::InputFloat("ViewX", &editViewX);
                ImGui::InputFloat("ViewY", &editViewY);
                ImGui::PopStyleColor();
                ImGui::PopItemWidth();
                if (ImGui::Button("Apply Changes")) {
                    if (strlen(editName) == 0) {
                        ImGui::OpenPopup("NameError");
                    }
                    else {
                        ApplyEditorChanges();
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset Fields")) {
                    LoadEditorFields(lastEditIdx);
                }
                if (ImGui::BeginPopup("NameError")) {
                    ImGui::Text("Name cannot be empty!");
                    if (ImGui::Button("OK")) ImGui::CloseCurrentPopup();
                    ImGui::EndPopup();
                }
            }
            ImGui::EndGroup();
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::InputText("##NewTPName", tpNameBuf, sizeof(tpNameBuf));
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::Button("Save TP") && loadedConfigIdx >= 0)
            {
                uintptr_t base = LocalPlayer::realPlayer.load();
                uintptr_t viewBase = ViewAngles::addr;
                TPManager::TPEntry e;
                e.name = tpNameBuf[0]
                    ? std::string(tpNameBuf)
                    : ("TP" + std::to_string(cycleList.size() + 1));
                ReadMem(driver, pid, base + POS_X, e.x);
                ReadMem(driver, pid, base + POS_Y, e.y);
                ReadMem(driver, pid, base + POS_Z, e.z);
                if (viewBase) {
                    ReadMem(driver, pid, (viewBase + VIEW_X), e.viewX);
                    ReadMem(driver, pid, (viewBase + VIEW_Y), e.viewY);
                }
                else {
                    e.viewX = e.viewY = 0.0f;
                }
                cycleList.push_back(e);
                WriteConfig(configs[loadedConfigIdx]);
                tpNameBuf[0] = '\0';
                currentCycleIdx = (int)cycleList.size() - 1;
            }
            ImGui::SameLine();
            if (ImGui::Button("Delete TP") &&
                currentCycleIdx >= 0 &&
                currentCycleIdx < (int)cycleList.size())
            {
                cycleList.erase(
                    cycleList.begin() + currentCycleIdx
                );
                WriteConfig(
                    configs[loadedConfigIdx]
                );
                ReadConfig(
                    configs[loadedConfigIdx]
                );
                if (currentCycleIdx >= (int)cycleList.size())
                    currentCycleIdx =
                    (int)cycleList.size() - 1;
            }
            if (currentCycleIdx >= (int)cycleList.size())
                currentCycleIdx = (int)cycleList.size() - 1;
            if (lastEditIdx >= (int)cycleList.size())
                ClearEditorFields();
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
            if (ImGui::ArrowButton("Up##tp", ImGuiDir_Up) &&
                currentCycleIdx > 0)
            {
                std::swap(
                    cycleList[currentCycleIdx],
                    cycleList[currentCycleIdx - 1]
                );
                --currentCycleIdx;
                WriteConfig(
                    configs[loadedConfigIdx]
                );
                ReadConfig(
                    configs[loadedConfigIdx]
                );
            }
            ImGui::SameLine();
            if (ImGui::ArrowButton("Down##tp", ImGuiDir_Down) &&
                currentCycleIdx + 1 < (int)cycleList.size())
            {
                std::swap(
                    cycleList[currentCycleIdx],
                    cycleList[currentCycleIdx + 1]
                );
                ++currentCycleIdx;
                WriteConfig(
                    configs[loadedConfigIdx]
                );
                ReadConfig(
                    configs[loadedConfigIdx]
                );
            }
            ImGui::PopStyleVar();
        }
    }
}

#include "Drawing.h"
#include <ctime>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include "DriverComm.h"
#include <algorithm>  // for std::copy_n
#include <iterator>   // for std::begin / std::size

#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <string.h>
#include <cwchar>
#include <cstdint>
#include <vector>
#include "Features.h"
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <ShlObj.h>
#include "themes.h"
#include "imgui/imgui_custom.h"
#include "TPManager.h"
#include "fonts/font_globals.h"

#include <iomanip>



// Global instruction toggles
static bool wasKillauraEnabled = false;
static bool wasViewAnglesEnabled = false;
static bool wasLocalPlayerEnabled = false;
static bool wasGhostmodeEnabled = false;
static bool wasGodmodeEnabled = false;
static bool wasInfAmmoEnabled = false;
static bool wasDmgMultEnabled = false;
static bool wasFOVEnabled = false;
static bool wasRPMEnabled = false;
static bool wasNoRecoilEnabled = false;
static bool wasOHKEnabled = false;
static bool wasNoJoiningAlliesEnabled = false;
static bool wasNoTurnBackEnabled = false;
static bool wasSparrowAnywhereEnabled = false;
static bool wasInfStacksEnabled = false;
static bool wasNoRezTokensEnabled = false;
static bool wasInstaRespawnEnabled = false;
static bool wasShootThruWallsEnabled = false;
static bool wasChamsEnabled = false;
static bool wasImmuneBossesEnabled = false;
static bool wasAbilityChargeEnabled = false;
static bool wasImmuneAuraEnabled = false;
static bool wasIcarusDashEnabled = false;
static bool wasInstantInteractEnabled = false;
static bool wasLobbyCrasherEnabled = false;
static bool wasGSizeEnabled = false;
static bool wasOxygenEnabled = false;
static bool wasInfSparrowBoostEnabled = false;
static bool wasInteractThruWallsEnabled = false;
static bool wasAntiFlinchEnabled = false;
static bool wasInfBuffTimersEnabled = false;
static bool wasMag999Enabled = false;
static bool wasInfExoticBuffTimersEnabled = false;

// at top of Drawing.cpp
static bool wasFlyEnabled = false;
static bool wasFlyKeyDown = false;
uintptr_t moduleBaseAddress = 0;

inline void LimitFPS(double targetFPS = 90.0)
{
    using namespace std::chrono;
    static auto lastTime = high_resolution_clock::now();
    constexpr microseconds spinThreshold{ 2000 }; // 2 ms spin-wait threshold

    // how long each frame should take
    const auto frameDuration = microseconds(static_cast<long long>(1e6 / targetFPS));

    auto now = high_resolution_clock::now();
    auto elapsed = duration_cast<microseconds>(now - lastTime);

    if (elapsed < frameDuration)
    {
        auto toSleep = frameDuration - elapsed;
        // sleep for most of the remaining time...
        if (toSleep > spinThreshold)
            std::this_thread::sleep_for(toSleep - spinThreshold);
        // …then spin-wait the rest
        while (duration_cast<microseconds>(high_resolution_clock::now() - lastTime) < frameDuration)
            std::this_thread::yield();
    }

    lastTime = high_resolution_clock::now();
}


void PollFly(HANDLE driver, DWORD pid, uintptr_t destinyBase)
{
    // 1) Toggle FlyEnabled on key press:
    bool flyKeyDown = (GetAsyncKeyState(Hotkeys["FlyToggle"]) & 0x8000) != 0;
    if (flyKeyDown && !wasFlyKeyDown && LocalPlayer::Enabled)
        FlyEnabled = !FlyEnabled;
    wasFlyKeyDown = flyKeyDown;

    // 2) Start/stop your fly thread when FlyEnabled flips:
    if (FlyEnabled && !wasFlyEnabled)
    {
        InjectCodecave(driver, pid, LocalPlayer::disableGravAddress, LocalPlayer::disableGravShellcode, 5, LocalPlayer::disableGravMemAllocatedAddress);
        StopFlyThread = false;
        FlyThread = std::thread(FlyLoop, driver, pid, destinyBase);
        FlyThread.detach();
        std::cout << "[Fly] Started\n";
    }
    else if (!FlyEnabled && wasFlyEnabled)
    {
        StopFlyThread = true;
        std::cout << "[Fly] Stopping…\n";
        WriteMem(driver, LocalPlayer::disableGravAddress, LocalPlayer::disableGravOrigBytes);
        // your FlyLoop should periodically check StopFlyThread and exit cleanly
    }
    wasFlyEnabled = FlyEnabled;
}

void PollKillKey(HANDLE driver, DWORD pid) {
    if (!LocalPlayer::Enabled                // overall local-player master switch
        || !LocalPlayer::KillKeyEnabled         // ← new gate
        || !LocalPlayer::realPlayer.load())     // addr not yet found
        return;

    bool keyNowDown = GetAsyncKeyState(LocalPlayer::KillKey) & 0x8000;

    if (keyNowDown && !LocalPlayer::KillKeyWasDown) {
        uintptr_t playerBase = LocalPlayer::realPlayer.load();
        const uintptr_t posOffset = 0x1C0;
        const uintptr_t velOffset = 0x230;

        float newX = -10000.0f;
        float newY = -10000.0f;
        float newVel = 10.0f;

        // Write X and Y only — leave Z unchanged
        WriteMem(driver, (playerBase + posOffset), newX);
        WriteMem(driver, (playerBase + posOffset + 4), newY);

        // Set velocity to 10.0 in all directions
        WriteMem(driver, (playerBase + velOffset), newVel);
        WriteMem(driver, (playerBase + velOffset + 4), newVel);
        WriteMem(driver, (playerBase + velOffset + 8), newVel);

        std::cout << "[KillKey] Player killed to X/Y = -10000, velocity = 10\n";
    }

    LocalPlayer::KillKeyWasDown = keyNowDown;
}

void RenderKillKeyUI() {
    // 1) Ensure we have a default binding
    if (Hotkeys["SuicideKey"] == 0)
        Hotkeys["SuicideKey"] = LocalPlayer::KillKey;         // Default VK_J :contentReference[oaicite:0]{index=0}

    ImGui::BeginDisabled(!LocalPlayer::Enabled);

    // 2) Checkbox + picker on one line
    ImGui::Toggle("Suicide Key", &LocalPlayer::KillKeyEnabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("SuicideKey", "Key", listening);         // auto-saves to hotkeys.json :contentReference[oaicite:1]{index=1}

    ImGui::EndDisabled();
}

void RenderAbilityChargeUI() {
    // 1. Ensure we have a default binding
    if (Hotkeys["AbilityCharge"] == 0)
        Hotkeys["AbilityCharge"] = VK_5;

    // 2. Checkbox + picker on one line
    ImGui::Toggle("Ability", &AbilityCharge::Enabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("Ability", "Key", listening);
}

// Polls once per frame to inject/restore based on key-hold
void PollAbilityCharge(HANDLE driver, DWORD pid) {
    static bool wasInjected = false;   // tracks if we currently have injected shellcode
    static bool wasKeyDown = false;

    int vk = Hotkeys["AbilityCharge"];
    if (vk == 0) return;               // no key bound

    // 1) If the checkbox is OFF, restore (if we had injected) then bail
    if (!AbilityCharge::Enabled) {
        if (wasInjected) {
            WriteMem(
                driver,
                AbilityCharge::InstructionAddress,
                AbilityCharge::origBytes);
            wasInjected = false;
            std::cout << "[AbilityCharge] Feature disabled—restored original bytes\n";
        }
        wasKeyDown = false;
        return;
    }

    // 2) Checkbox is ON → poll the key
    bool isKeyDown = (GetAsyncKeyState(vk) & 0x8000) != 0;

    // on key-down → inject (if not already)
    if (isKeyDown && !wasKeyDown) {
        InjectCodecave(
            driver,
            pid,
            AbilityCharge::InstructionAddress,
            AbilityCharge::shellcode,
            /*origSize=*/7,
            AbilityCharge::memAllocatedAddress
        );
        wasInjected = true;
        std::cout << "[AbilityCharge] Activated\n";
    }
    // on key-up → restore (if injected)
    else if (!isKeyDown && wasKeyDown && wasInjected) {
        WriteMem(
            driver,
            AbilityCharge::InstructionAddress,
            AbilityCharge::origBytes);
        wasInjected = false;
        std::cout << "[AbilityCharge] Deactivated\n";
    }

    wasKeyDown = isKeyDown;
}

void RenderImmuneBossesUI() {    // ImGui::Toggle only works with bool*, so snapshot/store atomics here:
    bool state = ImmuneBosses::Enabled.load();
    if (ImGui::Toggle("Immune Bosses", &state)) {
        ImmuneBosses::Enabled.store(state);
    }

    // show a “scanning…” notice if the thread is running but hasn't found the address yet
    if (ImmuneBosses::ThreadRunning.load() && ImmuneBosses::Address == 0) {
        ImGui::TextDisabled("Scanning memory...");
    }
}

void PollImmuneBosses(HANDLE driver, DWORD pid) {
    bool nowEnabled = ImmuneBosses::Enabled.load();

    // just got toggled ON?
    if (nowEnabled && !wasImmuneBossesEnabled && !ImmuneBosses::ThreadRunning.load()) {
        // kick off your scan thread
        std::thread(ImmuneBossesThread, driver, pid).detach();
    }
    // just got toggled OFF?
    else if (!nowEnabled && wasImmuneBossesEnabled) {
        // if we have an Address, restore the original float
        if (ImmuneBosses::Address != 0) {
            float one = 1.0f;
            if (WriteMem(
                driver,
                ImmuneBosses::Address,
                one
            )) {
                std::cout << "[+] Immune Bosses restored to 1.0f\n";
            }
            else {
                std::cerr << "[-] Failed to restore Immune Bosses: "
                    << GetLastError() << "\n";
            }
            ImmuneBosses::Address = 0;
        }
    }

    wasImmuneBossesEnabled = nowEnabled;
}

void RenderGameSpeedUI() {
    // ensure a default if nothing’s been bound yet
    if (Hotkeys["GameSpeed"] == 0)
        Hotkeys["GameSpeed"] = VK_F;

    // draw the enable checkbox and picker on one line
    ImGui::Toggle("GameSpeed", &GameSpeed::Enabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("GameSpeed", "", listening);

    // optional sliders/info below
}

void PollGameSpeed(HANDLE driver) {
    // bail out if the feature is switched off
    if (!GameSpeed::Enabled)
        return;

    int vk = Hotkeys["GameSpeed"];
    if (vk == 0) return;  // nothing bound yet

    // detect press / release
    bool isDown = (GetAsyncKeyState(vk) & 0x8000) != 0;
    if (isDown != GameSpeed::WasKeyDown) {
        // choose value
        float value = isDown
            ? GameSpeed::FastValue  // e.g. 9000.0f
            : GameSpeed::NormalValue;

        // patch memory
        SIZE_T written = 0;
        if (!WriteMem(
            driver,
            GameSpeed::Address,
            value)) {
            std::cerr << "[GameSpeed] Write failed\n";
        }
        else {
            std::cout << "[GameSpeed] Set to " << value << "\n";
        }

        GameSpeed::WasKeyDown = isDown;
    }
}

// this runs in the background at ~60 Hz


void DisableViewAngleHook(HANDLE driver) {
    ViewAngles::g_cacheThreadRunning = false;
    WriteMem(driver, ViewAngles::InstructionAddress, ViewAngles::origBytes);
}

void UpdateFeatureStates(HANDLE driver, DWORD pid)
{
    // LOCALPLAYER 
    if (LocalPlayer::Enabled && !wasLocalPlayerEnabled)
    {
        EnableLocalPlayerHook(driver, pid);
        EnableViewAngleHook(driver, pid);
         
        // ✅ Start background player finder
        g_StopFindThread = false;
        g_FindPlayerEnabled = true;
        g_FindPlayerThread = std::thread(AutoFindPlayerLoop, driver, pid,
            moduleBaseAddress + LocalPlayer::destinyBase,
            std::ref(LocalPlayer::realPlayer)  // ⚠️ pass by reference!
        );                    g_FindPlayerThread.detach(); // optional — see note below

        std::cout << "[+] Hook enabled and player finder thread started\n";
    }
    else if (!LocalPlayer::Enabled && wasLocalPlayerEnabled)
    {
        // 🧹 Restore original instruction
        WriteMem(driver, LocalPlayer::InstructionAddress, LocalPlayer::origBytes);
        DisableViewAngleHook(driver);

        // 🛑 Stop background player finder
        g_FindPlayerEnabled = false;
        g_StopFindThread = true;

        std::cout << "[-] Hook disabled and player finder thread stopped (clean exit will follow)\n";
    }
    wasLocalPlayerEnabled = LocalPlayer::Enabled;


    // KILLAURA
    if (Killaura::Enabled && !wasKillauraEnabled)
    {
        InjectCodecave(driver, pid, Killaura::InstructionAddress, Killaura::shellcode, 5, Killaura::memAllocatedAddress);
        std::cout << "[+] Killaura enabled\n";
    }
    else if (!Killaura::Enabled && wasKillauraEnabled)
    {
        WriteMem(driver, Killaura::InstructionAddress, Killaura::origBytes);
    }

    wasKillauraEnabled = Killaura::Enabled;


    // GHOSTMODE
    if (Ghostmode::Enabled && !wasGhostmodeEnabled) {
        InjectCodecave(driver, pid, Ghostmode::InstructionAddress, Ghostmode::shellcode, 6, Ghostmode::memAllocatedAddress);
        std::cout << "[+] Ghostmode enabled\n";
    }
    else if (!Ghostmode::Enabled && wasGhostmodeEnabled)
    {
        WriteMem(driver, Ghostmode::InstructionAddress, Ghostmode::origBytes);
    }
    wasGhostmodeEnabled = Ghostmode::Enabled;


    // GODMODE
    if (Godmode::Enabled && !wasGodmodeEnabled) {
        InjectCodecave(driver, pid, Godmode::InstructionAddress, Godmode::shellcode, 5, Godmode::memAllocatedAddress);
        std::cout << "[+] Godmode enabled\n";
    }
    else if (!Godmode::Enabled && wasGodmodeEnabled)
    {
        WriteMem(driver, Godmode::InstructionAddress, Godmode::origBytes);
    }
    wasGodmodeEnabled = Godmode::Enabled;


    // INF AMMO
    if (InfAmmo::Enabled && !wasInfAmmoEnabled)
    {
        EnableInfiniteAmmo(driver, pid);
        WriteMem(driver, InfSwordAmmo::InstructionAddress, InfSwordAmmo::nops);
    }
    else if (!InfAmmo::Enabled && wasInfAmmoEnabled)
    {
        WriteMem(driver, InfAmmo::InstructionAddress, InfAmmo::origBytes);
        WriteMem(driver, InfSwordAmmo::InstructionAddress, InfSwordAmmo::origBytes);
    }
    wasInfAmmoEnabled = InfAmmo::Enabled;


    // RPM
    if (RPM::Enabled && !wasRPMEnabled)
    {
        InjectCodecave(driver, pid, RPM::InstructionAddress, RPM::shellcode, 8, RPM::memAllocatedAddress);
        std::cout << "[+] RPM Enabled\n";
    }
    else if (!RPM::Enabled && wasRPMEnabled)
    {
        WriteMem(driver, RPM::InstructionAddress, RPM::origBytes);
    }
    wasRPMEnabled = RPM::Enabled;


    // DMG MULTIPLIER
    if (dmgMult::Enabled && !wasDmgMultEnabled)
    {
        InjectCodecave(driver, pid, dmgMult::InstructionAddress, dmgMult::shellcode, 6, dmgMult::memAllocatedAddress);
        std::cout << "[+] Dmg Mult enabled\n";
    }
    else if (!dmgMult::Enabled && wasDmgMultEnabled)
    {
        WriteMem(driver, dmgMult::InstructionAddress, dmgMult::origBytes);
    }
    wasDmgMultEnabled = dmgMult::Enabled;


    // IMMUNE AURA
    if (ImmuneAura::Enabled && !wasImmuneAuraEnabled)
    {
        InjectCodecave(driver, pid, ImmuneAura::InstructionAddress, ImmuneAura::shellcode, 7, ImmuneAura::memAllocatedAddress);
    }
    else if (!ImmuneAura::Enabled && wasImmuneAuraEnabled)
    {
        WriteMem(driver, ImmuneAura::InstructionAddress, ImmuneAura::origBytes);
    }
    wasImmuneAuraEnabled = ImmuneAura::Enabled;


    // NO RECOIL
    if (NoRecoil::Enabled && !wasNoRecoilEnabled)
    {
        InjectCodecave(driver, pid, NoRecoil::InstructionAddress, NoRecoil::shellcode, 7, NoRecoil::memAllocatedAddress);
        std::cout << "[+] No Recoil enabled\n";
    }
    else if (!NoRecoil::Enabled && wasNoRecoilEnabled)
    {
        WriteMem(driver, NoRecoil::InstructionAddress, NoRecoil::origBytes);
    }
    wasNoRecoilEnabled = NoRecoil::Enabled;


    // SHOOT THRU WALLS
    if (ShootThru::Enabled && !wasShootThruWallsEnabled)
    {
        WriteMem(driver, ShootThru::InstructionAddress, ShootThru::nops);
    }
    else if (!ShootThru::Enabled && wasShootThruWallsEnabled)
    {
        WriteMem(driver, ShootThru::InstructionAddress, ShootThru::origBytes);
    }
    wasShootThruWallsEnabled = ShootThru::Enabled;


    // ONE HIT KILL OHK
    if (OHK::Enabled && !wasOHKEnabled)
    {
        InjectCodecave(driver, pid, OHK::InstructionAddress, OHK::shellcode, 6, OHK::memAllocatedAddress);
        std::cout << "[+] OHK enabled\n";
    }
    else if (!OHK::Enabled && wasOHKEnabled)
    {
        WriteMem(driver, OHK::InstructionAddress, OHK::origBytes);
    }
    wasOHKEnabled = OHK::Enabled;


    // NO JOINING ALLIES
    if (NoJoinAllies::Enabled && !wasNoJoiningAlliesEnabled)
    {
        WriteMem(driver, NoJoinAllies::InstructionAddress, NoJoinAllies::nops);
    }
    else if (!NoJoinAllies::Enabled && wasNoJoiningAlliesEnabled)
    {
        WriteMem(driver, NoJoinAllies::InstructionAddress, NoJoinAllies::origBytes);
    }
    wasNoJoiningAlliesEnabled = NoJoinAllies::Enabled;


    // NO TURN BACK
    if (NoTurnBack::Enabled && !wasNoTurnBackEnabled)
    {
        WriteMem(driver, NoTurnBack::InstructionAddress, NoTurnBack::nops);
    }
    else if (!NoTurnBack::Enabled && wasNoTurnBackEnabled)
    {
        WriteMem(driver, NoTurnBack::InstructionAddress, NoTurnBack::origBytes);
    }
    wasNoTurnBackEnabled = NoTurnBack::Enabled;


    // INFINITE REZ TOKENS
    if (NoRezTokens::Enabled && !wasNoRezTokensEnabled)
    {
        WriteMem(driver, NoRezTokens::InstructionAddress, NoRezTokens::myByte);
    }
    else if (!NoRezTokens::Enabled && wasNoRezTokensEnabled)
    {
        WriteMem(driver, NoRezTokens::InstructionAddress, NoRezTokens::origByte);
    }
    wasNoRezTokensEnabled = NoRezTokens::Enabled;


    // RESPAWN ANYWHERE
    if (InstaRespawn::Enabled && !wasInstaRespawnEnabled)
    {
        InjectCodecave(driver, pid, RespawnAnywhere::InstructionAddress, RespawnAnywhere::shellcode, 7, RespawnAnywhere::memAllocatedAddress);
        WriteMem(driver, InstaRespawn::InstructionAddress, InstaRespawn::myBytes);
    }
    else if (!InstaRespawn::Enabled && wasInstaRespawnEnabled)
    {
        WriteMem(driver, InstaRespawn::InstructionAddress, InstaRespawn::origBytes);
        WriteMem(driver, RespawnAnywhere::InstructionAddress, RespawnAnywhere::origBytes);
    }
    wasInstaRespawnEnabled = InstaRespawn::Enabled;


    // INFINITE STACKS
    if (InfStacks::Enabled && !wasInfStacksEnabled)
    {
        InjectCodecave(driver, pid, InfStacks::InstructionAddress, InfStacks::shellcode, 5, InfStacks::memAllocatedAddress);
    }
    else if (!InfStacks::Enabled && wasInfStacksEnabled)
    {
        WriteMem(driver, InfStacks::InstructionAddress, InfStacks::origBytes);
    }
    wasInfStacksEnabled = InfStacks::Enabled;


    // INSTANT INTERACT
    if (InstantInteract::Enabled && !wasInstantInteractEnabled)
    {
        InjectCodecave(driver, pid, InstantInteract::InstructionAddress, InstantInteract::shellcode, 5, InstantInteract::memAllocatedAddress);
    }
    else if (!InstantInteract::Enabled && wasInstantInteractEnabled)
    {
        WriteMem(driver, InstantInteract::InstructionAddress, InstantInteract::origBytes);
    }
    wasInstantInteractEnabled = InstantInteract::Enabled;


    // SPARROW ANYWHERE
    if (SparrowAnywhere::Enabled && !wasSparrowAnywhereEnabled)
    {
        WriteMem(driver, SparrowAnywhere::InstructionAddress, SparrowAnywhere::mybyte);
    }
    else if (!SparrowAnywhere::Enabled && wasSparrowAnywhereEnabled)
    {
        WriteMem(driver, SparrowAnywhere::InstructionAddress, SparrowAnywhere::origByte);
    }
    wasSparrowAnywhereEnabled = SparrowAnywhere::Enabled;


    // CHAMS
    if (Chams::Enabled && !wasChamsEnabled)
    {
        InjectCodecave(driver, pid, Chams::InstructionAddress, Chams::shellcode, 7, Chams::memAllocatedAddress);
    }
    else if (!Chams::Enabled && wasChamsEnabled)
    {
        WriteMem(driver, Chams::InstructionAddress, Chams::origBytes);
    }
    wasChamsEnabled = Chams::Enabled;


    // INFINITE ICARUS DASH
    if (IcarusDash::Enabled && !wasIcarusDashEnabled)
    {
        WriteMem(driver, IcarusDash::InstructionAddress, IcarusDash::nops);
    }
    else if (!IcarusDash::Enabled && wasIcarusDashEnabled)
    {
        WriteMem(driver, IcarusDash::InstructionAddress, IcarusDash::origBytes);
    }
    wasIcarusDashEnabled = IcarusDash::Enabled;


    // LOBBY CRASHER
    if (LobbyCrasher::Enabled && !wasLobbyCrasherEnabled)
    {
        WriteMem(driver, LobbyCrasher::InstructionAddress, LobbyCrasher::nops);
    }
    else if (!LobbyCrasher::Enabled && wasLobbyCrasherEnabled)
    {
        WriteMem(driver, LobbyCrasher::InstructionAddress, LobbyCrasher::origBytes);
    }
    wasLobbyCrasherEnabled = LobbyCrasher::Enabled;


    // GOTD INFINITE OXYGEN
    if (Oxygen::Enabled && !wasOxygenEnabled)
    {
        WriteMem(driver, Oxygen::InstructionAddress, Oxygen::nops);
    }
    else if (!Oxygen::Enabled && wasOxygenEnabled)
    {
        WriteMem(driver, Oxygen::InstructionAddress, Oxygen::origBytes);
    }
    wasOxygenEnabled = Oxygen::Enabled;


    // INFINITE SPARROW BOOST
    if (InfSparrowBoost::Enabled && !wasInfSparrowBoostEnabled)
    {
        WriteMem(driver, InfSparrowBoost::InstructionAddress, InfSparrowBoost::myByte);
    }
    else if (!InfSparrowBoost::Enabled && wasInfSparrowBoostEnabled)
    {
        WriteMem(driver, InfSparrowBoost::InstructionAddress, InfSparrowBoost::origByte);
    }
    wasInfSparrowBoostEnabled = InfSparrowBoost::Enabled;


    // INTERACT THRU WALLS
    if (InteractThruWalls::Enabled && !wasInteractThruWallsEnabled)
    {
        InjectCodecave(driver, pid, InteractThruWalls::InstructionAddress1, InteractThruWalls::shellcode1, 7, InteractThruWalls::memAllocatedAddress1);
        InjectCodecave(driver, pid, InteractThruWalls::InstructionAddress2, InteractThruWalls::shellcode2, 7, InteractThruWalls::memAllocatedAddress2);
    }
    else if (!InteractThruWalls::Enabled && wasInteractThruWallsEnabled)
    {
        WriteMem(driver, InteractThruWalls::InstructionAddress1, InteractThruWalls::origBytes1);
        WriteMem(driver, InteractThruWalls::InstructionAddress2, InteractThruWalls::origBytes2);
    }
    wasInteractThruWallsEnabled = InteractThruWalls::Enabled;


    // ANTI FLINCH
    if (AntiFlinch::Enabled && !wasAntiFlinchEnabled)
    {
        WriteMem(driver, AntiFlinch::InstructionAddress1, AntiFlinch::nops);
        WriteMem(driver, AntiFlinch::InstructionAddress2, AntiFlinch::nops);
        WriteMem(driver, AntiFlinch::InstructionAddress3, AntiFlinch::nops);
    }
    else if (!AntiFlinch::Enabled && wasAntiFlinchEnabled)
    {
        WriteMem(driver, AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
        WriteMem(driver, AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
        WriteMem(driver, AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
    }
    wasAntiFlinchEnabled = AntiFlinch::Enabled;


    // INFINITE BUFF TIMERS
    if (InfBuffTimers::Enabled && !wasInfBuffTimersEnabled)
    {
        WriteMem(driver, InfBuffTimers::InstructionAddress, InfBuffTimers::nops);
    }
    else if (!InfBuffTimers::Enabled && wasInfBuffTimersEnabled)
    {
        WriteMem(driver, InfBuffTimers::InstructionAddress, InfBuffTimers::origBytes);
    }
    wasInfBuffTimersEnabled = InfBuffTimers::Enabled;


    // INFINITE EXOTIC BUFF TIMERS
    if (InfExoticBuffTimers::Enabled && !wasInfExoticBuffTimersEnabled)
    {
        WriteMem(driver, InfExoticBuffTimers::InstructionAddress, InfExoticBuffTimers::nops);
    }
    else if (!InfExoticBuffTimers::Enabled && wasInfExoticBuffTimersEnabled)
    {
        WriteMem(driver, InfExoticBuffTimers::InstructionAddress, InfExoticBuffTimers::origBytes);
    }
    wasInfExoticBuffTimersEnabled = InfExoticBuffTimers::Enabled;

    // MAGNETISM 999
    if (Mag999::Enabled && !wasMag999Enabled)
    {
        InjectCodecave(driver, pid, Mag999::InstructionAddress, Mag999::shellcode, 8, Mag999::memAllocatedAddress);
    }
    else if (!Mag999::Enabled && wasMag999Enabled)
    {
        WriteMem(driver, Mag999::InstructionAddress, Mag999::origBytes);
    }
    wasMag999Enabled = Mag999::Enabled;
}

void RenderFlyControls(/*…*/)
{
    static bool FlyListening = false;
    static bool BoostListening = false;

    if (!LocalPlayer::Enabled) ImGui::BeginDisabled();

    ImGui::Text("Fly"); ImGui::SameLine();
    DrawHotkeyPicker("FlyToggle", "Fly", FlyListening);
    ImGui::Text("Boost/NoClip"); ImGui::SameLine();
    DrawHotkeyPicker("FlyBoost", "Boost", BoostListening);

    ImGui::Separator();
    ImGui::Text("Fly Speed:");   ImGui::SliderFloat("##FlySpeed", &flySpeed, 25.0f, 100.0f, "%.1f");
    ImGui::Text("Boost Speed:"); ImGui::SliderFloat("##BoostSpeed", &boostSpeed, 0.5f, 25.0f, "%.1f");
    ImGui::Text("Hold [%s] to Boost", GetKeyName(Hotkeys["FlyBoost"]).c_str());

    if (!LocalPlayer::Enabled) ImGui::EndDisabled();
}

void PollHotkeys() {
    // e.g. toggle on key-down:
    //static bool keyWasDown = false;
    //bool keyNowDown = (GetAsyncKeyState(Hotkeys["AbilityCharge"]) & 0x8000) != 0;
    //if (keyNowDown && !keyWasDown)
  
    //keyWasDown = keyNowDown;
    // …repeat for each hotkey…
}

//==============================================================================
// Global Variables and Settings
//==============================================================================
int menuMode = 0;  // 0: Movement, 1: Combat, 2: Teleports, 3: Misc





// Choose a smaller window size for the demo
ImVec2 windowSize = ImVec2(900, 540);
float xButtonSize = 20.0f; // Size of the 'X' exit button

// Window settings
LPCSTR Drawing::lpWindowName = "IUIC Dev Build";
ImVec2 Drawing::vWindowSize = windowSize;
ImGuiWindowFlags Drawing::WindowFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize;
bool Drawing::bDraw = true;

//------------------------------------------------------------------------------
// Settings dropdown and Themes window state flags
//------------------------------------------------------------------------------
static bool gShowSettingsDropdown = false;
static bool gShowThemesWindow = false;

// Global RGB effect speed
static float rgbEffectSpeed = 1.0f;

// Helper: Compute a rainbow (RGB cycling) color based on time and speed.
ImVec4 GetRainbowColor(float speed) {
    float t = ImGui::GetTime() * speed;
    float r = (sinf(t) + 1.0f) * 0.5f;
    float g = (sinf(t + 2.094f) + 1.0f) * 0.5f;
    float b = (sinf(t + 4.188f) + 1.0f) * 0.5f;
    return ImVec4(r, g, b, 1.0f);
}

// Activate drawing
void Drawing::Active() {
    bDraw = true;
}

// Check if drawing is active
bool Drawing::isActive() {
    return bDraw;
}

DWORD get_process_id(const wchar_t* process_name) {
    DWORD process_id{ 0 };

    HANDLE snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
    if (snap_shot == INVALID_HANDLE_VALUE) {
        return process_id;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(decltype(entry));

    if (Process32FirstW(snap_shot, &entry) == TRUE) {
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


// CONFIG TAB
static std::string GetConfigDir()
{
    namespace fs = std::filesystem;

    // 1) safely fetch USERPROFILE
    char* userProfile = nullptr;
    size_t len = 0;
    if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0 || userProfile == nullptr)
    {
        // fallback to CWD/Documents
        return (fs::current_path() / "Documents" / "Hatemob" / "Configs").string();
    }

    // 2) build "%USERPROFILE%\Documents"
    fs::path docs = fs::path(userProfile) / "Documents";
    free(userProfile);

    // 3) build and create "…\Hatemob\Configs"
    fs::path cfg = docs / "Hatemob" / "Configs";
    std::error_code ec;
    fs::create_directories(cfg, ec);
    return cfg.string();
}

static char                          configBaseName[260] = "config";
static int                          selectedConfigIndex = 0;
static const std::string gConfigDir = GetConfigDir();
static char              saveConfigName[260] = "";    // no “.json”
static std::vector<std::string> configList;                 // all basenames
static int               selectedLoadIndex = 0;             // dropdown index

// ─── build full path, always “.json” ───
static std::string MakeConfigPath(const char* baseName)
{
    namespace fs = std::filesystem;
    fs::path p = fs::path(gConfigDir) / baseName;
    p.replace_extension(".json");
    return p.string();
}

// ─── scan gConfigDir for .json files (no extension) ───
static void RefreshConfigList()
{
    // Save the currently selected config name before clearing
    std::string previousSelection = configList.empty() ? "config" : 
                                   (selectedConfigIndex < configList.size() ? 
                                    configList[selectedConfigIndex] : "config");
    
    configList.clear();
    namespace fs = std::filesystem;
    
    try {
        for (const auto& e : fs::directory_iterator(gConfigDir))
        {
            if (e.is_regular_file() && e.path().extension() == ".json") {
                configList.push_back(e.path().stem().string());
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error scanning config directory: " << e.what() << std::endl;
    }
    
    if (configList.empty())
    {
        selectedConfigIndex = 0;
        selectedLoadIndex = 0;
        strcpy_s(configBaseName, "config");
    }
    else
    {
        // Try to find the previously selected item
        auto it = std::find(configList.begin(), configList.end(), previousSelection);
        if (it != configList.end()) {
            selectedConfigIndex = static_cast<int>(std::distance(configList.begin(), it));
        } else {
            selectedConfigIndex = 0;
        }
        
        // Make sure load index is also valid and bounded
        selectedLoadIndex = (std::min)(selectedLoadIndex, static_cast<int>(configList.size() - 1));
        
        strcpy_s(configBaseName, configList[selectedConfigIndex].c_str());
    }
}

void LoadConfig(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return;

    json j;
    try {
        in >> j;
    }
    catch (...) {
        return;
    }

    if (!j.contains("features") || !j["features"].is_object())
        return;

    // 1) Clear any previous state
    FeatureConfig.clear();
    
    // Define a map of feature names to their boolean pointers for cleaner code
    static std::unordered_map<std::string, bool*> featureMap = {
        {"Killaura", &Killaura::Enabled},
        {"LocalPlayer", &LocalPlayer::Enabled},
        {"Ghostmode", &Ghostmode::Enabled},
        {"Godmode", &Godmode::Enabled},
        {"InfAmmo", &InfAmmo::Enabled},
        {"dmgMult", &dmgMult::Enabled},
        {"ViewAngles", &ViewAngles::Enabled},
        {"RPM", &RPM::Enabled},
        {"NoRecoil", &NoRecoil::Enabled},
        {"OHK", &OHK::Enabled},
        {"NoJoinAllies", &NoJoinAllies::Enabled},
        {"NoTurnBack", &NoTurnBack::Enabled},
        {"InfSwordAmmo", &InfSwordAmmo::Enabled},
        {"SparrowAnywhere", &SparrowAnywhere::Enabled},
        {"InfStacks", &InfStacks::Enabled},
        {"NoRezTokens", &NoRezTokens::Enabled},
        {"InstaRespawn", &InstaRespawn::Enabled},
        {"RespawnAnywhere", &RespawnAnywhere::Enabled},
        {"ShootThru", &ShootThru::Enabled},
        {"Chams", &Chams::Enabled},
        {"SuicideKey", &LocalPlayer::KillKeyEnabled},
        {"GameSpeed", &GameSpeed::Enabled},
        {"AbilityCharge", &AbilityCharge::Enabled},
        {"ImmuneAura", &ImmuneAura::Enabled},
        {"IcarusDash", &IcarusDash::Enabled},
        {"InstantInteract", &InstantInteract::Enabled},
        {"LobbyCrasher", &LobbyCrasher::Enabled},
        {"InfiniteOxygen", &Oxygen::Enabled},
        {"InfiniteSparrowBoost", &InfSparrowBoost::Enabled},
        {"InteractThruWalls", &InteractThruWalls::Enabled},
        {"AntiFlinch", &AntiFlinch::Enabled},
        {"InfBuffTimers", &InfBuffTimers::Enabled}
    };
    
    // Special handling for atomic boolean
    ImmuneBosses::Enabled.store(false);

    // Reset all feature flags using the map
    for (const auto& [name, enablePtr] : featureMap) {
        *enablePtr = false;
    }

    // 2) Apply the JSON
    for (auto& [name, val] : j["features"].items()) {
        if (!val.is_boolean()) continue;
        bool enabled = val.get<bool>();
        FeatureConfig[name] = enabled;
        
        // Handle atomic boolean separately
        if (name == "ImmuneBosses") {
            ImmuneBosses::Enabled.store(enabled);
            continue;
        }
        
        // Set feature using the map
        auto it = featureMap.find(name);
        if (it != featureMap.end()) {
            *(it->second) = enabled;
        }
    }
    if (j.contains("settings") && j["settings"].is_object()) {
        auto& s = j["settings"];
        if (s.contains("flySpeed") && s["flySpeed"].is_number())
            flySpeed = s["flySpeed"].get<float>();
        if (s.contains("boostSpeed") && s["boostSpeed"].is_number())
            boostSpeed = s["boostSpeed"].get<float>();
    }
}

void SaveConfig(const std::string& path) {
    using json = nlohmann::json;

    // Start as an object so it's not `null`
    json j;
    j["features"] = json::object();

    // Dump every feature flag
    j["features"]["Killaura"] = Killaura::Enabled;
    j["features"]["LocalPlayer"] = LocalPlayer::Enabled;
    j["features"]["Ghostmode"] = Ghostmode::Enabled;
    j["features"]["Godmode"] = Godmode::Enabled;
    j["features"]["InfAmmo"] = InfAmmo::Enabled;
    j["features"]["dmgMult"] = dmgMult::Enabled;
    j["features"]["ViewAngles"] = ViewAngles::Enabled;
    j["features"]["RPM"] = RPM::Enabled;
    j["features"]["NoRecoil"] = NoRecoil::Enabled;
    j["features"]["OHK"] = OHK::Enabled;
    j["features"]["NoJoinAllies"] = NoJoinAllies::Enabled;
    j["features"]["NoTurnBack"] = NoTurnBack::Enabled;
    j["features"]["InfSwordAmmo"] = InfSwordAmmo::Enabled;
    j["features"]["SparrowAnywhere"] = SparrowAnywhere::Enabled;
    j["features"]["InfStacks"] = InfStacks::Enabled;
    j["features"]["NoRezTokens"] = NoRezTokens::Enabled;
    j["features"]["InstaRespawn"] = InstaRespawn::Enabled;
    j["features"]["RespawnAnywhere"] = RespawnAnywhere::Enabled;
    j["features"]["ShootThru"] = ShootThru::Enabled;
    j["features"]["Chams"] = Chams::Enabled;
    j["features"]["ImmuneBosses"] = ImmuneBosses::Enabled.load();
    j["features"]["AbilityCharge"] = AbilityCharge::Enabled;
    j["features"]["ImmuneAura"] = ImmuneAura::Enabled;
    j["features"]["IcarusDash"] = IcarusDash::Enabled;
    j["features"]["InstantInteract"] = InstantInteract::Enabled;
    j["features"]["LobbyCrasher"] = LobbyCrasher::Enabled;
    j["features"]["SuicideKey"] = LocalPlayer::KillKeyEnabled;
    j["features"]["GameSpeed"] = GameSpeed::Enabled;
    j["features"]["InfiniteOxygen"] = Oxygen::Enabled;
    j["features"]["InfiniteSparrowBoost"] = InfSparrowBoost::Enabled;
    j["features"]["InteractThruWalls"] = InteractThruWalls::Enabled;
    j["features"]["AntiFlinch"] = AntiFlinch::Enabled;
    j["features"]["InfBuffTimers"] = InfBuffTimers::Enabled;

    j["settings"] = {
    { "flySpeed",  flySpeed   },
    { "boostSpeed", boostSpeed }
    };


    // Write it out nicely
    std::ofstream out(path);
    out << std::setw(2) << j;
    RefreshConfigList();
}

// ─── call this once at startup or when you need to re-scan ───
// e.g. in your main() after ImGui is initialized:
//      RefreshConfigList();
// or hook it to a “Refresh” button

// ─── the Config tab rendering ───
void RenderConfigTab()
{
    RefreshConfigList();
    // — Save section —
    ImGui::Text("Save config:"); ImGui::SameLine();
    ImGui::PushItemWidth(150); // Limit width to 150 pixels
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
    ImGui::InputText("##SaveConfigName", saveConfigName, IM_ARRAYSIZE(saveConfigName));
    ImGui::PopStyleColor();
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (ImGui::Button("Save"))
    {
        SaveConfig(MakeConfigPath(saveConfigName));
    }

    ImGui::Spacing();

    // — Load section —
    ImGui::Text("Load config:"); ImGui::SameLine();
    if (configList.empty())
    {
        ImGui::TextDisabled("(no .json files)");
    }
    else
    {
        // dropdown
        ImGui::SameLine();
        ImGui::PushItemWidth(150);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
        if (ImGui::BeginCombo("##LoadCombo", configList[selectedLoadIndex].c_str()))
        {
            for (int i = 0; i < (int)configList.size(); ++i)
            {
                bool isSel = (i == selectedLoadIndex);
                if (ImGui::Selectable(configList[i].c_str(), isSel))
                {
                    selectedLoadIndex = i;
                }
                if (isSel)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
            ImGui::PopStyleColor();
        }
        ImGui::PopItemWidth();
    }

    // Refresh + Load button on same line
    ImGui::SameLine();
    if (!configList.empty() && ImGui::Button("Load"))
        LoadConfig(MakeConfigPath(configList[selectedLoadIndex].c_str()));

    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        RefreshConfigList();
    

    ImGui::Spacing();

    // — Info: show where we’re reading/writing —
    ImGui::Text("Config folder:"); ImGui::SameLine();
    ImGui::TextColored({ 0.7f,0.7f,0.7f,1.0f }, "%s", gConfigDir.c_str());
}

void RenderFOVSlider(HANDLE driver, DWORD pid) {
    static int fovSliderValue = 90;                // Starting fallback value
    static uint64_t lastUpdateTime = 0;
    const uint64_t now = GetTickCount64();

    // 1. Sync with memory every 10 seconds
    if (now - lastUpdateTime > 10000 || lastUpdateTime == 0) {
        uint8_t memFov = 0;
        if (FOV::ptr) {
            ReadMem(driver, pid, FOV::ptr + FOV::pointer, memFov);
            fovSliderValue = static_cast<int>(memFov);
        }
        lastUpdateTime = now;
    }

    // 2. Draw the slider (55–157 degrees range)
    if (ImGui::SliderInt("FOV", &fovSliderValue, 55, 157)) {
        // 3. Write new value if user changed the slider
        if (FOV::ptr) {
            uint8_t newFov = static_cast<uint8_t>(fovSliderValue);
            WriteMem(driver, (FOV::ptr + FOV::pointer), newFov);
            FOV::fov = newFov; // keep in sync
        }
    }
}

bool isInitialized = false;
DWORD pid = 0;
static HANDLE driver = INVALID_HANDLE_VALUE;
std::wstring wModuleName = L"destiny2.exe";

// setting theme
void SetCustomTheme() {
    Themes::ApplyTheme(Themes::currentTheme);
}

void Drawing::Poll() {
    PollHotkeys();    // toggles Enabled flags for other features
    PollFly(driver, pid, moduleBaseAddress + LocalPlayer::destinyBase);
    PollAbilityCharge(driver, pid);
    PollImmuneBosses(driver, pid);
    PollGameSpeed(driver);
    PollKillKey(driver, pid);
    TPManager::Poll(driver, pid);
    UpdateFeatureStates(driver, pid);
}

void Drawing::Draw() {
    // importing theme
    SetCustomTheme();

    static DWORD oldPid = 0;
    static auto lastCheck = std::chrono::steady_clock::now();
    static auto lastMessageTime = std::chrono::steady_clock::now();

    // Auto-reset if Destiny 2 exits
    if (isInitialized) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastCheck).count();

        if (elapsed >= 1) {
            if (get_process_id(L"destiny2.exe") == 0) {
                std::cout << "[!] Destiny 2 has exited. Resetting state..." << std::endl;
                isInitialized = false;
                pid = 0;
                oldPid = 0;
            }
            lastCheck = now;
        }
    }

    if (isInitialized == false) {
        std::cout << "[+] Starting initialization - connecting to driver..." << std::endl;

        driver = CreateFile(L"\\\\.\\IUIC_Enterprise", GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (driver == INVALID_HANDLE_VALUE) {
            std::cout << "[-] Failed to connect to driver. Please ensure the loader was run first." << std::endl;
            std::cin.get();
            return;
        }

        std::cout << "[+] Successfully connected to driver!" << std::endl;
        std::cout << "[+] Waiting for destiny2.exe process..." << std::endl;

        while (true) {
            DWORD newPid = get_process_id(L"destiny2.exe");

            if (newPid != 0 && newPid != oldPid) {
                pid = newPid;
                oldPid = newPid;
                std::cout << "[+] destiny2.exe found! Process ID: " << pid << std::endl;
                break;
            }

            auto currentTime = std::chrono::steady_clock::now();
            auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastMessageTime).count();

            if (elapsedSeconds >= 5) {
                std::cout << "[*] Still waiting for real destiny2.exe to start..." << std::endl;
                lastMessageTime = currentTime;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        DriverComm::Request request = {};
        request.process_id = reinterpret_cast<HANDLE>(pid);
        DWORD bytes_ret = 0;

        BOOL ok = DeviceIoControl(
            driver,
            DriverComm::codes::attach,
            &request, sizeof(request),
            &request, sizeof(request),
            &bytes_ret, nullptr
        );

        if (!ok) {
            std::cout << "[-] Failed to attach w/ error: " << GetLastError() << "\n";
            return;
        }

        std::cout << "[+] Successfully attached\n";

        wcscpy_s(request.moduleName, wModuleName.c_str());

        if (DeviceIoControl(driver, DriverComm::codes::get_base,
            &request, sizeof(request), &request, sizeof(request),
            nullptr, nullptr))
        {
            moduleBaseAddress = reinterpret_cast<uintptr_t>(request.base_address);
            std::cout << "[+] Module base address: 0x"
                << std::hex << moduleBaseAddress << std::endl;
        }
        else {
            std::cout << "[-] Failed to get module base.\n";
        }

        std::cout << "[+] Starting AOB scans..." << std::endl;

        PerformStartupAobScans(driver, pid, wModuleName);
        PerformStartupByteReads(driver, pid);

        LoadHotkeys();
        SetHotkeyDefault("FlyToggle", VK_H);
        SetHotkeyDefault("FlyBoost", VK_G);
        SetHotkeyDefault("AbilityCharge", VK_5);
        RefreshConfigList();
        TPManager::InitFolder();
        TPManager::RefreshConfigList();

        //std::this_thread::sleep_for(std::chrono::seconds(5));
        isInitialized = true;
    }

    if (!isActive())
        return;

    // Set up the main window.
    ImGui::SetNextWindowSize(vWindowSize, ImGuiCond_Once);

    // Add window rounding and shadow for a modern look
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 18));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));


    ImGui::Begin(lpWindowName, &bDraw, WindowFlags);
    // Set up the "X" button at the top-right.
    ImVec2 contentRegion = ImGui::GetWindowContentRegionMax();
    const float padding = 5.0f;
    const float xButtonSize = 20.0f; // adjust to your button size
    float posX = contentRegion.x - xButtonSize - padding;
    float posY = padding;

    // ─── Close Button ───
    ImGui::SetCursorPos(ImVec2(posX, posY));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
    if (ImGui::Button("X", ImVec2(xButtonSize, xButtonSize))) {
        exit(0);
    }
    ImGui::PopStyleColor(3);    // ─── Header Text ───
    // Align vertically with the button by setting the same Y
    ImGui::SetCursorPosY(posY);
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("IUIC Dev Build").x) * 0.5f);
    ImGui::TextColored(ImVec4(0.9f, 0.7f, 1.0f, 1.0f), "HATEMOB");    // ─── Divider ───
    ImGui::SetCursorPosY(posY + xButtonSize + 23); // Move separator just below the status text
    ImGui::Separator();

    // Begin the Tab Bar.
    if (ImGui::BeginTabBar("MyTabBar"))
    {
        // Movement Tab
        if (ImGui::BeginTabItem("Player"))
        {
            // Tab background
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 180;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("Player Options:");
            ImGui::Spacing();
            // Use lighter color for FOV slider
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_SliderGrab, ImVec4(0.7f, 0.8f, 1.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, ImVec4(0.8f, 0.9f, 1.0f, 1.0f));
            RenderFOVSlider(driver, pid);
            ImGui::Spacing();
            ImGui::Toggle("Hook LocalPlayer", &LocalPlayer::Enabled);
            RenderKillKeyUI();

            RenderFlyControls();
            ImGui::PopStyleColor(3);
            ImGui::EndTabItem();
        }

        // Combat Tab
        if (ImGui::BeginTabItem("Combat"))
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 220;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("Combat Options:");
            ImGui::Spacing();
            ImGui::Toggle("Killaura", &Killaura::Enabled);
            ImGui::Toggle("Ghostmode", &Ghostmode::Enabled);
            ImGui::Toggle("Godmode", &Godmode::Enabled);
            ImGui::Toggle("Inf Ammo", &InfAmmo::Enabled);
            ImGui::Toggle("RPM", &RPM::Enabled);
            ImGui::Toggle("Dmg Multiplier", &dmgMult::Enabled);
            ImGui::Toggle("Unshielded Immune Bosses/Aura", &ImmuneAura::Enabled);
            RenderAbilityChargeUI();
            ImGui::Toggle("No Recoil", &NoRecoil::Enabled);
            ImGui::Toggle("Shoot Thru Walls", &ShootThru::Enabled);
            RenderImmuneBossesUI();
            ImGui::Toggle("One hit kill", &OHK::Enabled);

            RenderMag999Button(driver, pid, iconFont);
            

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Misc"))
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 220;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("Misc Options:");
            ImGui::Spacing();
            ImGui::Toggle("No Joining Allies", &NoJoinAllies::Enabled);
            ImGui::Toggle("No Turn Back", &NoTurnBack::Enabled);
            ImGui::Toggle("Infinite Rez Tokens", &NoRezTokens::Enabled);
            ImGui::Toggle("Respawn Anywhere", &InstaRespawn::Enabled);
            ImGui::Toggle("Infinite Stacks", &InfStacks::Enabled);
            ImGui::Toggle("Infinite Buff Timers", &InfBuffTimers::Enabled);
            ImGui::Toggle("Infinite Exotic Buff Timers", &InfExoticBuffTimers::Enabled);
            RenderGameSpeedUI();
            ImGui::Toggle("Instant Interact", &InstantInteract::Enabled);
            ImGui::Toggle("Interact Thru Walls", &InteractThruWalls::Enabled);
            ImGui::Toggle("Sparrow Anywhere", &SparrowAnywhere::Enabled);
            ImGui::Toggle("Infinite Sparrow Boost", &InfSparrowBoost::Enabled);

            // Reset scan flag if user disables the feature
            if (GSize::Address == 0 && GSize::Enabled)
            {
                GSize::Address = AOBScan(driver, pid, wModuleName, GSize::AOB);
                if (GSize::Address == 0)
                {
                    GSize::Enabled = false; // disable if scan failed
                }
            }

            ImGui::Toggle("Guardian Size", &GSize::Enabled);

            if (GSize::Enabled && GSize::Address != 0)
            {
                ReadMem(driver, pid, GSize::Address, GSize::Value);
                static float lastReadVal = 0.0f;
                if (lastReadVal != GSize::Value)
                {
                    GSize::inputVal = GSize::Value;
                    lastReadVal = GSize::Value;
                }

                ImGui::PushItemWidth(150);
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::InputFloat("Size##GSize", &GSize::inputVal, 0.0f, 0.0f, "%.3f");
                ImGui::PopStyleColor();
                ImGui::PopItemWidth();

                if (ImGui::Button("Set##GSize"))
                {
                    WriteMem(driver, GSize::Address, GSize::inputVal);
                    lastReadVal = -1.0f;
                }
            }

            RenderActivityLoaderUI(driver, pid);

            ImGui::EndTabItem();
        }        if (ImGui::BeginTabItem("TPs"))
        {
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
                ImGui::InputText("##Config Name", TPManager::configNameBuf, sizeof(TPManager::configNameBuf));
                // If input is empty, draw a placeholder on top of it
                if (TPManager::configNameBuf[0] == '\0') {
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
                    std::string nm{ TPManager::configNameBuf };
                    if (!nm.empty()) {
                        TPManager::cycleList.clear();
                        TPManager::WriteConfig(nm);
                        TPManager::RefreshConfigList();
                        TPManager::loadedConfigIdx =
                            int(std::find(
                                TPManager::configs.begin(),
                                TPManager::configs.end(),
                                nm
                            ) - TPManager::configs.begin());
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Refresh")) {
                    TPManager::RefreshConfigList();
                }
                const char* curConfig = TPManager::loadedConfigIdx >= 0
                    ? TPManager::configs[TPManager::loadedConfigIdx].c_str()
                    : "Select config";
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::SetNextItemWidth(200.0f);
                if (ImGui::BeginCombo("##Configs", curConfig)) {
                    for (int i = 0; i < (int)TPManager::configs.size(); ++i)
                    {
                        bool isSel = (i == TPManager::loadedConfigIdx);
                        if (ImGui::Selectable(TPManager::configs[i].c_str(), isSel))
                            TPManager::loadedConfigIdx = i;
                        if (isSel)
                            ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                    ImGui::PopStyleColor();
                }
                ImGui::SameLine();
                ImGui::BeginDisabled(TPManager::loadedConfigIdx < 0);
                if (ImGui::Button("Load")) {
                    TPManager::ReadConfig(
                        TPManager::configs[TPManager::loadedConfigIdx]
                    );
                    TPManager::loadedConfigIdxActive = TPManager::loadedConfigIdx;
                }
                ImGui::SameLine();
                if (ImGui::Button("Unload")) {
                    TPManager::cycleList.clear();
                    TPManager::currentCycleIdx = 0;
                    TPManager::lastTPName = "None";
                    TPManager::loadedConfigIdxActive = -1;
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset Index")) {
                    TPManager::currentCycleIdx = -1;
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
                    TPManager::loadedConfigIdxActive >= 0
                    ? TPManager::configs[TPManager::loadedConfigIdxActive].c_str()
                    : "None"
                );
                ImGui::Text("Current TP Index: %d", TPManager::currentCycleIdx);
                ImGui::Text("Last TP: %s", TPManager::lastTPName.c_str());
                TPManager::UpdateStatus();
                ImGui::Text("Coords: %s", TPManager::coordsStr.c_str());
                ImGui::Text("View : %s", TPManager::viewStr.c_str());
                ImGui::EndGroup();
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Text("Teleport Entries:");
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.180f, 0.180f, 0.180f, 1.0f));
                if (ImGui::ListBoxHeader("##Tplist", (int)TPManager::cycleList.size(), 6)) {
                    for (int i = 0; i < (int)TPManager::cycleList.size(); ++i) {
                        bool selected = (i == TPManager::currentCycleIdx);
                        // prefix with 1-based index:
                        std::string label = std::format("{:d}. {}", i + 1, TPManager::cycleList[i].name);
                        if (ImGui::Selectable(label.c_str(), selected)) {
                            TPManager::currentCycleIdx = i;
                            TPManager::LoadEditorFields(i);
                        }
                    }
                    ImGui::ListBoxFooter();
                    ImGui::PopStyleColor(2);
                }
                ImGui::SameLine();
                ImGui::BeginGroup();
                ImGui::Text("Edit Selected TP");
                if (TPManager::lastEditIdx >= 0 && TPManager::lastEditIdx < (int)TPManager::cycleList.size()) {
                    ImGui::PushItemWidth(180);
                    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                    ImGui::InputText("Name", TPManager::editName, sizeof(TPManager::editName));
                    ImGui::InputFloat("X", &TPManager::editX);
                    ImGui::InputFloat("Y", &TPManager::editY);
                    ImGui::InputFloat("Z", &TPManager::editZ);
                    ImGui::InputFloat("ViewX", &TPManager::editViewX);
                    ImGui::InputFloat("ViewY", &TPManager::editViewY);
                    ImGui::PopStyleColor();
                    ImGui::PopItemWidth();
                    if (ImGui::Button("Apply Changes")) {
                        if (strlen(TPManager::editName) == 0) {
                            ImGui::OpenPopup("NameError");
                        }
                        else {
                            TPManager::ApplyEditorChanges();
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Reset Fields")) {
                        TPManager::LoadEditorFields(TPManager::lastEditIdx);
                    }
                    if (ImGui::BeginPopup("NameError")) {
                        ImGui::Text("Name cannot be empty!");
                        if (ImGui::Button("OK")) ImGui::CloseCurrentPopup();
                        ImGui::EndPopup();
                    }
                }
                ImGui::EndGroup();
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::InputText("##NewTPName", TPManager::tpNameBuf, sizeof(TPManager::tpNameBuf));
                ImGui::PopStyleColor();
                ImGui::SameLine();
                if (ImGui::Button("Save TP") && TPManager::loadedConfigIdx >= 0)
                {
                    uintptr_t base = LocalPlayer::realPlayer.load();
                    uintptr_t viewBase = ViewAngles::addr;
                    TPManager::TPEntry e;
                    e.name = TPManager::tpNameBuf[0]
                        ? std::string(TPManager::tpNameBuf)
                        : ("TP" + std::to_string(TPManager::cycleList.size() + 1));
                    ReadMem(driver, pid, (base + TPManager::POS_X), e.x);
                    ReadMem(driver, pid, (base + TPManager::POS_Y), e.y);
                    ReadMem(driver, pid, (base + TPManager::POS_Z), e.z);
                    if (viewBase) {
                        ReadMem(driver, pid, (viewBase + TPManager::VIEW_X), e.viewX);
                        ReadMem(driver, pid, (viewBase + TPManager::VIEW_Y), e.viewY);
                    }
                    else {
                        e.viewX = e.viewY = 0.0f;
                    }
                    TPManager::cycleList.push_back(e);
                    TPManager::WriteConfig(TPManager::configs[TPManager::loadedConfigIdx]);
                    TPManager::tpNameBuf[0] = '\0';
                    TPManager::currentCycleIdx = (int)TPManager::cycleList.size() - 1;
                }
                ImGui::SameLine();
                if (ImGui::Button("Delete TP") &&
                    TPManager::currentCycleIdx >= 0 &&
                    TPManager::currentCycleIdx < (int)TPManager::cycleList.size())
                {
                    TPManager::cycleList.erase(
                        TPManager::cycleList.begin() + TPManager::currentCycleIdx
                    );
                    TPManager::WriteConfig(
                        TPManager::configs[TPManager::loadedConfigIdx]
                    );
                    TPManager::ReadConfig(
                        TPManager::configs[TPManager::loadedConfigIdx]
                    );
                    if (TPManager::currentCycleIdx >= (int)TPManager::cycleList.size())
                        TPManager::currentCycleIdx =
                        (int)TPManager::cycleList.size() - 1;
                }
                if (TPManager::currentCycleIdx >= (int)TPManager::cycleList.size())
                    TPManager::currentCycleIdx = (int)TPManager::cycleList.size() - 1;
                if (TPManager::lastEditIdx >= (int)TPManager::cycleList.size())
                    TPManager::ClearEditorFields();
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
                if (ImGui::ArrowButton("Up##tp", ImGuiDir_Up) && TPManager::currentCycleIdx > 0)
                {
                    // swap in memory
                    std::swap(TPManager::cycleList[TPManager::currentCycleIdx],
                        TPManager::cycleList[TPManager::currentCycleIdx - 1]);
                    --TPManager::currentCycleIdx;                     // moved one up

                    // persist to disk
                    TPManager::WriteConfig(TPManager::configs[TPManager::loadedConfigIdx]);

                    // refresh the editor fields on the newly-selected entry
                    TPManager::LoadEditorFields(TPManager::currentCycleIdx);
                }
                ImGui::SameLine();
                if (ImGui::ArrowButton("Down##tp", ImGuiDir_Down) &&
                    TPManager::currentCycleIdx + 1 < (int)TPManager::cycleList.size())
                {
                    std::swap(TPManager::cycleList[TPManager::currentCycleIdx],
                        TPManager::cycleList[TPManager::currentCycleIdx + 1]);
                    ++TPManager::currentCycleIdx;                     // moved one down

                    TPManager::WriteConfig(TPManager::configs[TPManager::loadedConfigIdx]);
                    TPManager::LoadEditorFields(TPManager::currentCycleIdx);
                }                ImGui::PopStyleVar();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("PVP"))
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 120;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("PVP Options:");
            ImGui::Spacing();
            ImGui::Toggle("Chams", &Chams::Enabled);
            ImGui::Toggle("Infinite Icarus Dash", &IcarusDash::Enabled);
            ImGui::Toggle("Lobby Crasher", &LobbyCrasher::Enabled);
            ImGui::Toggle("No Flinch", &AntiFlinch::Enabled);
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Random"))
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 80;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("Random Options:");
            ImGui::Spacing();
            if (ImGui::CollapsingHeader("GotD"))
            {
                ImGui::Toggle("Infinite Oxygen", &Oxygen::Enabled);
            }
            ImGui::EndTabItem();
        }        if (ImGui::BeginTabItem("Config")) {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 200; // Increased height for theme selection
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            
            // Theme Selection Section
            ImGui::Text("Theme Selection:");
            ImGui::Spacing();
            
            static int selectedThemeIndex = static_cast<int>(Themes::currentTheme);
            auto availableThemes = Themes::GetAvailableThemes();
            
            // Create a vector of theme names for the combo
            std::vector<const char*> themeNames;
            for (const auto& theme : availableThemes) {
                themeNames.push_back(theme.name.c_str());
            }
            
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::SetNextItemWidth(200.0f);
            if (ImGui::Combo("##ThemeSelector", &selectedThemeIndex, themeNames.data(), static_cast<int>(themeNames.size()))) {
                // Apply the selected theme
                if (selectedThemeIndex >= 0 && selectedThemeIndex < static_cast<int>(availableThemes.size())) {
                    Themes::ApplyTheme(availableThemes[selectedThemeIndex].type);
                }
            }
            ImGui::PopStyleColor();
            
            // Show theme description
            if (selectedThemeIndex >= 0 && selectedThemeIndex < static_cast<int>(availableThemes.size())) {
                ImGui::TextDisabled("%s", availableThemes[selectedThemeIndex].description.c_str());
            }
            
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            
            ImGui::Text("Config Options:");
            RenderConfigTab();
            ImGui::EndTabItem();        }

        ImGui::EndTabBar();
    }
    LimitFPS(185);
    ImGui::End();


}
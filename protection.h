#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// Incluir winternl.h para las estructuras del PEB
#include <winternl.h>

// Usar las estructuras directamente de winternl.h sin redefinirlas
// winternl.h ya define: LIST_ENTRY, UNICODE_STRING, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, PEB


class LeuProtection {
private:
    static bool debuggerDetected;
    static std::thread protectionThread;
    static bool running;
    static bool basicFunctions;
    static bool mediumFunctions;
    static bool advancedFunctions;
    static bool antivmFunctions;

    static bool IsDebuggerPresentAPI();
    static bool CheckRemoteDebugger();
    static bool CheckPEBBeingDebugged();
    static bool CheckHardwareBreakpoints();
    static void ErasePEHeaders();
    static void CodeObfuscation();
    static void MemoryProtection();
    static void AntiAnalysis();
    static void CleanTraces();

    static void EnableMemoryGuard();
    static void GuardPagesProtection();
    static void SpoofMemoryRegions();
    static void ContinuousMemoryProtection();
    static void RemoveFromProcessList();
    static void HideFromTaskManager();
    static void ProtectCriticalMemory();

    // ========== AuthKey ==========
    static bool CheckHostsFileTampering();
    static bool CheckSuspiciousProcesses();
    static bool CheckCertificateTampering();
    static bool CheckAuthKeySecurity();

    // ========== Anti-Cracking DLL's ==========
    static bool CheckForMaliciousDLLs();
    static bool PreventDLLInjection();
    static void MonitorLoadedDLLs();
    static bool IsBlacklistedDLLLoaded();
    static std::thread dllMonitorThread;
    static bool dllMonitoring;


    // ========== CHECKSUM MD5 ==========
    static bool CheckModuleByMD5(const wchar_t* moduleName, const std::string& expectedMD5);
    static bool CheckKnownMaliciousModules();
    static std::string CalculateMD5(BYTE* data, size_t size);
    static std::string BytesToHexString(const BYTE* data, size_t length);

    // Listas negras
    static std::vector<std::string> registryBlacklist;
    static std::vector<std::wstring> fileBlacklist;

public:
    static void Initialize();
    static void Shutdown();
    static void ContinuousMonitoring();
    static bool IsDebuggerDetected();
};

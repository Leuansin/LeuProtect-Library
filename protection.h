#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#include <winternl.h>

class LeuProtection {
private:
    static bool debuggerDetected;
    static std::thread protectionThread;
    static bool running;

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
    static void HideProcessFromToolhelp();
    static void ProtectCriticalMemory();

public:
    static void Initialize();
    static void Shutdown();
    static void ContinuousMonitoring();
    static bool IsDebuggerDetected();
};

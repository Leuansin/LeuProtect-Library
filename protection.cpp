#include "protection.h"
#include <iostream>
#include <intrin.h>
#include <algorithm>
#include <atomic>
#include <random>
#include <chrono>
#include <thread>
#include <vector>
#include <string>

bool LeuProtection::debuggerDetected = false;
std::thread LeuProtection::protectionThread;
bool LeuProtection::running = false;
DWORD oldProtect;
BYTE* imageBase;

// ========== FUNCIONES DE DETECCIÓN BÁSICAS ==========
bool LeuProtection::IsDebuggerPresentAPI() {
    return IsDebuggerPresent();
}

bool LeuProtection::CheckRemoteDebugger() {
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged;
}

bool LeuProtection::CheckPEBBeingDebugged() {
    __try {
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        return pPeb->BeingDebugged;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LeuProtection::CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
    }
    return false;
}

// ========== FUNCIONES DE PROTECCIÓN AVANZADAS ==========
DWORD CalculateChecksum(BYTE* data, size_t size) {
    DWORD checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum >> 1) | (checksum << 31);
        checksum += data[i];
    }
    return checksum;
}

bool CheckModuleByChecksum(const wchar_t* moduleName) {
    HMODULE hModule = GetModuleHandleW(moduleName);
    if (!hModule) return false;

    MODULEINFO modInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        DWORD checksum = CalculateChecksum((BYTE*)modInfo.lpBaseOfDll, modInfo.SizeOfImage);
        return checksum != 0;
    }
    return false;
}

bool FindHiddenDebuggerWindows() {
    const wchar_t* debuggerWindows[] = {
        L"OLLYDBG", L"IDA", L"x64dbg", L"WinDbg",
        L"Immunity", L"Cheat Engine", L"Process Hacker"
    };

    for (const wchar_t* className : debuggerWindows) {
        if (FindWindowW(className, NULL)) {
            return true;
        }
    }
    return false;
}

bool AdvancedTimingCheck() {
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);

    volatile int result = 0;
    for (int i = 0; i < 1000000; i++) {
        result += i * i;
        if (i % 1000 == 0) {
            __nop();
        }
    }

    QueryPerformanceCounter(&end);

    double elapsed = (end.QuadPart - start.QuadPart) * 1000000.0 / frequency.QuadPart;
    return elapsed < 50000;
}

bool CheckDebuggerRegistryKeys() {
    HKEY hKey;
    const wchar_t* debugKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"SOFTWARE\\OllyDbg",
        L"SOFTWARE\\IDA Pro"
    };

    for (const wchar_t* keyPath : debugKeys) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

bool CheckDebuggerProcessNames() {
    const wchar_t* debuggers[] = {
        L"x64dbg.exe", L"ollydbg.exe", L"ida64.exe", L"idaq.exe",
        L"windbg.exe", L"cheatengine-x86_64.exe", L"processhacker.exe", L"hxd.exe"
    };

    for (const wchar_t* tool : debuggers) {
        if (GetModuleHandleW(tool)) {
            return true;
        }
    }
    return false;
}

void LeuProtection::CodeObfuscation() {
    imageBase = (BYTE*)GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    BYTE* codeStart = nullptr;
    DWORD codeSize = 0;

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            codeStart = imageBase + section->VirtualAddress;
            codeSize = section->Misc.VirtualSize;
            break;
        }
    }

    if (codeStart && codeSize > 0) {
        DWORD oldProt;
        VirtualProtect(codeStart, codeSize, PAGE_EXECUTE_READWRITE, &oldProt);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 100);

        for (DWORD i = 0; i < codeSize - 1; i += 2) {
            if (dis(gen) < 5) {
                codeStart[i] = 0x90;
            }
        }

        VirtualProtect(codeStart, codeSize, PAGE_EXECUTE_READ, &oldProt);
    }
}

void LeuProtection::MemoryProtection() {
    imageBase = (BYTE*)GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* sectionAddress = imageBase + section->VirtualAddress;
            DWORD protectSize = section->Misc.VirtualSize;

            VirtualProtect(sectionAddress, protectSize, PAGE_EXECUTE_READ, &oldProtect);
        }
    }
}

void LeuProtection::AntiAnalysis() {
    if (CheckDebuggerProcessNames()) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckModuleByChecksum(L"x64dbg.exe") ||
        CheckModuleByChecksum(L"cheatengine-x86_64.exe")) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (FindHiddenDebuggerWindows()) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckDebuggerRegistryKeys()) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (AdvancedTimingCheck()) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    auto start = std::chrono::high_resolution_clock::now();
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) {
        dummy += i * i;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    if (duration.count() < 100) {
        debuggerDetected = true;
    }
}

void LeuProtection::ErasePEHeaders() {
    imageBase = (BYTE*)GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);

    DWORD oldProt;
    VirtualProtect(imageBase, ntHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt);
}

void LeuProtection::CleanTraces() {
    __try {
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        PLIST_ENTRY moduleList = &pPeb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY moduleEntry = moduleList->Flink;

        while (moduleEntry != moduleList && moduleEntry != NULL) {
            PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)moduleEntry;
            if (module->DllBase == GetModuleHandle(NULL)) {
                if (module->FullDllName.Buffer && module->FullDllName.Length > 0) {
                    module->FullDllName.Buffer[0] = L'?';
                }
                break;
            }
            moduleEntry = moduleEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LeuProtection::RemoveFromProcessList() {
    __try {
        PPEB peb = (PPEB)__readgsqword(0x60);
        PPEB_LDR_DATA ldr = peb->Ldr;

        PLIST_ENTRY current = ldr->InMemoryOrderModuleList.Flink;
        while (current != &ldr->InMemoryOrderModuleList && current != NULL) {
            PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;

            if (entry->DllBase == GetModuleHandle(NULL)) {
                if (entry->InMemoryOrderLinks.Blink && entry->InMemoryOrderLinks.Flink) {
                    entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
                    entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

                    entry->InMemoryOrderLinks.Flink = (PLIST_ENTRY)&entry->InMemoryOrderLinks;
                    entry->InMemoryOrderLinks.Blink = (PLIST_ENTRY)&entry->InMemoryOrderLinks;
                }
                break;
            }
            current = current->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LeuProtection::GuardPagesProtection() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    for (int i = 0; i < 10; i++) {
        BYTE* testAddr = (BYTE*)sysInfo.lpMinimumApplicationAddress + (i * sysInfo.dwPageSize);

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(testAddr, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
            DWORD newProtect = PAGE_NOACCESS;
            DWORD oldProt;
            if (VirtualProtect(mbi.BaseAddress, sysInfo.dwPageSize, newProtect, &oldProt)) {
                PVOID baseAddress = mbi.BaseAddress;
                SIZE_T regionSize = sysInfo.dwPageSize;
                DWORD originalProtect = oldProt;

                std::thread([baseAddress, regionSize, originalProtect]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    DWORD tempProt;
                    VirtualProtect(baseAddress, regionSize, originalProtect, &tempProt);
                    }).detach();
            }
        }
    }
}

void LeuProtection::SpoofMemoryRegions() {
    for (int i = 0; i < 3; i++) {
        std::thread([]() {
            BYTE* fakeRegion = (BYTE*)VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (fakeRegion) {
                for (int j = 0; j < 8192; j++) {
                    fakeRegion[j] = rand() % 256;
                }

                std::this_thread::sleep_for(std::chrono::seconds(20));
                VirtualFree(fakeRegion, 0, MEM_RELEASE);
            }
            }).detach();
    }
}

void LeuProtection::ProtectCriticalMemory() {
    HMODULE hModule = GetModuleHandle(NULL);
    MODULEINFO modInfo;

    if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        static int protectionCounter = 0;
        DWORD newProtect;

        switch (protectionCounter % 3) {
        case 0: newProtect = PAGE_EXECUTE_READ; break;
        case 1: newProtect = PAGE_EXECUTE_READWRITE; break;
        case 2: newProtect = PAGE_READONLY; break;
        default: newProtect = PAGE_EXECUTE_READ;
        }

        DWORD oldProt;
        VirtualProtect(modInfo.lpBaseOfDll, modInfo.SizeOfImage, newProtect, &oldProt);

        protectionCounter++;
    }
}

void LeuProtection::ContinuousMemoryProtection() {
    int cycleCounter = 0;

    while (running) {
        if (IsDebuggerPresentAPI() || CheckRemoteDebugger() || CheckPEBBeingDebugged()) {
            debuggerDetected = true;
            TerminateProcess(GetCurrentProcess(), 0);
            break;
        }

        ProtectCriticalMemory();

        cycleCounter++;
        if (cycleCounter % 5 == 0) {
            GuardPagesProtection();
        }

        if (cycleCounter % 20 == 0) {
            SpoofMemoryRegions();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void LeuProtection::EnableMemoryGuard() {
    MemoryProtection();
    SpoofMemoryRegions();

    running = true;
    protectionThread = std::thread(ContinuousMemoryProtection);
}

// ========== FUNCIONES PÚBLICAS ==========

void LeuProtection::Initialize() {
    MemoryProtection();
    CodeObfuscation();
    AntiAnalysis();
    ErasePEHeaders();
    CleanTraces();

    EnableMemoryGuard();

    std::thread monitorThread(ContinuousMonitoring);
    monitorThread.detach();
}

void LeuProtection::Shutdown() {
    running = false;
    if (protectionThread.joinable()) {
        protectionThread.join();
    }
}

void LeuProtection::ContinuousMonitoring() {
    while (true) {
        if (IsDebuggerPresentAPI() || CheckRemoteDebugger() || CheckPEBBeingDebugged() || CheckHardwareBreakpoints()) {
            debuggerDetected = true;
            TerminateProcess(GetCurrentProcess(), 0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool LeuProtection::IsDebuggerDetected() {
    return debuggerDetected;
}

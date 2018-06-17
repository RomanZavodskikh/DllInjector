// NativeApi.h : works with syscalls and internal structures
//

#pragma once

typedef LONG NTSTATUS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];

    ULONG_PTR Ldr;
    //PPEB_LDR_DATA Ldr;
    ULONG_PTR ProcessParameters;
    //PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    BYTE Reserved4[104];
    PVOID Reserved5[52];

    ULONG_PTR PostProcessInitRoutine;
    //PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

extern "C" NTSTATUS WINAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ DWORD ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSuspendProcess(
    __in HANDLE ProcessHandle
);

extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwResumeProcess(
    __in HANDLE ProcessHandle
);

#pragma comment(lib, "ntdll.lib")


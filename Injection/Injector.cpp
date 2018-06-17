// Injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#ifndef _WIN64
	#define CHILD_EXE L"C:\\Users\\hp\\source\\repos\\Hello32\\Debug\\Hello32.exe"
	#define DLL_NAME L"C:\\Users\\hp\\source\\repos\\Injection\\Debug\\MyDll.dll"
	#define G_SHELLCODE g_shellcode_x32
#else
	#define CHILD_EXE L"C:\\Windows\\System32\\Taskmgr.exe"
	#define DLL_NAME L"C:\\Users\\hp\\source\\repos\\Injection\\x64\\Debug\\MyDll.dll"
	#define G_SHELLCODE g_shellcode_x64
#endif // _WIN64

UCHAR g_shellcode_x64[] =
{
	/*0x00:*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //pLoadLibrary pointer, RUNTIME
	/*0x08:*/ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8x nops to fix disassembly of VS
	/*0x10:*/ 0x48, 0x83, 0xEC, 0x28, //sub rsp,28h
	/*0x14:*/ 0x48, 0x8D, 0x0D, 0x1D, 0x00, 0x00, 0x00, //lea rcx,[RIP+(38h-1Bh)]
	/*0x1B:*/ 0xFF, 0x15, 0xDF, 0xFF, 0xFF, 0xFF, //call qword ptr[RIP-(21h-0)]
	/*0x21:*/ 0x33, 0xC9, //xor ecx, ecx
	/*0x23:*/ 0x83, 0xCA, 0xFF, //or edx, 0FFFFFFFFh
	/*0x26:*/ 0x48, 0x85, 0xC0, //test rax, rax
	/*0x29:*/ 0x0F, 0x44, 0xCA, //cmove ecx, edx
	/*0x2C:*/ 0x8B, 0xC1, //mov eax, ecx
	/*0x2E:*/ 0x48, 0x83, 0xC4, 0x28, //add rsp, 28h
	/*0x32:*/ 0xC3, //ret
	/*0x33:*/ 0x90, 0x90, 0x90, 0x90, 0x90 // 5x nop for alignment
	/*0x38:*/ // String: "MyDll.dll"
};

UCHAR g_shellcode_x32[] =
{
	/*0x00:*/ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //pLoadLibrary pointer, RUNTIME
	/*0x08:*/ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8x nops to fix disassembly of VS
	/*0x10:*/ 0x90, 0x83, 0xEC, 0x28, //sub esp,0x28
	/*0x14:*/ 0x68, 0x00, 0x00, 0x00, 0x00, //push 0x0
	/*0x19:*/ 0xBA, 0x00, 0x00, 0x00, 0x00, //mov edx, 0x0
	/*0x1E:*/ 0xFF, 0xD2, // call edx;
	/*0x20:*/ 0x90, 0x90, 0x90, //
	/*0x23:*/ 0x33, 0xC9, //xor ecx, ecx
	/*0x25:*/ 0x83, 0xCA, 0xFF, //or edx, 0FFFFFFFFh
	/*0x28:*/ 0x90, 0x85, 0xC0, //test eax, eax
	/*0x2B:*/ 0x0F, 0x44, 0xCA, //cmove ecx, edx
	/*0x2E:*/ 0x8B, 0xC1, //mov eax, ecx
	/*0x30:*/ 0x90, 0x83, 0xC4, 0x20, //add esp, 20h
	/*0x34:*/ 0xC3, //ret
	/*0x35:*/ 0x90, 0x90, 0x90 // 5x nop for alignment
	/*0x38:*/ // String: "MyDll.dll"
};

#if 0
typedef HMODULE(__stdcall *PFN_LoadLibraryW)(LPCWSTR lpLibFileName);
//this code was used to obtain shellcode
PFN_LoadLibraryW g_pLoadLibraryW = LoadLibraryW;
wchar_t* g_pString = L"kernel32.dll";
DWORD _declspec(noinline) func()
{
	if (NULL == g_pLoadLibraryW(g_pString))
	{
		return 0xFFFFFFFF;
	}
	return 0;
}
#endif

BOOL InjectDll(HANDLE hProcess, LPCTSTR lpFileName, PVOID pfnLoadLibrary)
{
	BOOL ret = FALSE;
	PVOID lpShellcode_remote = NULL;
	HANDLE hRemoteThread = NULL;

	for (;;)
	{
		//allocate remote storage
		DWORD lpFileName_size = (wcslen(lpFileName) + 1)*sizeof(wchar_t);
		DWORD lpShellcode_size = sizeof(G_SHELLCODE) + lpFileName_size;
		lpShellcode_remote = VirtualAllocEx(hProcess, NULL,
			lpShellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == lpShellcode_remote)
		{
			printf("VirtualAllocEx returns NULL \n");
			break;
		}
		*(UINT32*)((UCHAR*)g_shellcode_x32 + 0x15) = (UINT32)((char*)lpShellcode_remote + 0x38);
		*(UINT32*)((UCHAR*)g_shellcode_x32 + 0x1A) = (UINT32)(char*)pfnLoadLibrary;

		//fill remote storage with actual shellcode
		SIZE_T bytesWritten;
		BOOL res = WriteProcessMemory(hProcess, lpShellcode_remote,
			G_SHELLCODE, sizeof(G_SHELLCODE), &bytesWritten);
		if (FALSE == res)
		{
			printf("WriteProcessMemory failed with %d \n", GetLastError());
			break;
		}

		//fill remote storage with string
		res = WriteProcessMemory(hProcess, RVA_TO_VA(PVOID, lpShellcode_remote, sizeof(G_SHELLCODE)),
			lpFileName, lpFileName_size, &bytesWritten);
		if (FALSE == res)
		{
			printf("WriteProcessMemory failed with %d \n", GetLastError());
			break;
		}

		//adjust pfnLoadLibrary
		DWORD PatchedPointerRVA = 0x00;
		ULONG_PTR PatchedPointerValue = (ULONG_PTR)pfnLoadLibrary;
		WriteRemoteDataType<ULONG_PTR>(hProcess,
			RVA_TO_VA(ULONG_PTR, lpShellcode_remote, PatchedPointerRVA),
			&PatchedPointerValue);

		DWORD tid;
		//in case of problems try MyLoadLibrary if this is actually current process
		hRemoteThread = CreateRemoteThread(hProcess,
			NULL, 0, (LPTHREAD_START_ROUTINE)
			RVA_TO_VA(ULONG_PTR, lpShellcode_remote, 0x10),
			lpShellcode_remote,
			0, &tid);
		if (NULL == hRemoteThread)
		{
			printf("CreateRemoteThread failed with %d \n", GetLastError());
			break;
		}

		//wait for MyDll initialization
		WaitForSingleObject(hRemoteThread, INFINITE);

		DWORD ExitCode = 0xDEADFACE;
		GetExitCodeThread(hRemoteThread, &ExitCode);
		printf("GetExitCodeThread returns %x \n", ExitCode);

		ret = TRUE;
		break;
	}

	if (!ret)
	{
		//if (lpShellcode_remote)
		//TODO call VirtualFree(...)
	}

	if (hRemoteThread) CloseHandle(hRemoteThread);
	return ret;
}

#if 0
typedef struct _ENTRY_POINT_CONTEXT
{
	ULONG_PTR RemoteEntryPoint;
} ENTRY_POINT_CONTEXT, *PENTRY_POINT_CONTEXT;

bool FindEntryPoint(REMOTE_ARGS_DEFS, PVOID Context)
{
	bool is64;
	PIMAGE_NT_HEADERS pLocalPeHeader = GetLocalPeHeader(REMOTE_ARGS_CALL, &is64);
	PENTRY_POINT_CONTEXT MyContext = (PENTRY_POINT_CONTEXT)Context;
	ULONG_PTR
		pRemoteEntryPoint;

	if (is64)
	{
		PIMAGE_NT_HEADERS64 pLocalPeHeader2 = (PIMAGE_NT_HEADERS64)pLocalPeHeader;
		pRemoteEntryPoint = RVA_TO_REMOTE_VA(
			PVOID,
			pLocalPeHeader2->OptionalHeader.AddressOfEntryPoint);
	}
	else
	{
		PIMAGE_NT_HEADERS32 pLocalPeHeader2 = (PIMAGE_NT_HEADERS32)pLocalPeHeader;
		pRemoteEntryPoint = RVA_TO_REMOTE_VA(
			PVOID,
			pLocalPeHeader2->OptionalHeader.AddressOfEntryPoint);
	}
	free(pLocalPeHeader);
	MyContext->RemoteEntryPoint = pRemoteEntryPoint;
	return false;
}
#endif

ULONG_PTR FindEntryPoint2(REMOTE_ARGS_DEFS)
{
	bool is64;
	PIMAGE_NT_HEADERS pLocalPeHeader = GetLocalPeHeader(REMOTE_ARGS_CALL, &is64);
	ULONG_PTR pRemoteEntryPoint;

	if (is64)
	{
		PIMAGE_NT_HEADERS64 pLocalPeHeader2 = (PIMAGE_NT_HEADERS64)pLocalPeHeader;
		pRemoteEntryPoint = RVA_TO_REMOTE_VA(
			PVOID,
			pLocalPeHeader2->OptionalHeader.AddressOfEntryPoint);
	}
	else
	{
		PIMAGE_NT_HEADERS32 pLocalPeHeader2 = (PIMAGE_NT_HEADERS32)pLocalPeHeader;
		pRemoteEntryPoint = RVA_TO_REMOTE_VA(
			PVOID,
			pLocalPeHeader2->OptionalHeader.AddressOfEntryPoint);
	}
	free(pLocalPeHeader);
	return pRemoteEntryPoint;
}

//returns entry point in remote process
ULONG_PTR GetEntryPoint(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	memset(&pbi, 0, sizeof(pbi));
	DWORD retlen = 0;

	NTSTATUS Status = ZwQueryInformationProcess(
		hProcess,
		0,
		&pbi,
		sizeof(pbi),
		&retlen);

	PEB* pLocalPeb = REMOTE(PEB, (ULONG_PTR)pbi.PebBaseAddress);
	printf("from PEB: %p and %p \n", pLocalPeb->Reserved3[0], pLocalPeb->Reserved3[1]);

	ULONG_PTR PebRemoteImageBase = (ULONG_PTR)pLocalPeb->Reserved3[1]; //TODO x64 PoC only
	ULONG_PTR pRemoteEntryPoint = FindEntryPoint2(hProcess, PebRemoteImageBase);
	return pRemoteEntryPoint;
}

//returns address of LoadLibraryA in remote process
ULONG_PTR GetRemoteLoadLibraryA(REMOTE_ARGS_DEFS)
{
	//TODO move code from main
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
#if 0
	DWORD res = func();
	printf("func returns %d \n", res);
	return 0;
#endif

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	BOOL rtr = CreateProcess(CHILD_EXE, NULL,
		NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (rtr == false)
	{
		printf("CreateProcess failed GLE()=0x%x\n", GetLastError());
		return 1;
	}

	HANDLE hProcess = pi.hProcess;
	ULONG_PTR pRemoteEntryPoint = GetEntryPoint(hProcess);

	WORD OrigWord;
	WORD PatchedWord = 0xFEEB;
	ReadRemoteDataType<WORD>(hProcess, pRemoteEntryPoint, &OrigWord);
	WriteRemoteDataType<WORD>(hProcess, pRemoteEntryPoint, &PatchedWord);

	ResumeThread(pi.hThread); //resume patched process;
	Sleep(1000);

	DWORD nModules;
	HMODULE* phModules = GetRemoteModules(pi.hProcess, &nModules);

#if 0
	ENTRY_POINT_CONTEXT MyContext2;
	MyContext2.RemoteEntryPoint = 0;
	RemoteModuleWorker(processInfo.hProcess, phModules, nModules, FindEntryPoint, &MyContext2);
	printf("notepad.exe entry point is at %p \n", MyContext2.RemoteEntryPoint);
#endif

	EXPORT_CONTEXT MyContext;
	MyContext.ModuleName = "KERNEL32.dll";
	MyContext.FunctionName = "LoadLibraryW";
	MyContext.RemoteFunctionAddress = 0;
	RemoteModuleWorker(pi.hProcess, phModules, nModules, FindExport, &MyContext);
	printf("kernel32!LoadLibraryW is at %p \n", MyContext.RemoteFunctionAddress);

	//TODO:
	//if (is64)
	//{
	//}

	InjectDll(hProcess,
		DLL_NAME,
		(PVOID)MyContext.RemoteFunctionAddress);
	Sleep(1000);

	NTSTATUS Status = ZwSuspendProcess(hProcess);
	if (Status != 0x0)
	{
		printf("ZwSuspendProcess error 0x%x\n", Status);
		return 1;
	}
	WriteRemoteDataType<WORD>(hProcess, pRemoteEntryPoint, &OrigWord);
	Status = ZwResumeProcess(hProcess);
	Sleep(5000);

	/*
	WaitForSingleObject(processInfo.hProcess, INFINITE);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	*/
	return 0;

#if 0
	//where is LoadLibrary in my process?
	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	PVOID pLoadLibrary = GetProcAddress(hModule, "LoadLibraryW");
	printf("LoadLibrary is at %p \n", pLoadLibrary);

#if 0
	//Load MyDll into myself
	HMODULE pDll = LoadLibrary(DLL_NAME);
	printf("MyDll.dll
		was loaded at %p \n", pDll);
#endif

#if 0
		//Load MyDll into myself via CreateThread
		DWORD tid;
	HANDLE hThread = CreateThread(NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		DLL_NAME,
		0, &tid);
	Sleep(3000);
#else
		//Load MyDll into remote notepad.exe
		//hope that in hProcess LoadLibrary
		//will be at the same address


		BOOL res = CreateProcess(CHILD_EXE, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (!res)
	{
		printf("CreateProcess failed with %d \n", GetLastError());
	}
	else
	{
		printf("Child process %p(%d) was created \n", pi.hProcess, pi.dwProcessId);
	}

	SIZE_T dllNameSize = (wcslen(DLL_NAME) + 1)wchar_t;
	PVOID pRemoteDllName = VirtualAllocEx(pi.hProcess, NULL, dllNameSize, MEM_COMMIT, PAGE_READWRITE);
	SIZE_T bytesWritten;
	res = WriteProcessMemory(pi.hProcess, pRemoteDllName, DLL_NAME, dllNameSize, &bytesWritten);
	DWORD tid;
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		pRemoteDllName,
		0, &tid);
#endif

	return 0;
#endif
}
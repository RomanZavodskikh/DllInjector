// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <WinUser.h>
#include <Commctrl.h>
#include "const.h"
#include "hook.h"
#include "hooked_funcs.h"
#include "support.h"
#include "peb.h"
#include "import.h"

#ifndef GWL_HINSTANCE
#define GWL_HINSTANCE (-6)
#endif

struct handle_data {
	unsigned long process_id;
	HWND window_handle;
};
#ifdef _WIN64
HWND g_hListView;
bool is_hListView_got = false;
bool isAffinityColAdded = false;
int numOfInitializedCols = 0;

BOOL is_main_window(HWND handle)
{
	return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
}

BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam)
{
	struct handle_data* data = (struct handle_data*)lParam;
	unsigned long process_id = 0;
	GetWindowThreadProcessId(handle, &process_id);
	if (data->process_id != process_id || !is_main_window(handle))
		return TRUE;
	data->window_handle = handle;
	return FALSE;
}

HWND find_main_window()
{
	struct handle_data data;
	TCHAR buffer[1024] = { 0 };
	data.process_id = GetProcessId(GetCurrentProcess());
	data.window_handle = 0;
	EnumWindows(enum_windows_callback, (LPARAM)&data);
	swprintf_s(buffer, L"data.process_id: %u, data.window_handle: 0x%x", data.process_id, data.window_handle);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);
	return data.window_handle;
}

HWND find_sys_list_view(HWND hDirectUI, int order=0)
{
	for (HWND hi = GetWindow(hDirectUI, GW_CHILD); hi ; hi = GetWindow(hi, GW_HWNDNEXT))
	{
		TCHAR buffer[1024] = { 0 };
		TCHAR className[1024] = { 0 };
		HWND hChild = GetWindow(hi, GW_CHILD);
		GetClassName(hChild, className, 1024);
		//swprintf_s(buffer, L"hi: 0x%x, hChild: 0x%x, className: %s", hi, hChild, className);
		//MessageBox(NULL, buffer, L"MyDll", MB_OK);
		if (wcscmp(className, L"SysListView32") == 0)
		{
			if (order == 0)
				return hChild;
			else
				order--;
		}
	}
	return 0x0;
}

LONG_PTR
WINAPI
HookedSetWindowLongPtrW(
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong)
{
	HWND hTaskManagerWindow, hNativeHWNDHost, hDirectUI, hSysListView, hSysHeader, hwndButton;
	TCHAR buffer[1024] = { 0 };

	int ret = SetWindowLongPtr(hWnd, nIndex, dwNewLong);
	hTaskManagerWindow = find_main_window();
	swprintf_s(buffer, L"hTaskManagerWindow: 0x%x", hTaskManagerWindow);
	MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hNativeHWNDHost = GetWindow(hTaskManagerWindow, GW_CHILD);
	swprintf_s(buffer, L"hNativeHWNDHost: 0x%x", hNativeHWNDHost);
	MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hDirectUI = GetWindow(hNativeHWNDHost, GW_CHILD);
	swprintf_s(buffer, L"hDirectUI: 0x%x", hDirectUI);
	MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hSysListView = find_sys_list_view(hDirectUI, 0);
	g_hListView = hSysListView;
	is_hListView_got = true;
	swprintf_s(buffer, L"hSysListView: 0x%x", hSysListView);
	MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hSysHeader = GetWindow(hSysListView, GW_CHILD);
	swprintf_s(buffer, L"hSysHeader: 0x%x", hSysHeader);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);

	return ret;
}

LRESULT
WINAPI
HookedSendMessageW(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam)
{
	int ret = 0;

	//	Add new column
	if (is_hListView_got && hWnd == g_hListView && Msg == LWM_INSERTCOLUMNW && !isAffinityColAdded) {
		ret = SendMessageW(hWnd, Msg, wParam, lParam);
		numOfInitializedCols++;

		int colsNum = getListViewNumOfCols(hWnd);

		InfoLog(L"####   cols: %d, init_cols: %d", colsNum, numOfInitializedCols);
		if (numOfInitializedCols < DEFAULT_COLUMNS_NUM)
			goto end_hook;

		if (!addAffinityColumn(hWnd, colsNum))
			InfoLog(L"addAffinityColumn failed in HookedSendMessageW");
		else {
			InfoLog(L"Affinity column successfully added!");
			isAffinityColAdded = true;
		}

		goto end_hook;
	}

	// Refresh the data
	if (is_hListView_got && hWnd == g_hListView && Msg == WM_SETREDRAW) {
		if (!drawAffinityByPID(hWnd, PID_COL_NUM))
			MessageBox(NULL, L"drawAffinityByPID failed in HookedSendMessageW", L"MyDll", MB_OK);
	}

	ret = SendMessageW(hWnd, Msg, wParam, lParam);

end_hook:
	return ret;
}

int getListViewNumOfCols(HWND hWnd) {
	HWND hWndHdr = ListView_GetHeader(hWnd);
	if (!hWndHdr)
		InfoLog(L"ListView_GetHeader returned NULL in getListViewNumOfCols");

	int numOfCols = Header_GetItemCount(hWndHdr);
	if (numOfCols == -1)
		InfoLog(L"Header_getItemCount failed in getListViewNumOfCols");

	return numOfCols;
}

bool addAffinityColumn(HWND hWnd, int idx) {
	LVCOLUMN lvC;

	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvC.iSubItem = 7;
	lvC.pszText = L"Affinity";
	lvC.cx = 100;
	lvC.fmt = LVCFMT_LEFT;

	return ListView_InsertColumn(hWnd, idx, &lvC);
}

bool drawAffinityByPID(HWND hWnd, int pidColNum) {
	if (pidColNum == -1) {
		InfoLog(L"pidColNum is -1 in drawAffinityByPID");
		return false;
	}

	int itemCount = ListView_GetItemCount(hWnd);

	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	int cpuNum = sysinfo.dwNumberOfProcessors;

	WCHAR buf[BUFFSIZE] = {};
	WCHAR affBuf[MAX_CPU_NUM] = {};

	for (int iItem = 0; iItem < itemCount; ++iItem) {
		ListView_GetItemText(hWnd, iItem, pidColNum, buf, sizeof(buf));

		int pid = _wtoi(buf);

		if (!getAffinity(pid, affBuf, cpuNum)) {
			InfoLog(L"getAffinity failed in drawAffinityByPID");
			return false;
		}
			
		int affinityCol = getListViewNumOfCols(hWnd) - 1;  // -1 because of affinity column itself
		ListView_SetItemText(hWnd, iItem, affinityCol, affBuf);
	}

	return true;
}

bool getAffinity(int pid, PWCHAR affBuf, int cpuNum) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	DWORD_PTR processAffinityMask = 0, systemAffinityMask = 0;
	GetProcessAffinityMask(hProcess, &processAffinityMask, &systemAffinityMask);

	for (int i = 0; i < cpuNum; ++i) {
		int curr_bit = processAffinityMask & 0x1;
		affBuf[i] = curr_bit != 0 ? '+' : '-';
		processAffinityMask = processAffinityMask >> 1;
	}

	affBuf[cpuNum] = '\0';
	return true;
}

bool hookFuncByName(PCHAR name, ULONG_PTR newFunc) {
	ULONG_PTR pBase = get_pBase();
	InfoLog(L"pBase: %p\n", pBase);
	if (!checkMZ(pBase))
		return false;

	ULONG_PTR importRVA = getImportRVA(pBase);
	if (importRVA == NULL)
	{
		InfoLog(L"importRVA is NULL");
		return false;
	}
		

	PIMAGE_IMPORT_DESCRIPTOR pImpDir = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importRVA);
	while (pImpDir->Characteristics) {
		PVOID pOrigThunk = (PVOID)(pImpDir->OriginalFirstThunk + pBase);
		if (!pImpDir->OriginalFirstThunk)
			InfoLog(L"Original first thunk is NULL");

		PVOID pThunk = (PVOID)(pImpDir->FirstThunk + pBase);
		if (!pThunk)
			InfoLog(L"pThunk in NULL");

		ULONG_PTR pHookedFunc = changeFuncAddrByName(name, newFunc, pOrigThunk, pThunk, pBase);
		if (pHookedFunc != NULL) {
			InfoLog(L"Original address of hooked func: %p\n", pHookedFunc);
			break;
		}

		pImpDir++;
	}

	return true;
}
#endif

#if defined _M_IX86
#elif defined _M_X64
ULONG_PTR get_pBase() {
	DWORD offset = 0x60;
	PPEB64 pPeb = (PPEB64)__readgsqword(offset);
	return pPeb->ImageBaseAddress;
}

#else
ULONG_PTR get_pBase() {
	exit(EXIT_FAILURE);
}

#endif

bool checkMZ(ULONG_PTR pBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	char firstSymbol = pDosHeader->e_magic & 0xFF,
		secondSymbol = (pDosHeader->e_magic >> 8) & 0xFF;

	if (firstSymbol == 'M' && secondSymbol == 'Z')
	{
		InfoLog(L"MZ signature succesfully checked!");
		return true;
	}
		
	InfoLog(L"Error during MZ signature checking");
	return false;
}

ULONG_PTR getImportRVA(ULONG_PTR pBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pPEHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDD = getPDataDirectory(pPEHeader);
	return pDD[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
}

PIMAGE_DATA_DIRECTORY getPDataDirectory(PIMAGE_NT_HEADERS pPEHeader) {
	PIMAGE_DATA_DIRECTORY pDD;
	WORD machine = pPEHeader->FileHeader.Machine;

	if (machine == IMAGE_FILE_MACHINE_AMD64) {
		IMAGE_OPTIONAL_HEADER64 optHeader;
		memcpy(&optHeader, &(pPEHeader->OptionalHeader), sizeof(optHeader));
		pDD = optHeader.DataDirectory;
	}
	else {
		IMAGE_OPTIONAL_HEADER32 optHeader;
		memcpy(&optHeader, &(pPEHeader->OptionalHeader), sizeof(optHeader));
		pDD = optHeader.DataDirectory;
	}

	return pDD;
}

ULONG_PTR changeFuncAddrByName(PCHAR name, ULONG_PTR newFunc, PVOID pOrigThunk, PVOID pThunk, ULONG_PTR pBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pPEHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	WORD machine = pPEHeader->FileHeader.Machine;

	if (machine == IMAGE_FILE_MACHINE_AMD64)
		return changeFuncAddrByNameX64(name, newFunc, (PIMAGE_THUNK_DATA64)pOrigThunk, (PIMAGE_THUNK_DATA64)pThunk, pBase);
	else
		return changeFuncAddrByNameX86(name, newFunc, (PIMAGE_THUNK_DATA32)pOrigThunk, (PIMAGE_THUNK_DATA32)pThunk, pBase);

}


ULONG_PTR changeFuncAddrByNameX86(PCHAR name, ULONG_PTR newFunc, PIMAGE_THUNK_DATA32 pOrigThunk, PIMAGE_THUNK_DATA32 pThunk, ULONG_PTR pBase) {
	while (pOrigThunk->u1.AddressOfData) {
		if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
		{
			InfoLog(L"Ordinal higher bit is set!");
			return 0;
		}

		if (pThunk == NULL)
		{
			InfoLog(L"pThunk is NULL");
			return NULL;
		}

		if (pOrigThunk == NULL)
		{
			InfoLog(L"pOrigThunk is NULL");
			return NULL;
		}

		PCHAR curr_name = ((PIMAGE_IMPORT_BY_NAME)(pOrigThunk->u1.AddressOfData + pBase))->Name;
		if (!strcmp(curr_name, name)) {
			ULONG_PTR originalAddr = (ULONG_PTR)(pThunk->u1.Function);
			InfoLog(L"### The func is founded: %s | %p ###", curr_name, originalAddr);
			InfoLog(L"Trying to hook it!");

			DWORD oldProtect;
			VirtualProtect(&(pThunk->u1.Function), sizeof(newFunc), PAGE_EXECUTE_READWRITE, &oldProtect);
			LPVOID dst = memcpy(&(pThunk->u1.Function), &newFunc, sizeof(newFunc));
			VirtualProtect(&(pThunk->u1.Function), sizeof(newFunc), oldProtect, &oldProtect);

			return originalAddr;
		}

		pThunk++;
		pOrigThunk++;
	}

	return NULL;
}


ULONG_PTR changeFuncAddrByNameX64(PCHAR name, ULONG_PTR newFunc, PIMAGE_THUNK_DATA64 pOrigThunk, PIMAGE_THUNK_DATA64 pThunk, ULONG_PTR pBase) {
	while (pOrigThunk->u1.AddressOfData) {
		if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
		{
			InfoLog(L"Ordinal higher bit is set!");
			return 0;
		}
			

		if (pThunk == NULL)
		{
			InfoLog(L"pThunk is NULL");
			return NULL;
		}
			

		if (pOrigThunk == NULL)
		{
			InfoLog(L"pOrigThunk is NULL");
			return NULL;
		}

		PCHAR curr_name = ((PIMAGE_IMPORT_BY_NAME)(pOrigThunk->u1.AddressOfData + pBase))->Name;
		if (!strcmp(curr_name, name)) {
			ULONG_PTR originalAddr = (ULONG_PTR)(pThunk->u1.Function);
			InfoLog(L"### The func is founded: %s | %p ###", curr_name, originalAddr);
			InfoLog(L"Trying to hook it!");

			DWORD oldProtect;
			VirtualProtect(&(pThunk->u1.Function), sizeof(newFunc), PAGE_EXECUTE_READWRITE, &oldProtect);
			LPVOID dst = memcpy(&(pThunk->u1.Function), &newFunc, sizeof(newFunc));
			VirtualProtect(&(pThunk->u1.Function), sizeof(newFunc), oldProtect, &oldProtect);

			return originalAddr;
		}

		pThunk++;
		pOrigThunk++;
	}

	return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	HANDLE hDrawer = 0x0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, L"... is loading", L"MyDll", MB_OK);
		printf("... is loading\n");
		#ifdef _WIN64
		if (!hookFuncByName(SET_WINDOW_LONG_PTR_W, (ULONG_PTR)HookedSetWindowLongPtrW))
			MessageBox(NULL, L"hookFuncByName failed in dllmain during hooking 0 function", L"MyDll", MB_OK);

		if (!hookFuncByName(SEND_MESSAGE_W, (ULONG_PTR)HookedSendMessageW))
			MessageBox(NULL, L"hookFuncByName failed in dllmain during hooking 1 function", L"MyDll", MB_OK);
		#endif
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(NULL, L"... is unloading", L"MyDll", MB_OK);
		printf("... is unloading\n");
		break;
	}
	return TRUE;
}
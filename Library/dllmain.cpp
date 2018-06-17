// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <WinUser.h>
#include <Commctrl.h>

#ifndef GWL_HINSTANCE
#define GWL_HINSTANCE (-6)
#endif

struct handle_data {
	unsigned long process_id;
	HWND window_handle;
};

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
	MessageBox(NULL, buffer, L"MyDll", MB_OK);
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

DWORD WINAPI ButtonDrawer(LPVOID lpvParam)
{
	HWND hTaskManagerWindow, hNativeHWNDHost, hDirectUI, hSysListView, hSysHeader, hwndButton;
	TCHAR buffer[1024] = { 0 };

	Sleep(2000);
	hTaskManagerWindow = find_main_window();
	swprintf_s(buffer, L"hTaskManagerWindow: 0x%x", hTaskManagerWindow);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hNativeHWNDHost = GetWindow(hTaskManagerWindow, GW_CHILD);
	swprintf_s(buffer, L"hNativeHWNDHost: 0x%x", hNativeHWNDHost);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hDirectUI = GetWindow(hNativeHWNDHost, GW_CHILD);
	swprintf_s(buffer, L"hDirectUI: 0x%x", hDirectUI);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);

	hSysListView = find_sys_list_view(hDirectUI, 1);
	swprintf_s(buffer, L"hSysListView: 0x%x", hSysListView);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);

	LVCOLUMN lvc;
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.pszText = L"MyColumn";
	lvc.iSubItem = 0;
	lvc.cx = 100;
	lvc.fmt = LVCFMT_CENTER;
	int iRtr = ListView_InsertColumn(hSysListView, 0, &lvc);
	if (iRtr == -1)
	{
		MessageBox(NULL, L"ListView_InsertColumn error", L"MyDll", MB_OK);
		return 0;
	}

	hSysHeader = GetWindow(hSysListView, GW_CHILD);
	swprintf_s(buffer, L"hSysHeader: 0x%x", hSysHeader);
	//MessageBox(NULL, buffer, L"MyDll", MB_OK);
	hwndButton = CreateWindow(
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"OK",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		10,         // x position 
		10,         // y position 
		1000,        // Button width
		1000,        // Button height
		hSysHeader,     // Parent window
		NULL,       // No menu.
		(HINSTANCE)GetWindowLong(hSysHeader, GWL_HINSTANCE),
		NULL);      // Pointer not needed.
	swprintf_s(buffer, L"hwndButton: 0x%x", hwndButton);
	MessageBox(NULL, buffer, L"MyDll", MB_OK);

	return 0;
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
		hDrawer = CreateThread(
			NULL,              // no security attribute 
			0,                 // default stack size 
			ButtonDrawer,    // thread proc
			NULL,    // thread parameter 
			0,                 // not suspended 
			NULL); // returns thread ID 
		#endif // _WIN64
		//ExitProcess(0);
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
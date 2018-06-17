#pragma once


#define SET_WINDOW_LONG_PTR_W "SetWindowLongPtrW"
#define CALL_WINDOW_PROC_W "CallWindowProcW"
#define DRAW_TEXT_W "DrawTextW"
#define SEND_MESSAGE_W "SendMessageW"


//	This func is hooked for getting ListView handle
LONG_PTR
WINAPI
HookedSetWindowLongPtrW(
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong);


LRESULT
WINAPI
HookedSendMessageW(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam);

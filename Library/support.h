#pragma once

#define InfoLog(msg, ...) do {									\
						TCHAR buf[1024];					    \
						swprintf_s(buf, msg, __VA_ARGS__);		\
						MessageBox(NULL, buf, L"MyDll", MB_OK);	\
					} while(0)									

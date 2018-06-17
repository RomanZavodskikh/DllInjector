#pragma once


ULONG_PTR changeFuncAddrByName(PCHAR name, ULONG_PTR newFunc, PVOID pOrigThunk, PVOID pThunk, ULONG_PTR pBase);
ULONG_PTR changeFuncAddrByNameX86(PCHAR name, ULONG_PTR newFunc, PIMAGE_THUNK_DATA32 pOrigThunk, PIMAGE_THUNK_DATA32 pThunk, ULONG_PTR pBase);
ULONG_PTR changeFuncAddrByNameX64(PCHAR name, ULONG_PTR newFunc, PIMAGE_THUNK_DATA64 pOrigThunk, PIMAGE_THUNK_DATA64 pThunk, ULONG_PTR pBase);

ULONG_PTR get_pBase();
ULONG_PTR getImportRVA(ULONG_PTR pBase);
PIMAGE_DATA_DIRECTORY getPDataDirectory(PIMAGE_NT_HEADERS pPEHeader);

bool checkMZ(ULONG_PTR pBase);

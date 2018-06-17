#pragma once
bool hookFuncByName(PCHAR name, ULONG_PTR newFunc);

bool addAffinityColumn(HWND hWnd, int idx);
bool drawAffinityByPID(HWND hWnd, int pidColNum);
bool getAffinity(int pid, PWCHAR affBuf, int cpuNum);
int getListViewNumOfCols(HWND hWnd);
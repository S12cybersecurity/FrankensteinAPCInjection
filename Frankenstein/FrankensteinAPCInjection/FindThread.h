#pragma once
#include <windows.h>

HANDLE getFirstThreadHandleByPID(DWORD pid);
bool EnableDebugPrivilege();
HANDLE getNonMainOrAnyThreadHandleByPID(DWORD pid);
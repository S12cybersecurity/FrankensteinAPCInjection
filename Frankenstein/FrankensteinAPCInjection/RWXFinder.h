#pragma once
#include <windows.h>

LPVOID FindRWX(HANDLE hndl, SIZE_T size);
HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName);
LPVOID GetAmsiEntryPointCave(HANDLE hProcess, HMODULE hAmsi);
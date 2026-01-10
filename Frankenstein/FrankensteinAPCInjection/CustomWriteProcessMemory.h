#pragma once
#include <windows.h>

LPVOID CustomWriteProcessMemory(HANDLE hProcess, BYTE* payload, const size_t payload_size, LPVOID remotePtr);
void* getPEBUnused(HANDLE hProcess);
#pragma once
#include <windows.h>

//LPVOID CustomWriteProcessMemory(HANDLE hProcess, BYTE* payload, const size_t payload_size, LPVOID remotePtr);
LPVOID CustomWriteProcessMemory(HANDLE hProcess, BYTE* payload, size_t payload_size, LPVOID remotePtr, HANDLE hThread, LPVOID rwx);
void* getPEBUnused(HANDLE hProcess);
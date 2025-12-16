#ifndef PROCESS_THREAD_PAIR_H
#define PROCESS_THREAD_PAIR_H

#include <Windows.h>

struct ProcessThreadPair {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD processId;
    DWORD threadId;
    DWORD ownerProcessId;
};

#endif // PROCESS_THREAD_PAIR_H
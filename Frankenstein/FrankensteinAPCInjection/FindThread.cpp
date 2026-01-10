#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>  // For ULONG_MAX
#include <iostream>  // For error output, optional

// Function to enable debug privilege (required for accessing remote process threads)
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return success;
}

// Fallback function: Get the first thread handle found for the PID
HANDLE getFirstThreadHandleByPID(DWORD pid) {  // Changed int to DWORD for consistency
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
        return NULL;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                CloseHandle(hThreadSnap);
                return OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    else {
        std::cerr << "Failed to enumerate threads: " << GetLastError() << std::endl;
    }

    CloseHandle(hThreadSnap);
    return NULL;
}

// Main function: Get a handle to a non-main thread if exists, else the main thread
// Uses creation time if privileges allow, else falls back to getFirstThreadHandleByPID
HANDLE getNonMainOrAnyThreadHandleByPID(DWORD pid) {
    // Try to enable debug privilege
    bool hasPrivilege = EnableDebugPrivilege();

    if (!hasPrivilege) {
        std::cerr << "No debug privilege; falling back to first thread." << std::endl;
        return getFirstThreadHandleByPID(pid);
    }

    // If privilege enabled, proceed with creation time method
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
        return getFirstThreadHandleByPID(pid);  // Fallback on failure
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    FILETIME earliestCreationTime;
    earliestCreationTime.dwLowDateTime = ULONG_MAX;
    earliestCreationTime.dwHighDateTime = ULONG_MAX;

    DWORD mainThreadId = 0;
    bool foundAny = false;
    bool accessDenied = false;

    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
                if (hThread != NULL) {
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
                        if (!foundAny || CompareFileTime(&creationTime, &earliestCreationTime) < 0) {
                            earliestCreationTime = creationTime;
                            mainThreadId = threadEntry.th32ThreadID;
                            foundAny = true;
                        }
                    }
                    else {
                        if (GetLastError() == ERROR_ACCESS_DENIED) {
                            accessDenied = true;
                        }
                        std::cerr << "Failed to get times for thread " << threadEntry.th32ThreadID << ": " << GetLastError() << std::endl;
                    }
                    CloseHandle(hThread);
                }
                else {
                    std::cerr << "Failed to open thread " << threadEntry.th32ThreadID << ": " << GetLastError() << std::endl;
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }
    else {
        std::cerr << "Failed to enumerate threads: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);

    if (accessDenied || !foundAny) {
        std::cerr << "Access issues or no threads; falling back to first thread." << std::endl;
        return getFirstThreadHandleByPID(pid);
    }

    // Now enumerate again to find a non-main thread, or fall back to main
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
        return getFirstThreadHandleByPID(pid);  // Fallback on failure
    }

    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE hNonMainThread = NULL;
    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == pid && threadEntry.th32ThreadID != mainThreadId) {
                hNonMainThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, threadEntry.th32ThreadID);
                if (hNonMainThread != NULL) {
                    CloseHandle(hSnapshot);
                    return hNonMainThread;  // Found a non-main thread, return it
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }

    // If no non-main thread found, return the main one
    HANDLE hMainThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, mainThreadId);
    CloseHandle(hSnapshot);
    return hMainThread;  // Could be NULL if open fails
}
#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>  // For ULONG_MAX
#include <iostream>  // For error output, optional
#include <vector>
#include <algorithm>
#include <winternl.h>

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
//
//// Fallback function: Get the first thread handle found for the PID
//HANDLE getFirstThreadHandleByPID(DWORD pid) {  // Changed int to DWORD for consistency
//    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
//    if (hThreadSnap == INVALID_HANDLE_VALUE) {
//        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
//        return NULL;
//    }
//
//    THREADENTRY32 te32;
//    te32.dwSize = sizeof(THREADENTRY32);
//
//    if (Thread32First(hThreadSnap, &te32)) {
//        do {
//            if (te32.th32OwnerProcessID == pid) {
//                CloseHandle(hThreadSnap);
//                return OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
//            }
//        } while (Thread32Next(hThreadSnap, &te32));
//    }
//    else {
//        std::cerr << "Failed to enumerate threads: " << GetLastError() << std::endl;
//    }
//
//    CloseHandle(hThreadSnap);
//    return NULL;
//}
//
//// Main function: Get a handle to a non-main thread if exists, else the main thread
//// Uses creation time if privileges allow, else falls back to getFirstThreadHandleByPID
//HANDLE getNonMainOrAnyThreadHandleByPID(DWORD pid) {
//    // Try to enable debug privilege
//    bool hasPrivilege = EnableDebugPrivilege();
//
//    if (!hasPrivilege) {
//        std::cerr << "No debug privilege; falling back to first thread." << std::endl;
//        return getFirstThreadHandleByPID(pid);
//    }
//
//    // If privilege enabled, proceed with creation time method
//    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
//    if (hSnapshot == INVALID_HANDLE_VALUE) {
//        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
//        return getFirstThreadHandleByPID(pid);  // Fallback on failure
//    }
//
//    THREADENTRY32 threadEntry;
//    threadEntry.dwSize = sizeof(THREADENTRY32);
//
//    FILETIME earliestCreationTime;
//    earliestCreationTime.dwLowDateTime = ULONG_MAX;
//    earliestCreationTime.dwHighDateTime = ULONG_MAX;
//
//    DWORD mainThreadId = 0;
//    bool foundAny = false;
//    bool accessDenied = false;
//
//    if (Thread32First(hSnapshot, &threadEntry)) {
//        do {
//            if (threadEntry.th32OwnerProcessID == pid) {
//                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
//                if (hThread != NULL) {
//                    FILETIME creationTime, exitTime, kernelTime, userTime;
//                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
//                        if (!foundAny || CompareFileTime(&creationTime, &earliestCreationTime) < 0) {
//                            earliestCreationTime = creationTime;
//                            mainThreadId = threadEntry.th32ThreadID;
//                            foundAny = true;
//                        }
//                    }
//                    else {
//                        if (GetLastError() == ERROR_ACCESS_DENIED) {
//                            accessDenied = true;
//                        }
//                        std::cerr << "Failed to get times for thread " << threadEntry.th32ThreadID << ": " << GetLastError() << std::endl;
//                    }
//                    CloseHandle(hThread);
//                }
//                else {
//                    std::cerr << "Failed to open thread " << threadEntry.th32ThreadID << ": " << GetLastError() << std::endl;
//                }
//            }
//        } while (Thread32Next(hSnapshot, &threadEntry));
//    }
//    else {
//        std::cerr << "Failed to enumerate threads: " << GetLastError() << std::endl;
//    }
//
//    CloseHandle(hSnapshot);
//
//    if (accessDenied || !foundAny) {
//        std::cerr << "Access issues or no threads; falling back to first thread." << std::endl;
//        return getFirstThreadHandleByPID(pid);
//    }
//
//    // Now enumerate again to find a non-main thread, or fall back to main
//    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
//    if (hSnapshot == INVALID_HANDLE_VALUE) {
//        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
//        return getFirstThreadHandleByPID(pid);  // Fallback on failure
//    }
//
//    threadEntry.dwSize = sizeof(THREADENTRY32);
//
//    HANDLE hNonMainThread = NULL;
//    if (Thread32First(hSnapshot, &threadEntry)) {
//        do {
//            if (threadEntry.th32OwnerProcessID == pid && threadEntry.th32ThreadID != mainThreadId) {
//                hNonMainThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, threadEntry.th32ThreadID);
//                if (hNonMainThread != NULL) {
//                    CloseHandle(hSnapshot);
//                    return hNonMainThread;  // Found a non-main thread, return it
//                }
//            }
//        } while (Thread32Next(hSnapshot, &threadEntry));
//    }
//
//    // If no non-main thread found, return the main one
//    HANDLE hMainThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, mainThreadId);
//    CloseHandle(hSnapshot);
//    return hMainThread;  // Could be NULL if open fails
//}

struct ThreadCandidate2 {
	DWORD tid;
	HANDLE hThread;
	long long score;
	ULONGLONG cycles;
	ULONGLONG cpuTime;
	LONG priority;
	ULONG suspendCount;
	std::wstring description;
};
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);

// Structs for NtQueryInformationThread
typedef struct _KERNEL_USER_TIMES {
	FILETIME CreateTime;
	FILETIME ExitTime;
	FILETIME KernelTime;
	FILETIME UserTime;
} KERNEL_USER_TIMES, * PKERNEL_USER_TIMES;

typedef struct _THREAD_CYCLE_TIME_INFORMATION {
	ULONGLONG AccumulatedCycles;
} THREAD_CYCLE_TIME_INFORMATION, * PTHREAD_CYCLE_TIME_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


#define ThreadBasicInformation       0
#define ThreadTimes                  1
#define ThreadCycleTime             23
#define ThreadSuspendCount          35




HANDLE FindBestApcThread(DWORD targetPid) {
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) return INVALID_HANDLE_VALUE;

	auto NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
		GetProcAddress(hNtDll, "NtQueryInformationThread")
		);
	if (!NtQueryInformationThread) return INVALID_HANDLE_VALUE;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

	THREADENTRY32 te32{};
	te32.dwSize = sizeof(te32);

	std::vector<ThreadCandidate2> candidates;

	if (!Thread32First(hSnapshot, &te32)) {
		CloseHandle(hSnapshot);
		return INVALID_HANDLE_VALUE;
	}

	do {
		if (te32.th32OwnerProcessID != targetPid) continue;

		DWORD tid = te32.th32ThreadID;

		HANDLE hThread = OpenThread(
			THREAD_ALL_ACCESS,
			FALSE,
			tid
		);
		if (!hThread) continue;

		// Query suspend count
		ULONG suspendCount = 999;  // default high penalty if query fails
		NTSTATUS status = NtQueryInformationThread(hThread, ThreadSuspendCount, &suspendCount, sizeof(suspendCount), nullptr);
		if (!NT_SUCCESS(status)) suspendCount = 999;

		// Query user/kernel time
		KERNEL_USER_TIMES times{};
		ULONGLONG totalCpuTime = 0;
		status = NtQueryInformationThread(hThread, ThreadTimes, &times, sizeof(times), nullptr);
		if (NT_SUCCESS(status)) {
			ULONGLONG userTime = ((ULONGLONG)times.UserTime.dwHighDateTime << 32) | times.UserTime.dwLowDateTime;
			ULONGLONG kernelTime = ((ULONGLONG)times.KernelTime.dwHighDateTime << 32) | times.KernelTime.dwLowDateTime;
			totalCpuTime = userTime + kernelTime;
		}

		// Query cycle time
		THREAD_CYCLE_TIME_INFORMATION cycleInfo{};
		ULONGLONG cycles = 0;
		status = NtQueryInformationThread(hThread, ThreadCycleTime, &cycleInfo, sizeof(cycleInfo), nullptr);
		if (NT_SUCCESS(status)) {
			cycles = cycleInfo.AccumulatedCycles;
		}

		// Skip completely idle threads (no activity at all)
		if (cycles == 0 && totalCpuTime == 0) {
			CloseHandle(hThread);
			continue;
		}

		// Query basic info for priority
		THREAD_BASIC_INFORMATION basicInfo{};
		LONG priority = 9;  // default normal if fail
		status = NtQueryInformationThread(hThread, ThreadBasicInformation, &basicInfo, sizeof(basicInfo), nullptr);
		if (NT_SUCCESS(status)) {
			priority = basicInfo.Priority;
		}

		// Thread description
		std::wstring description;
		PWSTR descPtr = nullptr;
		if (SUCCEEDED(GetThreadDescription(hThread, &descPtr)) && descPtr) {
			description = descPtr;
			LocalFree(descPtr);
		}

		// Compute score (long long to avoid overflow with high cycles)
		long long score = 0;

		// Activity (primary factor)
		score += static_cast<long long>(cycles) / 1000000ULL;           // +1 per million cycles
		score += static_cast<long long>(totalCpuTime) / 100000ULL;      // +1 per ~0.01s

		// Bonuses
		if (suspendCount == 0) score += 300;
		if (priority >= 8 && priority <= 10) score += 150;
		bool goodDesc = description.empty() ||
			description.find(L"ThreadPool") != std::wstring::npos ||
			description.find(L"Foreground") != std::wstring::npos ||
			description.find(L"Worker") != std::wstring::npos ||
			description.find(L"pool") != std::wstring::npos;
		if (goodDesc) score += 200;

		// Penalties
		if (suspendCount > 0) score -= 150LL * suspendCount;
		if (priority < 1 || priority > 15) score -= 100;  // unusual priority
		if (!goodDesc && !description.empty()) {
			score -= 100;
			// Extra penalty for known bad/specialized threads
			if (description.find(L"DManip") != std::wstring::npos ||
				description.find(L"Composition") != std::wstring::npos ||
				description.find(L"VideoCapture") != std::wstring::npos ||
				description.find(L"BrokerEvent") != std::wstring::npos ||
				description.find(L"DMIT") != std::wstring::npos) {
				score -= 150;
			}
		}

		candidates.push_back({ tid, hThread, score, cycles, totalCpuTime, priority, suspendCount, std::move(description) });

	} while (Thread32Next(hSnapshot, &te32));

	CloseHandle(hSnapshot);

	if (candidates.empty()) {
		return INVALID_HANDLE_VALUE;
	}

	// Sort: highest score first, tie-break on highest cycles
	std::sort(candidates.begin(), candidates.end(),
		[](const ThreadCandidate2& a, const ThreadCandidate2& b) {
			if (a.score != b.score) return a.score > b.score;
			return a.cycles > b.cycles;
		});

	// Return the best one, close the rest
	HANDLE bestHandle = candidates[0].hThread;
	for (size_t i = 1; i < candidates.size(); ++i) {
		CloseHandle(candidates[i].hThread);
	}

	// Optional debug: print top score (comment out in production)
	// std::wcout << L"Best thread TID: " << candidates[0].tid << L", Score: " << candidates[0].score << std::endl;

	return bestHandle;
}
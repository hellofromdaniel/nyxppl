# nyxppl

**nyxppl** is a simple C tool to enable or disable Windows “Protected Process Light” (PPL) and full Protected Process flags at runtime.  
It dynamically discovers the kernel offsets of `_PS_PROTECTION` and related fields, locates a target process’s `EPROCESS`, and uses RTCore64 to patch the protection byte.

---

## Acknowledgments

Special thanks to [itm4n](https://github.com/itm4n) for the **PPLcontrol** project and his excellent blog posts.  
His work on dynamic offset finding and Protected Process Light bypass greatly inspired this tool.

---

## Features

- **Offset-finder**: scans on-disk `ntoskrnl.exe` exports (`PsIsProtectedProcess`, `PsGetProcessId`, etc.) to extract all required `_EPROCESS` offsets at runtime  
- **Process lookup**: walks `PsInitialSystemProcess`’s `ActiveProcessLinks` to find any PID’s `EPROCESS` base  
- **Read/Write** via RTCore64 driver: arbitrary kernel‐memory access to clear or set protection flags  
- **No hard-coded offsets** — works across Windows versions and ASLR

---
## Usage


nyxppl.exe <PID> <ProtectionCode>


- `<PID>`  
  Process ID of the target process (e.g. the PID of `lsass.exe`).

- `<ProtectionCode>`  
  A one-byte hex value specifying exactly which protection level to apply.

### Examples

```cmd
# Remove all protection
nyxppl.exe 1234 0x00

# Protected Process Light with Antimalware signer
nyxppl.exe 1234 0x31

# Full Protected Process with WinTcb signer
nyxppl.exe 1234 0x62
```
| Code | Description                  | Meaning                                  |
| ---- | ---------------------------- | ---------------------------------------- |
| 0x00 | None                         | No protection                            |
| 0x01 | PPL, Signer=None             | Protected Process Light, unsigned        |
| 0x11 | PPL, Signer=Authenticode     | PPL for CA-signed binaries               |
| 0x21 | PPL, Signer=CodeGen          | PPL for JIT/CodeGen code                 |
| 0x31 | PPL, Signer=Antimalware      | PPL for antimalware engines              |
| 0x41 | PPL, Signer=Lsa              | PPL for Local Security Authority (LSASS) |
| 0x51 | PPL, Signer=Windows          | PPL for core OS components               |
| 0x61 | PPL, Signer=WinTcb           | PPL for Trusted Computing Base           |
| 0x71 | PPL, Signer=WinSystem        | PPL for system-level components          |
| 0x81 | PPL, Signer=App              | PPL for UWP/Store applications           |
| 0x02 | Full PP, Signer=None         | Full Protected Process, unsigned         |
| 0x12 | Full PP, Signer=Authenticode | Full PP for CA-signed binaries           |
| 0x22 | Full PP, Signer=CodeGen      | Full PP for JIT/CodeGen code             |
| 0x32 | Full PP, Signer=Antimalware  | Full PP for antimalware engines          |
| 0x42 | Full PP, Signer=Lsa          | Full PP for Local Security Authority     |
| 0x52 | Full PP, Signer=Windows      | Full PP for core OS components           |
| 0x62 | Full PP, Signer=WinTcb       | Full PP for Trusted Computing Base       |
| 0x72 | Full PP, Signer=WinSystem    | Full PP for system-level components      |
| 0x82 | Full PP, Signer=App          | Full PP for UWP/Store applications       |


Notes

    Type

        Use Type=1 (low-bits 001) for PPL.

        Use Type=2 (low-bits 010) for Full PP.

    Signer is stored in the high nibble (bits 4–7).

    Audit bit (bit 3) is reserved and not currently used.

To display this help from the command line, run without arguments:

```cmd
nyxppl.exe
```

---

## Compile

```bash
# Windows x64, using MinGW
gcc nyxppl.c -lpsapi -o nyxppl.exe

```

---

## Install MSI Driver

```cmd
sc.exe create RTCore64 type= kernel start= auto binPath= C:\PATH\TO\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
net start RTCore64
```

## Silent Driver Loading with ioncodes/SilentLoad

By default loading a kernel driver via `sc.exe` or `CreateService()` emits “Driver Loaded” events that can be picked up by EDR/AV or ETW. To avoid generating those alerts, you can use the **[SilentLoad](https://github.com/ioncodes/SilentLoad/tree/master)** project to load RTCore64.sys “service-less”:


Configure main.cpp
SilentLoad doesn't drop the driver for you. Refer to the following to lines:

```c
#define SERVICE_NAME L"RTCore64"
#define DRIVER_PATH  L"\\??\\C:\PATH\\RTCore64.sys"

```


Verify

    No “Service Installed” or “Driver Loaded” event is logged.

    You can now open \\.\RTCore64 from user-mode and perform Read8/Write8 patches as usual.

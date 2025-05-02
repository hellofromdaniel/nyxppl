# nyxppl

**nyxppl** is a simple C tool to enable or disable Windows “Protected Process Light” (PPL) and full Protected Process flags at runtime.  
It dynamically discovers the kernel offsets of `_PS_PROTECTION` and related fields, locates a target process’s `EPROCESS`, and uses RTCore64 to patch the protection byte.

---

## Features

- **Offset-finder**: scans on-disk `ntoskrnl.exe` exports (`PsIsProtectedProcess`, `PsGetProcessId`, etc.) to extract all required `_EPROCESS` offsets at runtime  
- **Process lookup**: walks `PsInitialSystemProcess`’s `ActiveProcessLinks` to find any PID’s `EPROCESS` base  
- **Read/Write** via RTCore64 driver: arbitrary kernel‐memory access to clear or set protection flags  
- **No hard-coded offsets** — works across Windows versions and ASLR

---
## Usage



---

## Compile

```bash
# Windows x64, using MinGW
gcc nyxppl.c -lpsapi -o nyxppl.exe

```


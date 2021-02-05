---
title: "PEB/TEB/TIB Structure Offsets"
author: Travis Mathison
date: 2021-02-05 12:10:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, assembly]
---

## Intro
This is really more of a reference table post to show the PEB/TEB/TIB structure notable offsets that are commonly seen in malware as it performs references after fetching the Process Environment Block (PEB) via `FS:[0x30]`.  Knowing the offsets in the structures can help quickly identify them during reverse engineering your binary.

Attribution: The structure offsets shown in the below tables are directly pulled from [Amr Thabet's](https://github.com/AmrThabet) [x86Emulator](https://github.com/AmrThabet/x86Emulator) project in the file [tib.h](https://github.com/AmrThabet/x86Emulator/blob/master/tib.h).

## PEB Table
The Process Environment Block structure contains the process wide data structures which include global context, startup parameters, data structures for the program image loader, the program image base address, and synchronization objects.

| Name | Offset |
|:---|:----|
| char InheritedAddressSpace | `+00` |
| char ReadImageFileExecOptions | `+1` |
| DWORD Mutant | `+04` |
| DWORD ImageBaseAddress | `+08` |
| _PEB_LDR_DATA* LoaderData | `+0C` |
| DWORD ProcessParameters | `+10` |
| DWORD SubSystemData | `+14` |
| DWORD ProcessHeap | `+18` |
| DWORD FastPebLock | `+1C` |
| DWORD FastPebLockRoutine | `+20` |
| DWORD FastPebUnlockRoutine | `+24` |
| DWORD EnvironmentUpdateCount | `+28` |
| DWORD KernelCallbackTable | `+2C` |
| DWORD EventLogSection | `+30` |
| DWORD EventLog | `+34` |
| DWORD FreeList | `+38` |
| DWORD TlsExpansionCounter | `+3C` |
| DWORD TlsBitmap | `+40` |
| DWORD TlsBitmapBits[0x2] || 
| DWORD NumberOfHeaps | `+88` |
| DWORD MaximumNumberOfHeaps | `+8C` |
| DWORD *ProcessHeaps | `+90` |

## TEB Table
The Thread Environment Block contains information on the currently running thread ranging from the thread ID, to exceptions and error states, to referencing the PEB structure itself.

| Name | Offset |
|:---|:----|
| DWORD EnvironmentPointer | `+1C` |
| DWORD ProcessId | `+20` |
| DWORD threadId | `+24` |
| DWORD ActiveRpcInfo | `+28` |
| DWORD ThreadLocalStoragePointer | `+2C` |
| PEB* Peb | `+30` |
| DWORD LastErrorValue | `+34` |
| DWORD CountOfOwnedCriticalSections; | `+38` |
| DWORD CsrClientThread | `+3C` |
| DWORD Win32ThreadInfo | `+40` |
| DWORD Win32ClientInfo[0x1F] | `+44` |
| DWORD WOW32Reserved | `+48` |
| DWORD CurrentLocale | `+4C` |
| DWORD FpSoftwareStatusRegister | `+50` |
| DWORD SystemReserved1[0x36] | `+54` |
| DWORD Spare1 | `+58` |
| DWORD ExceptionCode | `+5C` |
| DWORD SpareBytes1[0x28] | `+60` |
| DWORD SystemReserved2[0xA] | `+64` |
| DWORD GdiRgn | `+68` |
| DWORD GdiPen | `+6C` |
| DWORD GdiBrush | `+70` |
| DWORD RealClientId1 | `+74` |
| DWORD RealClientId2 | `+78` |
| DWORD GdiCachedProcessHandle | `+7C` |
| DWORD GdiClientPID | `+80` |
| DWORD GdiClientTID | `+84` |
| DWORD GdiThreadLocaleInfo | `+88` |
| DWORD UserReserved[5] | `+8C` |
| DWORD GlDispatchTable[0x118] | `+90` |
| DWORD GlReserved1[0x1A] | `+94` |
| DWORD GlReserved2 | `+98` |
| DWORD GlSectionInfo | `+9C` |
| DWORD GlSection | `+A0` |
| DWORD GlTable | `+A4` |
| DWORD GlCurrentRC | `+A8` |
| DWORD GlContext | `+AC` |
| DWORD LastStatusValue | `+B0` |
| char* StaticUnicodeString | `+B4` |
| char StaticUnicodeBuffer[0x105] | `+B8` |
| DWORD DeallocationStack | `+BC` |
| DWORD TlsSlots[0x40] | `+C0` |
| DWORD TlsLinks | `+C4` |
| DWORD Vdm | `+C8` |
| DWORD ReservedForNtRpc | `+CC` |
| DWORD DbgSsReserved[0x2] | `+D0` |

## TIB Table
This contains similar information to TEB but was for the non-Windows NT versions (e.g. Windows 9x era and below).  The TEB is the structure for Windows NT, 2000, XP, Vista, 7, 8, and 10.

| Name | Offset |
|:---|:----|
| _PEXCEPTION_REGISTRATION_RECORD* ExceptionList | `FS:[0x00]` |
| DWORD StackBase | `FS:[0x04]` |
| DWORD StackLimit | `FS:[0x08]` |
| DWORD SubSystemTib | `FS:[0x0C]` |
| DWORD FiberData | `FS:[0x10]` |
| DWORD ArbitraryUserPointer | `FS:[0x14]` |
| DWORD TIBOffset | `FS:[0x18]` |

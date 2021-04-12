---
title: "String and function hiding techniques"
author: Travis Mathison
date: 2021-04-12 12:10:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, emotet, debugging, ida, ghidra, memory, techniques, stack, obfuscation, ntdll.dll, kernel32.dll]
---

**Table of Contents**
- TOC
{:toc}

## Intro
This is carrying on from the previous post on finding the start of the malicious user code in the MFC application.  While continuing to step through there are several notable techniques that are worth mentioning as they are common for a lot of malware.  

Due to the size of this sample I won't be continuing to analyze every assembly instruction and will use a more dynamic approach to attempt to locate the key areas big actions take place like copying itself to a new location and deleting it's original file as well as performing a series of posts to a large collection of C&C IPs.

This post will discuss three techniques seen early on:
1. Hiding strings via single byte pushes to stack
2. Getting DllBase and export table to crawl export functions of ntdll.dll and kernel32.dll
3. Encoded string obfuscation

## The malware sample used in this blog post
* MD5 hash: `a4513379dad5233afa402cc56a8b9222`
* VirusTotal link to sample: [https://www.virustotal.com/gui/file/ccd380ea868ffad4f960d7455fecf88c2ac3550001bbb6c21c31ae70b3bbf4f6/detection](https://www.virustotal.com/gui/file/ccd380ea868ffad4f960d7455fecf88c2ac3550001bbb6c21c31ae70b3bbf4f6/detection)

## Visual of observed flows
An overall digram of the beginning flow that contains the techniques to be discussed.<br/>
<img style="align:left" src="{{ site.url }}/assets/img/blogging/tdc-phase2.png"/>

Numbers techniques are tied to in the diagram:<br/>
<img style="align:left" src="{{ site.url }}/assets/img/blogging/tdc-phase2-notable-techniques.png" />

## Notable Techniques
### Hiding strings via single byte pushes to stack
Observe the following sequence of assembly.  A repeating pattern of moving a single hex byte to `EAX` and pushing it to the stack is performed. NOTE: often it will be full `DWORD`'s that are pushed to put together a final string.
```c
00500022    B8 6B000000     MOV EAX,6B
00500027    66:8945 98      MOV WORD PTR SS:[EBP-68],AX
0050002B    B9 65000000     MOV ECX,65
00500030    66:894D 9A      MOV WORD PTR SS:[EBP-66],CX
00500034    BA 72000000     MOV EDX,72
00500039    66:8955 9C      MOV WORD PTR SS:[EBP-64],DX
0050003D    B8 6E000000     MOV EAX,6E
00500042    66:8945 9E      MOV WORD PTR SS:[EBP-62],AX
00500046    B9 65000000     MOV ECX,65
0050004B    66:894D A0      MOV WORD PTR SS:[EBP-60],CX
0050004F    BA 6C000000     MOV EDX,6C
00500054    66:8955 A2      MOV WORD PTR SS:[EBP-5E],DX
00500058    B8 33000000     MOV EAX,33
0050005D    66:8945 A4      MOV WORD PTR SS:[EBP-5C],AX
00500061    B9 32000000     MOV ECX,32
00500066    66:894D A6      MOV WORD PTR SS:[EBP-5A],CX
0050006A    BA 2E000000     MOV EDX,2E
0050006F    66:8955 A8      MOV WORD PTR SS:[EBP-58],DX
00500073    B8 64000000     MOV EAX,64
00500078    66:8945 AA      MOV WORD PTR SS:[EBP-56],AX
0050007C    B9 6C000000     MOV ECX,6C
00500081    66:894D AC      MOV WORD PTR SS:[EBP-54],CX
00500085    BA 6C000000     MOV EDX,6C
0050008A    66:8955 AE      MOV WORD PTR SS:[EBP-52],DX
0050008E    33C0            XOR EAX,EAX
00500090    66:8945 B0      MOV WORD PTR SS:[EBP-50],AX
00500094    B9 6E000000     MOV ECX,6E
00500099    66:894D B4      MOV WORD PTR SS:[EBP-4C],CX
0050009D    BA 74000000     MOV EDX,74
005000A2    66:8955 B6      MOV WORD PTR SS:[EBP-4A],DX
005000A6    B8 64000000     MOV EAX,64
005000AB    66:8945 B8      MOV WORD PTR SS:[EBP-48],AX
005000AF    B9 6C000000     MOV ECX,6C
005000B4    66:894D BA      MOV WORD PTR SS:[EBP-46],CX
005000B8    BA 6C000000     MOV EDX,6C
005000BD    66:8955 BC      MOV WORD PTR SS:[EBP-44],DX
005000C1    B8 2E000000     MOV EAX,2E
005000C6    66:8945 BE      MOV WORD PTR SS:[EBP-42],AX
005000CA    B9 64000000     MOV ECX,64
005000CF    66:894D C0      MOV WORD PTR SS:[EBP-40],CX
005000D3    BA 6C000000     MOV EDX,6C
005000D8    66:8955 C2      MOV WORD PTR SS:[EBP-3E],DX
005000DC    B8 6C000000     MOV EAX,6C
005000E1    66:8945 C4      MOV WORD PTR SS:[EBP-3C],AX
005000E5    33C9            XOR ECX,ECX
005000E7    66:894D C6      MOV WORD PTR SS:[EBP-3A],CX
005000EB    8D55 B4         LEA EDX,DWORD PTR SS:[EBP-4C]
005000EE    52              PUSH EDX
```

All these bytes pushed to the stack result in the string seen below (also note, when pushing to the stack it is being done in reverse order).  The malware could have just had the full string saved in the `.data` section and loaded it, however, it would then come up in static analysis when searching for strings.

Many variations of this technique are used to hide DLL names or names of exported functions it will later fetch via `GetProcAddress` so they don't show up in the export table during static analysis.
```c
0019F3EC              6B 00 65 00 72 00 6E 00 65 00 6C 00      k.e.r.n.e.l.
0019F3FC  33 00 32 00 2E 00 64 00 6C 00 6C 00 00 00 19 00  3.2...d.l.l....
0019F40C  6E 00 74 00 64 00 6C 00 6C 00 2E 00 64 00 6C 00  n.t.d.l.l...d.l.
0019F41C  6C 00                                            l.
```

### Getting DllBase and export table
Another sequence of calls that must be known has to do with getting the Process Environment Block (PEB), the LoaderData, the ModuleList, and the export table.  Let's take a look at two important structures and their offsets.

The Thread Environment Block (TEB) can be accessed via calls that look like `DWORD PTR FS:[30]`.  In fact his is the most common one as its gets a reference to the PEB structure which is where the rest of the crawling around the structures typically start from.

The following structures and offsets are referenced in the following examples.

#### Thread Environment Block (TEB)
```c
struct TEB {
  DWORD         EnvironmentPointer;         //+1C
  DWORD         ProcessId;                  //+20
  DWORD         threadId;                   //+24
  DWORD         ActiveRpcInfo;              //+28
  DWORD         ThreadLocalStoragePointer;  //+2C
  PEB*          Peb;                        //+30
  ...and more...
```

#### Process Environment Block (PEB)
```c
struct PEB {
  char           InheritedAddressSpace;    //+00
  char           ReadImageFileExecOptions; //+01
  char           BeingDebugged;            //+02
  char           Spare;                    //+03
  DWORD          Mutant;                   //+04
  DWORD          ImageBaseAddress;         //+08
  _PEB_LDR_DATA* LoaderData;               //+0C
  ...and more...
```

#### PEB Loader Data
```c
struct _PEB_LDR_DATA {
    DWORD        Length_;                         //+00
    DWORD        Initialized;                     //+04
    DWORD        SsHandle;                        //+08
    __LIST_ENTRY InLoadOrderModuleList;           //+0C
    __LIST_ENTRY InMemoryOrderModuleList;         //+14
    __LIST_ENTRY InInitializationOrderModuleList; //+1C
    DWORD        EntryInProgress;                 //+24  
    DWORD        ShutdownInProgress;              //+28
    DWORD        ShutdownThreadId;                //+2C
};
```

#### PEB Loader Data Entry
```c
struct _LDR_DATA_TABLE_ENTRY{
  __LIST_ENTRY InLoadOrderLinks;               //+00
  __LIST_ENTRY InMemoryOrderLinks;             //+08
  __LIST_ENTRY InInitializationOrderLinks;     //+10
  DWORD        DllBase;                        //+18
  DWORD        EntryPoint;                     //+1C
  DWORD        SizeOfImage;                    //+20
  DWORD        FullDllNameLength;              //+24
  char*        FullDllName; // _UNICODE_STRING //+28
  DWORD        BaseDllNameLength;              //+2C
  char*        BaseDllName; //_UNICODE_STRING  //+30
  DWORD        Flags;                          //+34
  short        LoadCount;                      //+38
  short        TlsIndex;                       //+3C
  ...and more...
};
```

In our sample, we have the following function.  It attempts to get the base address of `ntdll.dll` through the following sequence of structure crawling:<br/>
<img style="align:left" src="{{ site.url }}/assets/img/blogging/tdc-phase2-get-dllbase.png" />

The below assembly can be summed up as "find ntdll.dll and return the base address of it".
```c
00500260    55              PUSH EBP
00500261    8BEC            MOV EBP,ESP
00500263    83EC 10         SUB ESP,10
00500266    64:A1 30000000  MOV EAX,DWORD PTR FS:[30]     ; PEB
0050026C    8945 F4         MOV DWORD PTR SS:[EBP-C],EAX
0050026F    8B4D F4         MOV ECX,DWORD PTR SS:[EBP-C]
00500272    8B51 0C         MOV EDX,DWORD PTR DS:[ECX+C]  ; _PEB_LDR_DATA* LoaderData
00500275    8955 F8         MOV DWORD PTR SS:[EBP-8],EDX
00500278    8B45 F8         MOV EAX,DWORD PTR SS:[EBP-8]
0050027B    8B48 0C         MOV ECX,DWORD PTR DS:[EAX+C]  ; __LIST_ENTRY InLoadOrderModuleList
0050027E    894D F0         MOV DWORD PTR SS:[EBP-10],ECX
00500281    8B55 F8         MOV EDX,DWORD PTR SS:[EBP-8]
00500284    8B42 0C         MOV EAX,DWORD PTR DS:[EDX+C]
00500287    8945 FC         MOV DWORD PTR SS:[EBP-4],EAX
0050028A    8B4D 08         MOV ECX,DWORD PTR SS:[EBP+8]
0050028D    51              PUSH ECX
0050028E    8B55 FC         MOV EDX,DWORD PTR SS:[EBP-4]
00500291    8B42 30         MOV EAX,DWORD PTR DS:[EDX+30] ; name of running binary
00500294    50              PUSH EAX
00500295    E8 66000000     CALL 00500300                 ; compare_strings
0050029A    83C4 08         ADD ESP,8
0050029D    85C0            TEST EAX,EAX
0050029F    75 08           JNZ SHORT 005002A9            ; do not match
005002A1    8B4D FC         MOV ECX,DWORD PTR SS:[EBP-4]  ; ECX = _LDR_DATA_TABLE_ENTRY
005002A4    8B41 18         MOV EAX,DWORD PTR DS:[ECX+18] ; EAX = DWORD DllBase
005002A7    EB 12           JMP SHORT 005002BB            ; found match -> exit loop
005002A9    8B55 FC         MOV EDX,DWORD PTR SS:[EBP-4]
005002AC    8B02            MOV EAX,DWORD PTR DS:[EDX]
005002AE    8945 FC         MOV DWORD PTR SS:[EBP-4],EAX
005002B1    8B4D FC         MOV ECX,DWORD PTR SS:[EBP-4]
005002B4    3B4D F0         CMP ECX,DWORD PTR SS:[EBP-10]
005002B7  ^ 75 D1           JNZ SHORT 0050028A
005002B9    33C0            XOR EAX,EAX
005002BB    8BE5            MOV ESP,EBP
005002BD    5D              POP EBP
005002BE    C3              RETN
```

Now that we have the `DllBase` of `ntdll.dll` we can go a step further and get to the EXPORT table to enumerate it's exported functions (this same process can be done for any DLL, not just for `ntdll.dll`).

The following structure is the target of the next action this malware performs which is to get the exported names, addresses, and ordinals.

```c
struct image_export_directory
{
  unsigned long characteristics;          //+00
  unsigned long timestamp;                //+04
  unsigned short major_version;           //+08
  unsigned short minor_version;           //+0A
  unsigned long name;                     //+0C
  unsigned long base;                     //+10
  unsigned long number_of_functions;      //+14
  unsigned long number_of_names;          //+18
  unsigned long address_of_functions;     //+1C // RVA from base of image
  unsigned long address_of_names;         //+20 // RVA from base of image
  unsigned long address_of_name_ordinals; //+24 // RVA from base of image
};
```

The below function has access to the `BaseDll` address which is stored in `EBP+8`.

```c
00500540    55              PUSH EBP
00500541    8BEC            MOV EBP,ESP
00500543    83EC 20         SUB ESP,20
00500546    8B45 08         MOV EAX,DWORD PTR SS:[EBP+8]   ; EAX = ntdll.dll->BaseDll
00500549    8945 F4         MOV DWORD PTR SS:[EBP-C],EAX
0050054C    8B4D F4         MOV ECX,DWORD PTR SS:[EBP-C]
0050054F    8B55 08         MOV EDX,DWORD PTR SS:[EBP+8]
00500552    0351 3C         ADD EDX,DWORD PTR DS:[ECX+3C]  ; PE offset (skip DOS header)
00500555    8955 F0         MOV DWORD PTR SS:[EBP-10],EDX
00500560    8B55 F0         MOV EDX,DWORD PTR SS:[EBP-10]     ; PE offset
00500563    8B45 08         MOV EAX,DWORD PTR SS:[EBP+8]      ; ntdll.dll->BaseDll
00500566    03440A 78       ADD EAX,DWORD PTR DS:[EDX+ECX+78] ; EXPORT table data entry

0050056A    8945 F8         MOV DWORD PTR SS:[EBP-8],EAX
0050056D    8B4D F8         MOV ECX,DWORD PTR SS:[EBP-8]
00500570    8B55 08         MOV EDX,DWORD PTR SS:[EBP+8]

; RVA of Name Pointer Table - addresses of exported function names
00500573    0351 20         ADD EDX,DWORD PTR DS:[ECX+20]                 
00500576    8955 EC         MOV DWORD PTR SS:[EBP-14],EDX
00500579    8B45 F8         MOV EAX,DWORD PTR SS:[EBP-8]
0050057C    8B4D 08         MOV ECX,DWORD PTR SS:[EBP+8]

; RVA of Address Table - addresses of exported functions
0050057F    0348 1C         ADD ECX,DWORD PTR DS:[EAX+1C]
00500582    894D E0         MOV DWORD PTR SS:[EBP-20],ECX
00500585    8B55 F8         MOV EDX,DWORD PTR SS:[EBP-8]
00500588    8B45 08         MOV EAX,DWORD PTR SS:[EBP+8]

; RVA of Ordinal Table - function order number as listed in the table
0050058B    0342 24         ADD EAX,DWORD PTR DS:[EDX+24]
```

When studying the [PE-Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) we can see that Win32 binaries have a DOS Stub that is placed at the front of the EXE image. The format states that:
> "At location 0x3c, the stub has the file offset to the PE signature. This information enables Windows to properly execute the image file, even though it has an MS-DOS stub. This file offset is placed at location 0x3c during linking."

With this known, we can view a table of offsets relative to `DllBase+3C` to make sense of which structures or addresses the malware is after in the above sample.<br/>

|---|---|
|Structure / Address|Offset|
|:--|:---|
| RVA of Export Table | 0x78 |
| address_of_functions | 0x78+0x1C|
| address_of_names| 0x78+0x20|
| address_of_name_ordinals | 0x78+0x24|

Now, with `EBP-14` containing the addresses of exported function names we see it iterate over it via a counter in `ECX` and index to each subsequent item which are all 4 bytes long.

```c
; ECX = counter
005005AE    8B4D FC         MOV ECX,DWORD PTR SS:[EBP-4]
...
; index into next exported function name
005005B7    03048A          ADD EAX,DWORD PTR DS:[EDX+ECX*4]
```
In this sample we are analyzing it is looping through searching for specific exported function names that are encoded in some way. As it will turn out, the method in which is encodes them doesn't really matter but it does show another example of how the names would not turn up during the initial static analysis.

### Encoded string obfuscation
This sample decrypted a resource file found as RCData = 666 (0x29A).  You can see this if you view the original binary in Resource Hacker.  It is mapped to `00560000` and called into via the following instruction:

```c
00560024    E8 04000000     CALL 0056002D
```

In the following instructions we see a case where the name of the exported function was encoded in some way and stored.  Upon looping through the exported function names via the previous technique it will use the same encoding function to generate a comparable string to perform a match on.

You can think of this similar to how passwords are hashed and the hash is stored.  Upon typing a password in it re-hashes it in the same way and then compares them.  This is essentially what we see here and the exact method of encoding becomes less important once it was understood exactly what the `00560467` function was doing.

```c
0056002D    83EC 48         SUB ESP,48
00560030    836424 18 00    AND DWORD PTR SS:[ESP+18],0
00560035    B9 4C772607     MOV ECX,726774C
0056003A    53              PUSH EBX
0056003B    55              PUSH EBP
0056003C    56              PUSH ESI
0056003D    57              PUSH EDI
0056003E    33F6            XOR ESI,ESI
00560040    E8 22040000     CALL 00560467 ; 726774C = KERNEL32.LoadLibraryA
00560045    B9 49F70278     MOV ECX,7802F749
0056004A    894424 1C       MOV DWORD PTR SS:[ESP+1C],EAX
0056004E    E8 14040000     CALL 00560467 ; 7802F749 = KERNEL32.GetProcAddress
00560053    B9 58A453E5     MOV ECX,E553A458
00560058    894424 20       MOV DWORD PTR SS:[ESP+20],EAX
0056005C    E8 06040000     CALL 00560467 ; E553A458 = KERNEL32.VirtualAlloc
00560061    B9 10E18AC3     MOV ECX,C38AE110
00560066    8BE8            MOV EBP,EAX
00560068    E8 FA030000     CALL 00560467 ; C38AE110 = KERNEL32.VirtualProtect
0056006D    B9 AFB15C94     MOV ECX,945CB1AF
00560072    894424 2C       MOV DWORD PTR SS:[ESP+2C],EAX
00560076    E8 EC030000     CALL 00560467 ; 945CB1AF = ntdll.ZwFlushInstructionCache
0056007B    B9 33009E95     MOV ECX,959E0033
00560080    894424 30       MOV DWORD PTR SS:[ESP+30],EAX
00560084    E8 DE030000     CALL 00560467 ; 959E0033 = KERNELBA.GetNativeSystemInfo
00560089    8BD8            MOV EBX,EAX
0056008B    8B4424 5C       MOV EAX,DWORD PTR SS:[ESP+5C]
0056008F    8B78 3C         MOV EDI,DWORD PTR DS:[EAX+3C]
00560092    03F8            ADD EDI,EAX
00560094    897C24 10       MOV DWORD PTR SS:[ESP+10],EDI
00560098    813F 50450000   CMP DWORD PTR DS:[EDI],4550
```

In the above sample it has pre-encoded strings shown as `726774C`, `7802F749`, `E553A458`, `C38AE110`, `945CB1AF`, and `959E0033`.  Once the matching function name (when encoded) matches this it will return the base address to it and store it in the stack for later use.  

It utlimately resolves the following Win32 functions that it will use:
```c
KERNEL32.LoadLibraryA
KERNEL32.GetProcAddress
KERNEL32.VirtualAlloc
KERNEL32.VirtualProtect
ntdll.ZwFlushInstructionCache
KERNELBA.GetNativeSystemInfo
```

These are important and very telling functions that you would want to break and understand what they are loading and or allocating.  When you open CFF Explorer on the original file you will not see any of these listed in the Import Address Table (IAT).

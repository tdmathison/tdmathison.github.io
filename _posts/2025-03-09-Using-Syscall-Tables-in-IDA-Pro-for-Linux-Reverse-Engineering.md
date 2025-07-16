---
title: "Using Syscall Tables in IDA Pro for Linux Reverse Engineering"
date: 2025-03-09 11:20:00 -0700
categories: [Blogging]
tags: [ida, syscall, linux]
---

## Summary
When reverse engineering Linux binaries, especially statically linked or stripped ELF files, understanding system calls is essential. Linux binaries often invoke syscalls directly via `int 0x80`, `syscall`, or `sysenter`, bypassing libc wrappers.

**This post will walk you through:**
* Identifying the Linux kernel version of your target.
* Finding the correct syscall table.
* Creating a custom enumeration in IDA Pro to automatically resolve syscall numbers to names.

## Identify the Linux Kernel Version
When reversing malware or forensic images, you often start with an unknown environment. To determine which syscall table to use, you need the kernel version.

**Sources to check:**
* Hardcoded version string in binary (use IDA/Ghidra string search: `uname`, `Linux version`, etc).
* Forensics of system images: look in `/proc/version`, `/boot/vmlinuz-*`, or the kernel logs.
* Captured system calls from dynamic analysis tools (e.g. `strace`) that match a known version.
* If you're reversing an ELF and see syscalls like `syscall #322`, you’ll need to know what `322` maps to on a specific kernel version.

## Match Syscalls to a Versioned Table
Now that you know the kernel version (e.g. `5.4.0`), consult an online syscall table reference like:

* [https://syscall.sh](https://syscall.sh)
* [https://syscalls.mebeim.net/](https://syscalls.mebeim.net/)

Example: Searching for syscall `322` on Linux x86_64 kernel 5.4 yields:

```c
322: pidfd_send_signal
```

This mapping is critical when you reverse this:

```c
mov     eax, 0x142  ; syscall 322
syscall
```

You now know the binary is sending a signal to a process via file descriptor.


## Create a Syscall Enumeration in IDA Pro
Creating an enum in IDA lets you label syscall numbers with their names across disassembly views and pseudocode.

Steps in IDA Pro:
* Open the Enums window (`Shift+F9` or `View → Open Subviews → Enums`).
* Click Insert to create a new enum:
  * Name: `linux_syscalls_x64`
  * Width: `4 bytes` (or `8 bytes` for `x64`)
  * Populate it using a list of syscalls from your kernel version:

Example:
```c
__enum__ linux_syscalls_x64 {
    SYS_read = 0,
    SYS_write = 1,
    SYS_open = 2,
    SYS_close = 3,
    ...
    SYS_pidfd_send_signal = 322,
};
```

## Apply the Enum in Code View
In disassembly:
* Highlight the immediate syscall number (e.g. `mov eax, 0x142`)
* Press `M` to apply the enum.
* Select `linux_syscalls_x64`.

IDA will now show:

```c
mov     eax, SYS_pidfd_send_signal
```

## Auto-Applying Syscall Enums with a Script
You can automate this using IDC or Python:

```python
import idautils
import ida_enum

eid = ida_enum.get_enum("linux_syscalls_x64")
if eid == ida_enum.BADADDR:
    print("Enum not found.")
else:
    for ea in idautils.Functions():
        if idc.get_operand_type(ea, 1) == idc.o_imm:
            imm = idc.get_operand_value(ea, 1)
            idc.op_enum(ea, 1, eid, 0)
```

This will auto-apply the enum to all `mov eax`, `imm` instructions across functions.

## Conclusion
System call numbers are the "API" of the Linux kernel. By combining kernel version knowledge with syscall tables and IDA enums, you can:
* Quickly understand syscall-based behavior.
* Decode obfuscated syscall wrappers.
* Automate analysis across Linux rootkits, malware, or even legitimate ELF binaries.

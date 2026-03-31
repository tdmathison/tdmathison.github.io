---
title: "MuddyWater LightPhoenix Deobfuscation"
date: 2026-04-21 10:05:00 -0700
categories: [Blogging]
tags: [MuddyWater, UNC3313, UNC5667, malware, ida, LightPhoenix, backdoor]
---

## Summary
The malware sample from this post is the LightPhoenix malware that was unpacked from the malware loading from a previous post.

[MuddyWater Malware Loader drops LightPhoenix](https://www.travismathison.com/posts/MuddyWater-Malware-Loader-drops-LightPhoenix/)

This post explores some of the techniques the malware performs for obfuscation.  There is a lot of overlap with the loader due to it being written by the same threat actor (most likely). However, there are some notable differences.  This malware ultimately sets up a Command-and-Control (C2) loop allowing for running commands on the target machine and upload files.

The hashes to both binaries are in the following table (if you want to follow along in IDA/Binja/Ghidra).

| Hash | Description |
|:---|:----|
| 32F51A376A8277649088047DD61EFDF5 | The malware loader |
| 96CA9282847651CB806ADAA82E532D17  | The embedded payload (LightPhoenix) |

## Analysis
### Opening the malware binary in IDA Pro
As soon as we investigate WinMain we see the same situation as we saw in the loader where global variables are clearly being used as functions.  They are resolved during initialization before `WinMain` is executed. The first step will be to analyze the initializer functions and resolve the global variables.

NOTE: For details on the initializer functions and where to locate them see the previous post on the loader [here](https://www.travismathison.com/posts/MuddyWater-Malware-Loader-drops-LightPhoenix/).

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/00.png"/><br/>
Figure 1: Showing unknown global variable in WinMain</div><br />

### String decoding variant 1 – Hex byte manipulation
There are several techniques that this malware uses to obfuscate strings.  This is one of them and there are several variants present.  We will look at one of them to understand it a little better.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/01.png"/><br/>
Figure 2: Function preparing to deobfuscate the C2 domain name</div><br />

These are 32-bit integers, but the function treats them as `_WORD *`, so in memory they become 14 16-bit values due to little-endian layout.

```c
a1[0]  = 0x00E5
a1[1]  = 0x00CA
a1[2]  = 0x00AA
a1[3]  = 0x00DC
a1[4]  = 0x00E7
a1[5]  = 0x00EB
a1[6]  = 0x00CA
a1[7]  = 0x0099
a1[8]  = 0x00DB
a1[9]  = 0x009F
a1[10] = 0x00E6
a1[11] = 0x00D7
a1[12] = 0x009D
a1[13] = 0x0073
```

NOTE: In other variants, the bytes that are sent into the function that performs the final decoding comes from a `xmmword` reference instead.  Below is an example of that from a different function that ultimately resolves the string `“WinHttpReadData”`.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/02.png"/><br/>
Figure 3: Function decoding a string using bytes from an xmmword value</div><br />

These starting bytes are passed into a second function that performs additional logic that subtracts a repeated set of constants (`0x77`, `0x65`, `0x36`, `0x73`, `0x71`) from those `WORD`s.

```c
v3[0]  = a1[0]  - 0x77
v3[1]  = a1[1]  - 0x65
v3[2]  = a1[2]  - 0x36
v3[3]  = a1[3]  - 0x73
v3[4]  = a1[4]  - 0x71
v3[5]  = a1[5]  - 0x77
v3[6]  = a1[6]  - 0x65
v3[7]  = a1[7]  - 0x36
v3[8]  = a1[8]  - 0x73
v3[9]  = a1[9]  - 0x71
v3[10] = a1[10] - 0x77
v3[11] = a1[11] - 0x65
v3[12] = a1[12] - 0x36
v3[13] = a1[13] - 0x73
```

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/03.png"/><br/>
Figure 4: Decoding function that resolves the final string</div><br />

After the modifications are made to the hex bytes it will reveal the final bytes that resolve to the string.  Throughout the malware there are many versions of this and not all of them are the same.

```c
0xE5 - 0x77 = 0x6E = 'n'
0xCA - 0x65 = 0x65 = 'e'
0xAA - 0x36 = 0x74 = 't'
0xDC - 0x73 = 0x69 = 'i'
0xE7 - 0x71 = 0x76 = 'v'
0xEB - 0x77 = 0x74 = 't'
0xCA - 0x65 = 0x65 = 'e'
0x99 - 0x36 = 0x63 = 'c'
0xDB - 0x73 = 0x68 = 'h'
0x9F - 0x71 = 0x2E = '.'
0xE6 - 0x77 = 0x6F = 'o'
0xD7 - 0x65 = 0x72 = 'r'
0x9D - 0x36 = 0x67 = 'g'
0x73 - 0x73 = 0x00 = '\0'
```

So, the decoded string is:
`L"netivtech.org"`

Translated into C code it would be something like:

```c
wchar_t *decode_string(const WORD *src)
{
    static const WORD key[] = {0x77, 0x65, 0x36, 0x73, 0x71};
    wchar_t *out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 14 * sizeof(wchar_t));
    if (!out)
        return NULL;

    for (int i = 0; i < 14; i++)
        out[i] = src[i] - key[i % 5];

    return out;
}
```

This is the C2 domain the malware will start communicating with.

### String decoding variant 2 - Wide string decoding
While moving through additional initialization functions there are wide strings that are resolved based on appended hex values.  A specific post on one technique that I currently use to resolve the strings is posted at:

[Wide string decoding](https://www.travismathison.com/posts/Wide-String-Decoding/)


### Renaming all functions
Once we have resolved all the strings through the two techniques above, we can rename all functions and global variables so they are better understood when we analyze the assembly and decompilation further.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/04.png"/><br/>
Figure 5: Renamed initialization functions</div><br />

**A note on static vs dynamic resolution**
My primary focus here is on how to understand it from a static analysis perspective.  If the goal is the get to the result as quickly as possible there are also dynamic approaches you can take.  

Generally speaking, since this all happens before a known point in the malware `WinMain` in this case, you can use a debugger to break at `WinMain` after the resolution has occurred and extract it from memory to patch back into IDA Pro (or patched directly into the binary and re-open in IDA Pro).

There are some techniques to resolve Import Address Tables (IATs) via debugging and I made some commentary on this quite some time ago in the following post:

[Resolving IAT with AGDCservices Scripts](https://www.travismathison.com/posts/Resolving-IAT-with-AGDCservices-scripts/)

### Back to WinMain
The first function called:
* Checks to see if it can connect successfully to the C2 domain
* Performs the connection and reads all data from C2
* Copies all of the data to a memory location it `VirtualAlloc`’ed during one of the initialization functions

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/05.png"/><br/>
Figure 6: Malware performing its initial C2 check-in</div><br />

It saves the responses from the C2 into a memory location that was setup during one of the initialization functions.  I renamed the global variable name at this point after I knew what was being saved.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/06.png"/><br/>
Figure 7: Saving C2 initial response that is used later in C2 communication</div><br />

In `WinMain` the malware builds an HTTP header block based on a decoded template and then enters the main C2 loop.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/07.png"/><br/>
Figure 8: Building HTTP header block used in subsequent C2 communication</div><br />

In `mw_BuildHttpHeaderBlock` a template is decoded and the rest of the function performs some setup and conversions to the payload memory address and creates a random token to use for the session cookie.  In all subsequent requests to the C2 this will be used.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/08.png"/><br/>
Figure 9: The header block that is decoded and used in C2 requests</div><br />

Finally, the malware moves into its C2 loop where it starts to process commands and is controlled by the threat actor.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/09.png"/><br/>
Figure 10: The beginning of the C2 loop to process commands</div><br />

In the C2 loop there are a number of commands that can be seen.  Primarily this comes down to being able to upload files and execute arbitrary commands on the victim machine.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260421_0/10.png"/><br/>
Figure 11: Fetching the next command to run from the C2</div><br />


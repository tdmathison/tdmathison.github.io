---
title: "Ghidra error: Unable to locate the DIA SDK"
date: 2020-09-27 11:08:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [ghidra]
---

## Ghidra error on auto-analysis
In my flarevm using Windows 10 I have Visual Studio 2019 Community edition installed for building C/C++ programs as needed.  When performing the initial auto-analysis on a binary you may run into the following error message relating to the DIA SDK and loading PDB files.  

This is simply relating to a DIA SDK DLL not being registered that is part  of the Visual Studio install (why it does not get registered during the install I don't know). The Ghidra docs state that there is a bundled pdb.exe that gets used on Windows and this is a pre-requisite that requires some manual intervention.

### The error dialog box
<img src="{{ site.url }}/assets/img/blogging/ghidra_dia_sdk_pdb_error.png"/>

### The fix
In the case of Visual Studio 2019 installed, the file to register is at the following location (the exact location of this file may different based on Visual Studio version installed):
```
C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\DIA SDK\bin\amd64\msdia140.
dll
```

To register it, run the following command from elevated command prompt:
```
regsvr32 “C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\DIA SDK\bin\amd64\msdia140.dll”
```

<img src="{{ site.url }}/assets/img/blogging/ghidra_msdia140_reg_success.png"/>

Restart Ghidra and the auto-analysis should function as expected.
---
title: Windows Enumeration Script
date: 2017-08-03 12:00:00 -0700
categories: [Blogging, Penetration-Testing]
tags: [windows, enumeration, penetration-testing, hacking, script]
---

As I've started learning what the most common misconfigurations are on a Windows machine I decided that I should start creating a script to automate the searching for them.  I have started an initial script to search for some common things that I do every time I try to escalate a Windows machine and will continue to update and improve on it.

## Description
This is a python script that will collect some important information about the Windows system regarding patching, permission issues, and potentially leaked credentials in files and/or the registry.  The intent is to continue adding to the script as I find more things to search for.

Right now it is a single file and the intial intent was to have just one file to copy around.  However, I believe to make it more modular and feature rich it will need to be split up and become more of a python module or library where the intent would be to alway compile it with PyInstaller before deploying to a Windows machine.

At any rate, this is the initial script that I'm running against a Windows system and will continue to tweak and add to.

## Goals
To create a single script that I can run against a Windows machine to collect targeted information. Among the information is:
* System information and currently installed patches
* Poorly permissioned Windows Services and Scheduled tasks (looks at both binpath file as well as directory permissions)
* Passwords/credentials leaked in files on disk
* unattended install files
* Passwords/credentials in the registry

## Usage
- The script can run on its own via python3+PyWin32 if it is installed on the Windows machine
- If not, you can use pyinstaller to turn it into an executable and move the executable to the windows machine
	- NOTE: pyinstaller supports python 3.3-3.5 (not the latest 3.6 at the time of this writing) so if you are going to use pyinstaller make sure you are targeting python 3.5 instead

## Pre-requisites
- Python3 (specifically 3.5 if you are going to use pyinstaller)
- PyInstaller
- PyWin32
- accesschk.exe / accesschk64.exe

## Create the self-contained Windows executable
```
c:\Users\sengen\Desktop>pyinstaller --onefile WinEnum.py
78 INFO: PyInstaller: 3.2.1
78 INFO: Python: 3.5.3
78 INFO: Platform: Windows-7-6.1.7601-SP1
78 INFO: wrote c:\Users\sengen\Desktop\WinEnum.spec
78 INFO: UPX is not available.
78 INFO: Extending PYTHONPATH with paths
['c:\\Users\\sengen\\Desktop', 'c:\\Users\\sengen\\Desktop']
78 INFO: checking Analysis
78 INFO: Building Analysis because out00-Analysis.toc is non existent
78 INFO: Initializing module dependency graph...
78 INFO: Initializing module graph hooks...
78 INFO: Analyzing base_library.zip ...
2140 INFO: running Analysis out00-Analysis.toc
2156 INFO: Adding Microsoft.Windows.Common-Controls to dependent assemblies of f
inal executable
  required by c:\program files\python35\python.exe
2453 INFO: Caching module hooks...
2468 INFO: Analyzing c:\Users\sengen\Desktop\WinEnum.py
2468 INFO: Loading module hooks...
2468 INFO: Loading module hook "hook-pydoc.py"...
2468 INFO: Loading module hook "hook-encodings.py"...
2546 INFO: Loading module hook "hook-xml.py"...
2718 INFO: Looking for ctypes DLLs
2718 INFO: Analyzing run-time hooks ...
2718 INFO: Looking for dynamic libraries
2812 INFO: Looking for eggs
2812 INFO: Using Python library c:\program files\python35\python35.dll
2812 INFO: Found binding redirects:
[]
2812 INFO: Warnings written to c:\Users\sengen\Desktop\build\WinEnum\warnWinEnum
.txt
2812 INFO: checking PYZ
2812 INFO: Building PYZ because out00-PYZ.toc is non existent
2812 INFO: Building PYZ (ZlibArchive) c:\Users\sengen\Desktop\build\WinEnum\out0
0-PYZ.pyz
3250 INFO: Building PYZ (ZlibArchive) c:\Users\sengen\Desktop\build\WinEnum\out0
0-PYZ.pyz completed successfully.
3265 INFO: checking PKG
3265 INFO: Building PKG because out00-PKG.toc is non existent
3265 INFO: Building PKG (CArchive) out00-PKG.pkg
4890 INFO: Building PKG (CArchive) out00-PKG.pkg completed successfully.
4890 INFO: Bootloader c:\program files\python35\lib\site-packages\PyInstaller\bo
otloader\Windows-64bit\run.exe
4890 INFO: checking EXE
4890 INFO: Building EXE because out00-EXE.toc is non existent
4890 INFO: Building EXE from out00-EXE.toc
4890 INFO: Appending archive to EXE c:\Users\sengen\Desktop\dist\WinEnum.exe
4890 INFO: Building EXE from out00-EXE.toc completed successfully.
```

## The repository with the script
All the future Windows enumeration and data collection script will be in the following repository (including this first one, WinEnum.py)<br /><br />
[https://github.com/tdmathison/WindowsEnumeration](https://github.com/tdmathison/WindowsEnumeration)

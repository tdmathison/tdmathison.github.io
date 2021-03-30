---
title: "Searching IAT for DLLs"
author: Travis Mathison
date: 2021-03-29 10:34:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, iat]
---

## Intro
With a given binary it is very simple to view the Import Address Table (IAT) and see what DLLs it imports and further, what functions are used within those DLLs.  In my case, I needed to do the opposite: I had a DLL that was known to be bad but needed to find if any binaries were importing that DLL.  I have no logs or additional information to work from and just the a known drive of files.

This scenaraio resulted in writing up a little python script that performs the following:
* Allows you to specify
  * The root path to recursively search for files in
  * The extension of the files to search for (my targets being `EXE` and `DLL`)
  * The name of the import DLL to search for within the Import Table
* The script searches for relevant files and attempt to open it as a `PE` file
* It loops through the Import Address Table attempting to make a match on the DLL file name you are searching for
* If found it will print the full path to the binary so you can grab it for further analysis

## Running the script
The script is targeting Win32 PE files but can be adapted for any file type you are after.  The format for the script is:
```
$ python3 ./iat_search.py 
usage: iat_search.py [-h] -p PATH -e EXTENSION -dll DLL
iat_search.py: error: the following arguments are required: -p/--path, -e/--extension, -dll
```

Example running of script on my Linux machine while looking for a DLL that is known to be present:
```
$ python3 ./iat_search.py -p=/usr -e=exe -dll=user32.dll
Indexing files: 325098

17 eligible files | 3 detections
----------------------------------
"/usr/lib/vmware/tools-upgraders/VMwareToolsUpgraderNT.exe":b'USER32.dll'
"/usr/lib/vmware/tools-upgraders/VMwareToolsUpgrader9x.exe":b'USER32.dll'
"/usr/lib/vmware/tools-upgraders/VMwareToolsUpgrader.exe":b'USER32.dll'
```

## Source
The script can be grabbed from the following location and used/modified as needed: <br/>
[https://github.com/tdmathison/PythonScripts/blob/main/iat_search.py](https://github.com/tdmathison/PythonScripts/blob/main/iat_search.py)

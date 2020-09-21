---
title: "Getting Started with Ghidra and FlareVM"
author: Travis Mathison
date: 2020-09-21 15:35:00 +0800
categories: [Blogging]
tags: [flarevm, ghidra]
---

## Goal
This is a quick guide to get you started on installing FlareVM by FireEye and setting up Ghidra for reverse engineering malware. The FlareVM installation is a script you can run that will turn a Windows 10 installation into a reverse engineering environment that has all the tools needed for binary analysis, RE, and a safe place to detonate malicious software.

The flagship RE tool in the industry is HexRays IDA Pro and while a IDA Free version is available it has quite a few limitations.  Ghidra has been released as OpenSource by the NSA and parallels many features of IDA Pro and can augment IDA Free in a good way.

## FireEye FlareVM
To begin, you should have either Oracle VirtualBox [https://www.virtualbox.org](https://www.virtualbox.org) or VMware Workstation/Fusion [https://www.vmware.com/products/workstation-pro.html](https://www.vmware.com/products/workstation-pro.html) installed on the host machine you are going to perform analysis from.

### Post-Windows 10 install steps
The FlareVM script attempts to take some steps to prepare the Windows 10 installation to turn off AV services that will interfere with what the VM is being built out for. However, I have experienced many issues with this failing to work properly and have found taking the following steps manually to make everything work properly.

#### Disable Windows Defender (Windows 7 & 10)
* Start gpedit.msc
  * Computer Configuration > Administrative Templates > Windows Components > Windows Defender
  * Enable “Turn off Windows Defender"
  * Click “Apply”, “OK"
  * Restart Windows

#### Disable update Auto-restarts
* Start gpedit.msc
  * Computer Configuration > Administrative Templates > Windows Components > Windows Update
  * Enable “No auto-restart with logged…"
  * Click “Apply”, “OK"

Take a snapshot of your Windows 10 machine in case the FlareVM install goes bad.

### Installing FlareVM onto the Windows machine
1. Clone the GitHub FlareVM repository to your Windows 10 VM machine. The repository is located at [https://github.com/fireeye/flare-vm](https://github.com/fireeye/flare-vm).
2. To kick off the installation process read the steps detailed in [https://github.com/fireeye/flare-vm/blob/master/README.md](https://github.com/fireeye/flare-vm/blob/master/README.md) which contain only a few actions: 
   1. Open PowerShell as Admin and run "Set-ExecutionPolicy Unrestricted"
   2. Run ./install.ps1.

> NOTE: This process uses the package manager tool Chocolatey [https://chocolatey.org](https://chocolatey.org) and custom FireEye built packages to completely transform the machine into a VM that you can perform all your RE tasks from. This install process can take many hours to complete so plan to allocate some time for this to finish.

When the install of FlareVM completes make sure you take another snapshot.

## NSA's Ghidra
The official site for the Ghidra RE tool is at [https://ghidra-sre.org](https://ghidra-sre.org) and can be downloaded and ran on its own, from any platform. I typically use this within the Windows FlareVM but also have this installed on my Kali Linux VM for reversing GNU/Linux based malware.

At this point you will have Ghidra installed already on your machine and there should be a link to Ghidra on your desktop. If not, hit the Windows key and do a search for Ghidra and it should pop up in the results.

There are some post-FlareVM actions I take in regard to Ghidra that are optional, but recommended to get the most out of Ghidra. I have broken this into three parts:
1. Gaining some FLIRT signatures capability that IDA Pro has
2. Getting a debugger to work with ghidra
3. Additional Ghidra scripts that help in the RE Process

### Gaining some FLIRT signatures capability that IDA Pro has
To understand what F.L.I.R.T. signatures are and why they are important please read the HexRays IDA Pro article on this topic:
* IDA F.L.I.R.T. Technology: In-Depth
[https://www.hex-rays.com/products/ida/tech/flirt/in_depth/](https://www.hex-rays.com/products/ida/tech/flirt/in_depth/)

To gain some of this capability we can install a script that allows for importing and applying the signatures:
* Ghidra Plugin Script to apply signature files
  * [https://github.com/NWMonster/ApplySig](https://github.com/NWMonster/ApplySig)
* Two FLIRT Signature databases that you should clone to your FlareVM for use by this are:
  * [https://github.com/push0ebp/sig-database](https://github.com/push0ebp/sig-database)
  * [https://github.com/Maktm/FLIRTDB](https://github.com/Maktm/FLIRTDB)

### Getting a debugger to work with Ghidra
A missing capability in Ghidra that IDA Pro has is an integrated debugger. This is a feature that is planned to make its way into Ghidra but until it does we can use the following plugin to gain the ability to sync to an external debugger. The debugger that I integrate with is x64dbg and the instructions with additional steps to complete the integration are on the ret-sync GitHub page.
* [https://github.com/bootleg/ret-sync](https://github.com/bootleg/ret-sync)

### Additional Ghidra scripts that help in the RE Process
The following is a list of additional scripts I use that aid in enhancing the use of Ghidra:
* [https://github.com/reb311ion/replica](https://github.com/reb311ion/replica)
  * Script to rename functions and types based on findings of its scan
* [https://github.com/d3v1l401/FindCrypt-Ghidra](https://github.com/d3v1l401/FindCrypt-Ghidra)
  * Find cryptography functions
* [https://github.com/ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts)
  * Useful Ghidra scripts (namely for Yara and binwalk)
* [https://github.com/0xb0bb/pwndra](https://github.com/0xb0bb/pwndra)
  * A collection of pwn/CTF related utilities
* [https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer](https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer)
  * The script used to import the output of OOAnalyzer for C++ code
  * Article: [https://insights.sei.cmu.edu/sei_blog/2019/07/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra.html](https://insights.sei.cmu.edu/sei_blog/2019/07/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra.html)

Some Ghidra Settings changes that can be adjusted from the CodeBrowser tool once a project is created:
* Edit->Tool Options
  * Listing Display
    * Font -> Bold
  * ByteViewer
    * Highlight Cursor Line Color -> Yellow (or some other more visible color)
  * Listing Fields->Bytes Field
    * Maximum Lines To Display = 1
  * Listing Fields->Cursor Text Highlight
    * Mouse Button To Activate = LEFT
  * Listing Fields->EOL Comments Field
    * Show Semicolon at Start of Each Line = Checked
  * Listing Fields->Operands Field
    * Add Space After Separator = Checked

Lastly, to make going between Ghidra and IDA Pro a little easier, I have updated the keymappings of Ghidra to be more similar to IDA Pro (many of these mapping just make more sense anyways (like using ESC to move backward and using the key 'x' to search for "references to")).
* [https://github.com/JeremyBlackthorne/Ghidra-Keybindings](https://github.com/JeremyBlackthorne/Ghidra-Keybindings)

This completes the basic setup of the FlareVM that can now be used for RE and malware detonation purposes.
---
title: "Reverse Engineering on Windows 11 ARM (Macbook Pro M1/M2)"
date: 2023-02-02 21:38:00 -0700
categories: [Blogging]
tags: [ida, tips-and-tricks, arm, macbook-pro]
---

## Summary
I have recently purchased the new Macbook Pro M2 Max 16" as I finally wanted to switch over into the ARM world on the desktop.  One of my main concerns was around my focus on reverse engineering malware and how that will play out on an ARM-based device.

The primary questions to be answered were:
* Will VMware Fusion 13 (the latest at the time of this writing) install Windows 11 ARM properly or will I need to re-visit Parallels?
* Can I install IDA Pro within Windows 11 ARM properly without issue?
* How will x86 / x86_64 malware disassemble and more importantly, how does it run in x64dbg on the ARM version of Windows (will Rosetta 2 x86 emulation end up showing me ARM or x86 instructions when dynamically running)

## BLUF
* VMware Fusion 13 in its current state is a terrible option for the M1/M2 ARM-based machines and too many things do not work or have not been implemented -- VMware is massively struggling on this front right now
* Parallels has hit the ball out of the park and everything worked 100% perfectly with Windows 11 ARM
  * They provide ease of install and all functionality is present (even coherence works perfectly)
* IDA Pro installs and disassembles binaries the same it would on an Intel-based system
* When debugging x86 binaries on ARM you see the x86 instructions and not ARM (this is very important so I can map addresses and assembly between IDA Pro disassembly and the debugger)
* The current experience after reversing both x86 and ARM malware is that I am able to do both and it's proving to be the best of both worlds

## The Windows 11 ARM Windows Defender disabling issue
I previously posted on how to reliably disable Windows Defender for Windows 10 (non-ARM) and that no longer works for Windows 11 ARM.  Microsoft continues to make it as difficult as possible for a user to have any sense of control of their operating system.

That said, I have found the below steps to work in stopping Windows Defender from interfering with malware analysis.  Of course, with any Microsoft update they will likely revert these settings to ruin your analysis machine again so you'll have to repeat them to re-baseline and get a new snapshot.

## Post Windows 11 ARM configuration (Disable Windows Defender)
* Get autoruns via `choco install AutoRuns`
* Run `msconfig` as admin
  * Boot -> Enable Safe Boot
  * Restart Windows
* Run `AutoRuns`
  * Services -> WinDefend (Uncheck)
* Run `gpedit.msc`
  * Click Computer Configuration -> Administrative Templates -> Windows Components -> Microsoft Defender Antivirus
  * Set `Turn off Microsoft Defender Antivirus` to enabled
* Run `msfconfig`
  * Services -> Disable Windows Defender Advanced Threat Protection Service
  * Services -> Disable Windows Defender Firewall
  * Services -> Microsoft Defender Antivirus Network Inspection Service
  * Restart Windows

NOTE: The Windows Defender services still seem to be running after the reboot, however the services seem to not be working when viewing through Security Center.  

Extra setting for yet another annoying thing Microsoft has done
* Add back the full right-click menu so you don't have to click "Show more options"
  * `reg add HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 /ve /d "" /f`

## FlareVM Install
Once the above steps have been performed you'll be able to carry on with installing the FlareVM packages to turn this into your new machine to perform reverse engineering on.

https://github.com/mandiant/flare-vm
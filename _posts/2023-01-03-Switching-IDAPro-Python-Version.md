---
title: "Switching IDA Pro Python Version"
date: 2023-01-03 16:59:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [ida, tips-and-tricks]
---

## Summary
In FlareVM you will likely have many versions of Python installed.  Not all of these are going to be compatible with IDA Pro and you may need to switch which version IDA Pro is looking at.

If you see errors around modules not found, even after you have pip install them, or errors around `_ctypes` as seen below, you can use a tool provided by Hex-Rays to re-target to a new version.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/idapyswitch_ida_python_errors.png"/>

## idapyswitch.exe
In the default directory of IDA Pro you can find a tool called `idapyswitch.exe` that will scan the system for all installed versions of python and allow you to select that one you want to use.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/idapyswitch_exe.png"/>

Upon switching to a new version, in my case I switched back to version 3.8 (from 3.10), and upon restarting IDA Pro the errors are cleared. The root issue around this is with a `sip.pyd` file required for PyQt bindings to function properly.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/idapyswitch_ida_python_no_errors.png"/>

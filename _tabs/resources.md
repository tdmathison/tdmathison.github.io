---
title: Resources
icon: fas fa-book
order: 3
---
**Table of Contents**
- TOC
{:toc}

---

## Favorite blogs
The following sites often contain decent malware write-ups and information.

| Name | Link |
|:---|:----|
| Unit42 Blog | [https://unit42.paloaltonetworks.com/category/threat-research](https://unit42.paloaltonetworks.com/category/threat-research) |
| Sekoia Blog | [https://blog.sekoia.io/category/threat-research](https://blog.sekoia.io/category/threat-research) |
| Mandiant Blog | [https://cloud.google.com/blog/topics/threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence) |
| CrowdStrike Cyber Security Blog | [https://www.crowdstrike.com/en-us/blog](https://www.crowdstrike.com/en-us/blog) |
| ProofPoint Blog | [https://www.proofpoint.com/us/blog](https://www.proofpoint.com/us/blog) |
| Resecurity Blog | [https://www.resecurity.com/blog](https://www.resecurity.com/blog) |
| CheckPoint Blog | [https://research.checkpoint.com](https://research.checkpoint.com) |
| Securonix Blog | [https://www.securonix.com/blog?_categories=threat-research](https://www.securonix.com/blog?_categories=threat-research) |
| LevelBlue Blog | [https://levelblue.com/blogs/labs-research](https://levelblue.com/blogs/labs-research) |
| SentinelOne Blog | [https://www.sentinelone.com/blog](https://www.sentinelone.com/blog) |

## Malware Detonation sandboxes
The following are a few malware detonation sandboxes I have used and have been valuable:

| Name | Link |
|:---|:----|
| Cuckoo Box | [https://cuckoosandbox.org/](https://cuckoosandbox.org/) |
| Hybrid Analysis | [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/) |
| Intezer Analyze | [https://analyze.intezer.com/](https://analyze.intezer.com/) |
| Joe Sandbox | [https://www.joesandbox.com/](https://www.joesandbox.com/) |
| ANY.RUN | [https://any.run/](https://any.run/) |


## Malware Samples
The following are some locations where you can grab samples of malware for analysis.

### General Live Malware

| Name | Link |
|:---|:----|
| The Zoo | [https://github.com/ytisf/theZoo](https://github.com/ytisf/theZoo) |
| InQuest | [https://github.com/InQuest/malware-samples](https://github.com/InQuest/malware-samples) |
| VirusTotal | [https://www.virustotal.com/gui/](https://www.virustotal.com/gui/) |
| CyberLab | [https://cyberlab.pacific.edu/resources/malware-samples-for-students](https://cyberlab.pacific.edu/resources/malware-samples-for-students) |
| MacOS Malware | [https://objective-see.com/malware.html](https://objective-see.com/malware.html) |
| MacOS Malware Encyclopedia | [https://macos.checkpoint.com/](https://macos.checkpoint.com/) |
| Das Malwerk | [https://dasmalwerk.eu/](https://dasmalwerk.eu/) |
| MalShare | [https://malshare.com/](https://malshare.com/) |
| Malpedia | [https://malpedia.caad.fkie.fraunhofer.de/](https://malpedia.caad.fkie.fraunhofer.de/) |
| TotalHash | [https://totalhash.cymru.com](https://totalhash.cymru.com) |
| MalwareBazaar | [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/) |

### Network Packet Samples

| Name | Link |
|:---|:----|
| PacketTotal | [https://packettotal.com/](https://packettotal.com/) |
| Malware-Traffic-Analysis | [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/) |

### Lists of malicious URLs hosting malware

| Name | Link |
|:---|:----|
| URLHause | [https://urlhaus.abuse.ch/browse/](https://urlhaus.abuse.ch/browse/) |
| Zeltser | [https://zeltser.com/malicious-ip-blocklists/#](https://zeltser.com/malicious-ip-blocklists/#) |

## Automated malware unpacking

| Name | Link |
|:---|:----|
| OpenAnalysis UNPACME | [https://www.unpac.me/#/](https://www.unpac.me/#/) |

## Malware Techniques examples
A few GitHub repos that I found of which have examples of anti-analysis techniques (Anti-Debug, Anti-VM, Anti-Analysis, etc). These can be useful to compile and see what it looks like in the disassembler when you run into them.  This also can help in seeing what types of techniques may be found in malware attempting to make reverse engineering more difficult for the analyst.

| Name | Link |
|:---|:----|
| alichtman: malware-techniques | [https://github.com/alichtman/malware-techniques](https://github.com/alichtman/malware-techniques) |
| LordNoteworthy: al-khaser | [https://github.com/LordNoteworthy/al-khaser](https://github.com/LordNoteworthy/al-khaser) |
| Ultimate Anti-Reversing Reference | [The_Ultimate_Anti-Reversing_Reference.pdf](https://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf) |

## Malware Analysis VMs
These are images, VM's, or scripts to build out a VM that is suitable to reverse engineer or otherwise deal with analyzing malware.  Granted, you can build your own (I did for a long time) but being able to automate the creation of an environment in minimal time has proven to be more valuable.

| Name | Link |
|:---|:----|
| FlareVM | [https://github.com/fireeye/flare-vm](https://github.com/fireeye/flare-vm) |
| REMnux | [https://remnux.org/](https://remnux.org/) |

## Reverse Engineering Disassemblers
While there are tons of disassemblers and decompilers out there, the following list seems to the standard ones that come up in conversation over and over that you should be aware of.

| Name | Link |
|:---|:----|
| Hex Rays IDA Pro | [https://www.hex-rays.com/products/ida/](https://www.hex-rays.com/products/ida/) |
| Ghidra | [https://ghidra-sre.org/](https://ghidra-sre.org/) |
| Hopper | [https://www.hopperapp.com/](https://www.hopperapp.com/) |
| Binary Ninja | [https://binary.ninja/](https://binary.ninja/) |
| Radare2 | [https://rada.re/n/](https://rada.re/n/) |
| Cutter | [https://cutter.re/](https://cutter.re/) |

## Emulators
There are several tools and frameworks that can help emulate the CPU and crawl a binary in an attempt to capture what the instructions are trying to do, what API calls it is making, etc.  They can be hit and miss and often give you a partial view of what is happening.  The information you can get, however, may be critical and substantial.

| Name | Link |
|:---|:----|
| SpeakEasy | [https://github.com/fireeye/speakeasy](https://github.com/fireeye/speakeasy) |
| Qiling Framework | [https://qiling.io/](https://qiling.io/)<br/>[https://docs.qiling.io/en/latest/install/](https://docs.qiling.io/en/latest/install/) |
| x86Emulator | [https://github.com/AmrThabet/x86Emulator](https://github.com/AmrThabet/x86Emulator) |

## Other Tools
Additional tools that add or augment analysis.

| Name | Link |
|:---|:----|
| BinDiff (for use by IDA Pro) | [https://zynamics.com/software.html](https://zynamics.com/software.html) |
| BinDiff Quick Walkthrough | [https://www.youtube.com/watch?v=BLBjcZe-C3I](https://www.youtube.com/watch?v=BLBjcZe-C3I) |

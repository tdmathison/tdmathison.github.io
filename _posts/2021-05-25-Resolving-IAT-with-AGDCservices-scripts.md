---
title: "Resolving IAT with AGDCservices Scripts"
date: 2021-05-25 11:15:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, hermes, ransomware, debugging, ida, ghidra, memory, techniques]
---

**Table of Contents**
- TOC
{:toc}

## Intro
Ransomware is a big topic that keeps getting more and more attention.  I have been doing research in this area, finding samples to reverse engineer, and of course, watching plenty of people do their own reversing work to learn from.  In one series of videos on reverse engineering a Hermes ransomware sample there were a set of Ghidra scripts used to perform a number of tasks during analysis.

There were two scripts in particular that I decided to convert to IDA Pro 7.6 (my only contribution to the below work that was created by AGDC services).

## Attribution
AGDC Services video series on reversing Hermes ransomware
* [Hermes Malware Deep Dive Pt 1 - Unpacking](https://www.youtube.com/watch?v=kkQAJFyoCVU)
* [Hermes Malware Deep Dive Pt 2](https://www.youtube.com/watch?v=wsdPmW0dt0I)

Ghidra scripts used in the video series
* [Ghidra-Scripts](https://github.com/AGDCservices/Ghidra-Scripts)
* [Misc-Malware-Analysis-Tools](https://github.com/AGDCservices/Misc-Malware-Analysis-Tools)

## My IDA Pro 7.6 plugin scripts (rough conversion of theirs)
[https://github.com/tdmathison/HelperScripts/tree/master/AGDCservices](https://github.com/tdmathison/HelperScripts/tree/master/AGDCservices)

NOTE: This covers the highlighting and the script to resolve IAT entries within IDA Pro (7.4+ compatible)

## Details
When dropping all three of the IDA Pro plugin files to the `<IDA PRO Install Dir>\plugins\` directory you will see them show up in the `Edit->Plugins` menu as seen below:
<img style="align:left" src="{{ site.url }}/assets/img/blogging/agdc_plugin_menu_list.png"/>

### Color coding instructions
To make it easier to visually focus in on certain types of calls in assembly I was using a plugin called [fluorescence](https://github.com/tacnetsol/ida/tree/master/plugins/fluorescence) that allows you to toggle on/off highlighting of `call` instructions.  This has been very helpful, however, I think I am now going to make use of the AGDCservices version that enhances this a bit more by identifying calls, pointers, likely crypto operations, and string operations.

My converted plugins for this are here:
* [AGDCservices_highlight_target_instructions_plugin.py](https://github.com/tdmathison/HelperScripts/blob/master/AGDCservices/AGDCservices_highlight_target_instructions_plugin.py)
* [AGDCservices_clear_all_instruction_colors_plugin.py](https://github.com/tdmathison/HelperScripts/blob/master/AGDCservices/AGDCservices_clear_all_instruction_colors_plugin.py)

When the plugin is invoked you will see the assembly in IDA Pro light up as seen below (and you can remove the highlighting by calling the other plugin):
<img style="align:left" src="{{ site.url }}/assets/img/blogging/agdc_color_coding.png"/>

### IAT Resolution
Since malware often resolves imports dynamically at runtime you will not see a properly populated import table during initial static analysis.  The idea here is to locate where the malware resolves the imports and builds an import table.  When you have located this, you can debug into the malware and right after the resolution has occurred you can take a snapshots of the RVA's of the imports.  This is the relative offsets from the image base to which they are located.

To perform this action AGDCservices uses the following executable:<br/>
[Dump_Labeled_Iat_Memory.exe](https://github.com/AGDCservices/Misc-Malware-Analysis-Tools/blob/main/Dump_Labeled_Iat_Memory.exe)

#### The IDA Pro plugin to use this output
Once you have this file with the imports and associated RVA's you can use the following plugin to apply it to the IDA database:<br/>
[AGDCservices_label_iat_entries_plugin.py](https://github.com/tdmathison/HelperScripts/blob/master/AGDCservices/AGDCservices_label_iat_entries_plugin.py)

**Before:**
<img style="align:left" src="{{ site.url }}/assets/img/blogging/agdc_pre_iat_resolve.png"/>

**After:**
<img style="align:left" src="{{ site.url }}/assets/img/blogging/agdc_post_iat_resolve.png"/>

## Conclusion
There are many ways to achieve these types of results and everybody ends up developing their own tools and workflows.  This is just another one that seems to work well for this task that I will be taking parts of it away with me to integrate into my own workflow.  Be sure to watch the videos of the source of this that I pointed out in the attribution section to get the full walkthrough.
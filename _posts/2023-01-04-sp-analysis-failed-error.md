---
title: "Resolving IDA Pro “sp-analysis failed” Error"
date: 2023-01-04 04:45:00 -0700
categories: [Blogging]
tags: [ida, tips-and-tricks]
---

## Summary
IDA Pro does not always get the disassembly, and pseudo-C decompilation correct.  When it has an issue, it can manifest in several ways but one thing you may see is a red error message in the disassembly saying `sp-analysis failed`.

## sp-analysis failed
The below screenshot shows an example of what this looks like in disassembly.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_1.png"/>

We can see that at `00537E0F` is declares this to be the end of the function, it also is aware something isn’t right.  In this case, we can see that the assembly continues right afterward, and it is not over.  If you decompile this with the Hex-Rays decompiler you get the following:

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_2.png"/>

To get our pseudo-C code to properly generate we need to fix the assembly to undefine and redefine the entire section of assembly that we believe is the true function.

### Step 1: Undefine assembly
Highlight the full assembly for the function and undefine it via `right-click->Undefine` (or simply press `“U”` on the keyboard).

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_3.png"/>

### Step 2: Redefine bytes as Code
Select all the undefined bytes and force it to be defined via highlighting it all and `right-click->Code` (or press `“C”` on the keyboard).

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_4.png"/>

IDA Pro will ask if you want it to perform another analysis on this assembly and you should say no, you just want to force it to turn to code (it already got it wrong the first time).

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_5.png"/>

### Step 3: Force it to be a function
Select the new location tag and tell it that it is a function via `right-click->Create function` (or press `“P”` on the keyboard).

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_6.png"/>

Resulting assembly will now show a properly defined function with all the assembly.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_7.png"/>

### Step 4: Generate new Pseudo-C
Confirm that we can now decompile the assembly into readable pseudo-C.  Press `F5` to view that everything is decompiling as expected now.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/sp_analysis_8.png"/>

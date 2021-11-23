---
title: "Hex-Rays IDA Tips and Tricks"
author: Travis Mathison
date: 2021-11-23 12:07:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [ida, tips-and-tricks]
---

## Hex-Rays tips and tricks to IDA Pro
Igor Skochinsky of Hex-Rays presents a new IDA Pro tip every week.  This is more of a pointer toward a "season 1" compilation of these tips and to the Hex-Rays blog where they continue to be posted.

The first 52 tips have been compiled into a single PDF document (by Hex-Rays):<br/>
[https://hex-rays.com/blog/igors-tip-of-the-week-season-01/](https://hex-rays.com/blog/igors-tip-of-the-week-season-01/)

The continued series is can be found at:<br/>
[https://hex-rays.com/blog/](https://hex-rays.com/blog/)

## Some favorites
*NOTE: The below text and examples are extracts from Igor's tips and not my commentary, but shown to give you a taste of what you can expect*

### #35 Demangled names
**Name simplification**<br/>
Some deceptively simple-looking names may end up very complicated after compilation, especially when templates are involved. For example, a simple `std::string1` from STL actually expands to<br/>
```c
std::basic_string<char,std::char_traits<char>,std::allocator<char>>
```

To ensure interoperability, the compiler has to preserve these details in the mangled name, so they reappear on demangling; however, such implementation details are usually not interesting to a human reader who would prefer to see a simple std::string again. This is why IDA implements name simplification as a post-processing step. Using the rules in the file cfg/goodname.cfg, IDA applies them to transform a name like<br/>
```c
std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > 
    & __thiscall std::ba- sic_string<char,struct std::char_traits<char>,
    class std::allocator<char> >::erase(unsigned int,unsigned int)
```

into

```c
std::string & std::string::erase(unsigned int,unsigned int)
```

which is much easier to read and understand.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/igor-tips-35.png"/>


### #18 Decompiler and global cross-references
**Global cross-references**<br/>
If you have a well-analyzed database with custom types used by the program and properly set up function prototypes, you can ask the decompiler to analyze all functions and build a list of cross-references to a structure field, an enum member or a whole local type. The default hotkey is `Ctrl-Alt-X`.

When you use it for the first time, the list may be empty or include only recently decompiled functions.

To cover all functions, refresh the list from the context menu or by pressing Ctrl-U. This will decompile all functions in the database and gather the complete list. The decompilation results are cached so next time you use the feature it will be faster.

<img style="align:left" src="{{ site.url }}/assets/img/blogging/igor-tips-18.png"/>

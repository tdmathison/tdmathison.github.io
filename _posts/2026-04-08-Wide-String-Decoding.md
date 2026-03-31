---
title: "Wide string decoding"
date: 2026-04-08 12:13:00 -0700
categories: [Blogging]
tags: [MuddyWater, strings, decoding, widechar, ida, scripts]
---

## Summary
While reverse engineering the MuddyWater malware loader in the previous post ([here](https://www.travismathison.com/posts/MuddyWater-Malware-Loader-drops-LightPhoenix/)) there were several cases of string decodings that was worth noting as its own post.  This covers a good initial approach to resolving widechar strings in IDA Pro when its represented as a series of hex values.

## FLOSS
Currently, FLOSS is usually the best options to resolve strings (as a default first option if you want to add in some automation).
There is an IDA Pro script that you can call that will run FLOSS against the binary and then attempt to apply comments to the function calls where the string was decoded. 

**FLOSS Usage:**<br/>
* The FLOSS tool can be acquired from here: [https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss)
* Once the files are copied to your machine where IDA Pro can get to them you can execute the script file (`idaplugin.py`) via `File->Script file...`

**Results**<br/>
This works in many cases such as below (example of one of the successfully decoded strings output in the IDA Pro output console).

`[INFO] decoded string for function call at 0x140007c56: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) WinHttpClient/1.0	(idaplugin:apply_decoded_strings)`

Double clicking on the function call location `0x140007c56` (in this case) will take you to that location in IDA where it has added it as a comment at the point of the call to `sub-140007FB0`.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260408_0/00.png"/><br/>
Figure 1: String applied as comment to function call</div><br />

Within the called function you can see the hex that makes up the resulting wide string.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260408_0/01.png"/><br/>
Figure 2: Hex values representing the widestring</div><br />

There are some cases where it fails to apply the comment or there isn’t a direct call to the function and it doesn’t apply a comment.  An example of this is in the initialization functions that don’t have explicit calls to them (a starting address of a series of function addresses is used to iterate and execute them dynamically).

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260408_0/02.png"/><br/>
Figure 3: Functions not directly called not getting the comments applied</div><br />

In this case we can manually decode this.  I wrote a script to be able to manually copy/paste the decompilation into the console and perform the string resolution.  This should probably be converted into a small plugin.

Copy the hex concatenation part of the decompilation.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260408_0/03.png"/><br/>
Figure 4: Copying hex from decompilation</div><br />

Run the python script, paste what was copied, hit `Enter` and then `CTRL-Z`.  The resulting plaintext string will then be printed.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260408_0/04.png"/><br/>
Figure 5: Running script to decode string</div><br />

The script to perform this action is below.
```python
#!/usr/bin/env python3
"""
Decode IDA-style DWORD-assigned wide strings (plain UTF-16LE only).

Supports:
    *result = 0x72002F;
    result[1] = 0x670065;

    v15[0] = 0x20003B;
    v15[1] = 0x680074;
"""

import argparse
import re
import sys
from typing import Dict, List

ASSIGN_RE = re.compile(
    r"""
    (?:
        \*\s*(?P<star_var>[A-Za-z_]\w*)
        |
        (?P<idx_var>[A-Za-z_]\w*)\s*\[\s*(?P<idx>0x[0-9A-Fa-f]+|\d+)\s*\]
    )
    \s*=\s*
    (?P<val>0x[0-9A-Fa-f]+|\d+)
    \s*;
    """,
    re.VERBOSE,
)


def parse_int(text: str) -> int:
    return int(text, 0)


def extract_assignments(text: str) -> List[int]:
    values_by_index: Dict[int, int] = {}

    for match in ASSIGN_RE.finditer(text):
        if match.group("star_var") is not None:
            idx = 0
        else:
            idx = parse_int(match.group("idx"))

        val = parse_int(match.group("val"))
        values_by_index[idx] = val

    if not values_by_index:
        raise ValueError("No matching assignments found.")

    max_idx = max(values_by_index)
    missing = [i for i in range(max_idx + 1) if i not in values_by_index]
    if missing:
        raise ValueError(f"Missing indices: {missing}")

    return [values_by_index[i] for i in range(max_idx + 1)]


def dwords_to_utf16_string(values: List[int]) -> str:
    out_bytes = bytearray()

    for v in values:
        out_bytes += v.to_bytes(4, "little")

    # Decode UTF-16LE and stop at first NULL
    decoded = out_bytes.decode("utf-16le", errors="ignore")
    return decoded.split("\x00", 1)[0]


def read_input(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(
        description="Decode IDA DWORD-based wide strings (plain UTF-16LE)."
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Optional input file. Otherwise reads from stdin."
    )
    args = parser.parse_args()

    try:
        text = read_input(args.file)
        values = extract_assignments(text)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1

    print(f"[+] Parsed {len(values)} DWORD(s)")
    print()

    decoded = dwords_to_utf16_string(values)

    print("[decoded]")
    print(repr(decoded))

    return 0


if __name__ == "__main__":
    sys.exit(main())
```
---
title: "Dump PE headers"
categories: [pe]
tags: [headers]
---

{% raw %}
```python
import sys
import pefile

def dump_pe_headers(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        print(f"[!] {file_path} is not a valid PE file.")
        return

    print(f"== PE Header Info: {file_path} ==")
    print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
    print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")

    print("\n== Sections ==")
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').rstrip('\x00')
        vsize = section.Misc_VirtualSize
        rsize = section.SizeOfRawData
        vaddr = section.VirtualAddress
        print(f"[{name}] VA: 0x{vaddr:X}, VS: {vsize}, RS: {rsize}, Entropy: {section.get_entropy():.2f}")

    print("\n== Imports ==")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"{entry.dll.decode()}:")
            for imp in entry.imports:
                print(f"  {hex(imp.address)} {imp.name}")
    else:
        print("No import table found.")

    print("\n== Exports ==")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"  Ordinal: {exp.ordinal} | Address: {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)} | Name: {exp.name}")
    else:
        print("No export table found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dump_pe_headers.py <pe_file>")
        sys.exit(1)
    dump_pe_headers(sys.argv[1])
```
{% endraw %}
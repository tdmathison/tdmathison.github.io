---
title: "Reverse Engineering With C++ STL Types"
date: 2025-04-21 12:10:00 -0700
categories: [Blogging]
tags: [stl, c++, struct]
---

## Summary
When reversing C++ binaries, recognizing STL types like `std::string`, `std::vector`, and `std::shared_ptr` can make your analysis significantly more readable. However, IDA Pro does not natively understand STL layouts due to their complexity and compiler-specific ABI implementations.

This section walks through how to import STL structure definitions into IDA and use them to label memory regions, class members, or function arguments.

## A Ready-to-Import STL Struct Header
I created a multi-compiler STL header file that includes simplified type definitions for:
* MSVC (Visual Studio)
* libstdc++ (used by GCC)
* libc++ (used by Clang/LLVM)

```c
#ifndef STL_STRUCTS_H
#define STL_STRUCTS_H

// Choose your compiler ABI
// #define COMPILER_MSVC
// #define COMPILER_LIBSTDCXX
// #define COMPILER_LIBCXX

// =====================
// MSVC STL Layouts
// =====================
#ifdef COMPILER_MSVC

struct std_string {
    void* _ptr;
    int _length;
    int _capacity;
    char _buffer[1];
};

struct std_vector_int {
    int* _start;
    int* _end;
    int* _capacity_end;
};

struct std_shared_ptr_int {
    int* _ptr;
    void* _ref_count;
};

struct std_unique_ptr_int {
    int* _ptr;
};

struct std_optional_int {
    char _has_value;
    int _value;
};

// Simplified red-black tree node (std::map/set internal)
struct std_rb_node {
    struct std_rb_node* _parent;
    struct std_rb_node* _left;
    struct std_rb_node* _right;
    bool _is_red;
    char _padding[7]; // alignment
};

struct std_map_int_int {
    struct std_rb_node* _root;
    size_t _size;
};

#endif // COMPILER_MSVC

// =====================
// libstdc++ Layouts (GCC / Itanium ABI)
// =====================
#ifdef COMPILER_LIBSTDCXX

struct std_string {
    char* _data;
    size_t _length;
    size_t _capacity;
};

struct std_vector_int {
    int* _start;
    int* _finish;
    int* _end_of_storage;
};

struct std_shared_ptr_int {
    int* _ptr;
    void* _ctrl;  // control block with ref count
};

struct std_unique_ptr_int {
    int* _ptr;
};

struct std_optional_int {
    char _has_value;
    char _storage[sizeof(int)];
};

// Simplified tree layout for std::map/set
struct std_map_node_base {
    struct std_map_node_base* _parent;
    struct std_map_node_base* _left;
    struct std_map_node_base* _right;
    bool _color; // true = red, false = black
};

struct std_map_int_int {
    struct std_map_node_base* _root;
    size_t _size;
};

#endif // COMPILER_LIBSTDCXX

// =====================
// libc++ Layouts (Clang)
// =====================
#ifdef COMPILER_LIBCXX

struct std_string {
    char* _data;
    size_t _size;
    union {
        size_t _cap;
        char _small[16];
    };
};

struct std_vector_int {
    int* _begin;
    int* _end;
    struct {
        int* _begin;
        size_t _cap;
    } _storage;
};

struct std_shared_ptr_int {
    int* _ptr;
    void* _ctrl_block;
};

struct std_unique_ptr_int {
    int* _ptr;
};

struct std_optional_int {
    char _engaged;
    char _value[sizeof(int)];
};

// libc++ uses red-black tree for std::map/set
struct std_map_node {
    struct std_map_node* _parent;
    struct std_map_node* _left;
    struct std_map_node* _right;
    bool _red;
};

struct std_map_int_int {
    struct std_map_node* _root;
    size_t _size;
};

#endif // COMPILER_LIBCXX

#endif // STL_STRUCTS_H
```

## What's Inside the header?
Each compiler layout includes common STL types:

| Type | MSVC | libstdc++ (GCC) | libc++ (Clang) |
|:---|:----|:----|:----|
| std::string | _ptr, len, cap | data, len, cap | SSO/heap union |
| std::vector<int> | start/cap-end | start/finish/end | begin/end/cap |
| std::shared_ptr | ptr/ref-count | ptr/control blk | ptr/ctrl blk |
| std::unique_ptr<int> | _ptr | _ptr | _ptr |
| std::optional<int> | _has_value, _value | _has_value, _storage[] | _engaged, _value[] |
| std::map<int, int> | _root (rb_node*), _size | _root (map_node_base*), _size | _root (map_node*), _size|

## How to Use It in IDA
### Choose the Right Compiler
Before using the header, identify which compiler was used to build the binary:
* MSVC: Look for ??-prefixed symbols or msvcrt.dll imports.
* GCC: Look for Itanium name mangling (_Z), glibc calls.
* Clang: Similar to GCC but may use libc++ layouts.

### Define the Compiler Macro
At the top of the file, uncomment the matching line:

```c
// #define COMPILER_MSVC
// #define COMPILER_LIBSTDCXX
// #define COMPILER_LIBCXX
```

Example for GCC:

```c
#define COMPILER_LIBSTDCXX
```

### Import the Header into IDA
* Go to: `File → Load` `File → C Header File...`
* Select the `stl_structs_multi_compiler.h` file
* IDA will parse the matching struct definitions

### Apply Structs in Disassembly or Decompiler Views
Highlight a variable or memory region and press T to assign a struct type (e.g., `std_string`, `std_vector_int`, `std_shared_ptr_int`).


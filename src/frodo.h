/********************************************************************************************
* Frodo: a post-quantum key exchange based on the Learning with Errors (LWE) problem.
*
* Abstract: header for settings
*********************************************************************************************/

#ifndef __FRODO_H
#define __FRODO_H

#include <stddef.h>
#include <stdint.h>


// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(WINDOWS)            // Microsoft Windows
    #define OS_TARGET OS_WIN
#elif defined(LINUX)            // Linux
    #define OS_TARGET OS_LINUX 
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2
#define COMPILER_CLANG   3

#if defined(_MSC_VER)           // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
    
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64 
#elif defined(_X86_)
    #define TARGET TARGET_x86
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
#else
    #error -- "Unsupported ARCHITECTURE"
#endif


#if defined(WINDOWS)
    #define ALIGN_HEADER(N) __declspec(align(N))
    #define ALIGN_FOOTER(N) 
#else
    #define ALIGN_HEADER(N)
    #define ALIGN_FOOTER(N) __attribute__((aligned(N)))
#endif


#if defined(AVX2)
    #define USE_AVX2
#endif


#endif

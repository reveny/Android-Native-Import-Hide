//
// HideImport.hpp - A library for hiding and retrieving symbols in ELF binaries.
// Created by reveny and ARandomPerson on 6/6/24.
// Copyright (c) 2024. All rights reserved.
//
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdint.h>
#include <dlfcn.h>
#include <vector>
#include <array>
#include <memory>
#include <cinttypes>
#include <dirent.h>
#include <ctype.h>
#include <string>
#include <cstdio>
#include <unordered_map>
#include <set>
#include <fstream>
#include <mutex>
#include <sstream>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define HI_INLINE __attribute__((always_inline))

#define HI_ENABLE_DEBUG 1
#if HI_ENABLE_DEBUG
    #define HI_TAG "HideImport"
    #if defined(__ANDROID__)
        #include <android/log.h>
        #define HI_LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, HI_TAG, __VA_ARGS__))
        #define HI_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, HI_TAG, __VA_ARGS__))
    #else
        #include <stdio.h>
        #define HI_LOGE(fmt, ...) printf("ERROR: [%s] " fmt "\n", HI_TAG, ##__VA_ARGS__)
        #define HI_LOGI(fmt, ...) printf("INFO: [%s] " fmt "\n", HI_TAG, ##__VA_ARGS__)
    #endif
#else
#define HI_LOGE(fmt, ...)
#define HI_LOGI(fmt, ...)
#endif

// Template to simplify function pointer assignment
template <typename FuncSignature>
class SimpleFunctionPointer;

template <typename R, typename... Args>
class SimpleFunctionPointer<R(Args...)> {
public:
    using Type = R (*)(Args...);

    // Constructor from uintptr_t
    SimpleFunctionPointer(uintptr_t address) : ptr(reinterpret_cast<Type>(address)) {}

    // Overload the function call operator
    R operator()(Args... args) const {
        if (ptr) {
            return ptr(args...);
        } else {
            throw std::runtime_error("Function pointer is null");
        }
    }

    // Assignment operator for function pointer
    SimpleFunctionPointer& operator=(Type p) {
        ptr = p;
        return *this;
    }

    // Assignment operator for uintptr_t
    SimpleFunctionPointer& operator=(uintptr_t address) {
        ptr = reinterpret_cast<Type>(address);
        return *this;
    }
private:
    Type ptr;
};

#define HI_FUNCTION_POINTER(func_name, ret_type, ...) \
    SimpleFunctionPointer<ret_type(__VA_ARGS__)> func_name

#define HI_GET(library, symbol) \
    HideImport::GetSymbol(library, symbol)

#define HI_CALL(library, symbol, ret_type, ...) \
    reinterpret_cast<SimpleFunctionPointer<ret_type(__VA_ARGS__)>::Type>(HI_GET(library, #symbol))

#define HI_GET_SAFE(library, symbol) \
({ \
    auto func = HI_GET(library, symbol); \
    IS_FUNCTION_HOOKED(func) ? NULL : func; \
})

#define HI_CALL_SAFE(library, symbol, ret_type, ...) \
    reinterpret_cast<SimpleFunctionPointer<ret_type(__VA_ARGS__)>::Type>(HI_GET_SAFE(library, #symbol))

#if defined(__x86_64) || defined(__aarch64__)
    #define Elf_Ehdr Elf64_Ehdr
    #define Elf_Shdr Elf64_Shdr
    #define Elf_Sym Elf64_Sym
    #define _ELF_ST_BIND(x) ELF64_ST_BIND(x)
#else
    #define Elf_Ehdr Elf32_Ehdr
    #define Elf_Shdr Elf32_Shdr
    #define Elf_Sym Elf32_Sym
    #define _ELF_ST_BIND(x) ELF32_ST_BIND(x)
#endif

// arm and arm64 only for now.
#if defined(__aarch64__)
    #define IS_LDR_X17(instr) (((instr) & 0xFF000000) == 0x58000000)
    #define IS_BR_X17(instr) ((instr) == 0xd61f0220)
    #define IS_HOOKED_CONDITION (IS_LDR_X17(instr1) && IS_BR_X17(instr2))
#elif defined(__arm__)
    #define IS_LDR_PC(instr) (((instr) & 0x0F7FF000) == 0x051FF000)
    #define IS_BLX_R3(instr) ((instr) == 0xE12FFF33)
    #define IS_HOOKED_CONDITION (IS_LDR_PC(instr1) && IS_BLX_R3(instr2))
#else
    #define IS_HOOKED_CONDITION 0
#endif

#define IS_FUNCTION_HOOKED(function) ({ \
    uint32_t *addr = (uint32_t *)(function); \
    uint32_t instr1 = *addr; \
    uint32_t instr2 = *(addr + 1); \
    int result = 0; \
    if (IS_HOOKED_CONDITION) { \
        uintptr_t *hook_addr_ptr = (uintptr_t *)(addr + 2); \
        result = 1; \
    } \
    result; \
})

namespace HideImport {
    extern std::unordered_map<std::string, uintptr_t> symbolCache;
    extern std::mutex cacheMutex;  // Mutex for thread safe access

    enum class MachineType : uint16_t {
        ELF_EM_NONE = EM_NONE,       // No machine
        ELF_EM_386 = EM_386,         // Intel 80386
        ELF_EM_ARM = EM_ARM,         // ARM
        ELF_EM_X86_64 = EM_X86_64,   // x86_64
        ELF_EM_AARCH64 = EM_AARCH64  // ARM64
    };

    namespace Memory {
        constexpr static auto K_PERM_LENGTH = 5;
        constexpr static auto K_MAP_ENTRY = 7;
        struct MapInfo {
            std::string name;
            uintptr_t start;
            uintptr_t end;
            int perms;
            bool private_map;
            uintptr_t offset;
            dev_t dev;
            ino_t inode;
            std::string path;
        };

        std::vector<MapInfo> ListModulesNew();
        std::string GetLibraryPath(const std::string &path);
        uintptr_t FindLibraryBase(const std::string &path);
    };

    uintptr_t GetELFSymbolOffset(uintptr_t entryAddr, Elf_Ehdr *elfEntry, const char *symbolName);
    uintptr_t MapELFFile(uintptr_t baseAddr, std::string path, std::string symbolName);
    uintptr_t GetSymbol(std::string elfName, std::string symbolName);
};
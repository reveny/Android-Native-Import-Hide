//
// HideImport.cpp - A library for hiding and retrieving symbols in ELF binaries.
// Created by reveny and ARandomPerson on 6/6/24.
// Copyright (c) 2024. All rights reserved.
//
#include "HideImport.hpp"

namespace HideImport {
    std::unordered_map<std::string, uintptr_t> symbolCache;
    std::mutex cacheMutex;
}

// Inspired by LSPlt's implementation of module listing.
// Reference: https://github.com/LSPosed/LSPlt/blob/a674793be6bc060b6d695c0cb481e8262c763885/lsplt/src/main/jni/lsplt.cc#L245
/**
 * ListModulesNew - Lists memory mappings of the current process by reading /proc/self/maps.
 * Parses each line of the maps file and extracts memory region information.
 *
 * @return A vector of MapInfo structures containing details about each memory region.
 */
std::vector<HideImport::Memory::MapInfo> HideImport::Memory::ListModulesNew() {
    std::vector<MapInfo> info;
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY);
    if (fd == -1) {
        HI_LOGE("Failed to open /proc/self/maps with error: %s", strerror(errno));
        return info;
    }

    char buffer[4096];
    ssize_t bytesRead;
    std::string line;
    while ((bytesRead = syscall(__NR_read, fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        line += buffer;

        size_t pos;
        while ((pos = line.find('\n')) != std::string::npos) {
            std::string entry = line.substr(0, pos);
            line.erase(0, pos + 1);

            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t offset = 0;
            ino_t inode = 0;
            unsigned int devMajor = 0;
            unsigned int devMinor = 0;
            std::array<char, K_PERM_LENGTH> perm{'\0'};
            int pathOff;

            // Extract fields from the entry line
            if (sscanf(entry.c_str(), "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n", &start, &end, perm.data(), &offset, &devMajor, &devMinor, &inode, &pathOff) != K_MAP_ENTRY) {
                continue;
            }

            // Skip spaces to find the path offset
            while (pathOff < entry.size() && isspace(entry[pathOff])) {
                pathOff++;
            }

            auto &ref = info.emplace_back(MapInfo{
                entry,
                start,
                end,
                0,
                perm[3] == 'p',
                offset,
                makedev(devMajor, devMinor),
                inode,
                entry.substr(pathOff)
            });

            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
    }

    if (bytesRead == -1) {
        HI_LOGE("Failed to read /proc/self/maps file: %s", strerror(errno));
        perror("read");
    }

    close(fd);
    return info;
}

/**
 * GetLibraryPath - Retrieves the full path of a loaded library by matching the provided substring.
 * 
 * @param path The substring to match against the library paths.
 * @return The full path of the matching library, or an empty string if not found.
 */
std::string HideImport::Memory::GetLibraryPath(const std::string &path) {
    std::vector<MapInfo> modules = ListModulesNew();
    for (const auto& module : modules) {
        if (module.path.find(path) != std::string::npos) {
            return module.path;
        }
    }
    return "";
}

/**
 * FindLibraryBase - Finds the base address of a loaded library by matching the provided substring.
 *
 * @param path The substring to match against the library paths.
 * @return The base address of the matching library, or 0 if not found.
 */
uintptr_t HideImport::Memory::FindLibraryBase(const std::string &path) {
    auto modules = ListModulesNew();
    for (const auto& module : modules) {
        if (module.path.find(path) != std::string::npos) {
            return module.start;
        }
    }
    return 0;
}

/**
 * GetELFSymbolOffset - Retrieves the offset of a symbol within an ELF binary.
 *
 * @param entryAddr The base address of the ELF binary in memory.
 * @param entryElf The ELF header of the binary.
 * @param symbolName The name of the symbol to find.
 * @return The offset of the symbol within the ELF binary, or -1 if not found.
 */
uintptr_t HideImport::GetELFSymbolOffset(uintptr_t entryAddr, Elf_Ehdr *entryElf, const char* symbolName) {
    uintptr_t result = static_cast<uintptr_t>(-1);
    Elf_Shdr* sections = reinterpret_cast<Elf_Shdr*>(entryAddr + static_cast<uintptr_t>(entryElf->e_shoff));
    Elf_Shdr* symtab = nullptr;

    // Find the symbol table section
    for (int i = 0; i < entryElf->e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB || sections[i].sh_type == SHT_DYNSYM) {
            symtab = &sections[i];
            break;
        }
    }

    if (!symtab) {
        return result;
    }

    const char* strSecAddr = reinterpret_cast<const char*>(entryAddr + static_cast<uintptr_t>(sections[symtab->sh_link].sh_offset));
    Elf_Sym* symSec = reinterpret_cast<Elf_Sym*>(entryAddr + static_cast<uintptr_t>(symtab->sh_offset));
    int nSymbols = symtab->sh_size / sizeof(Elf_Sym);

    // Search for the symbol by name
    for (int i = 0; i < nSymbols; i++) {
        if (!(_ELF_ST_BIND(symSec[i].st_info) & (STT_FUNC | STB_GLOBAL))) {
            continue;
        }

        const char* currSymbolName = strSecAddr + symSec[i].st_name;
        if (strcmp(currSymbolName, symbolName) == 0) {
            result = symSec[i].st_value;
            break;
        }
    }

    HI_LOGI("Found offset (%p) of %s.", result, symbolName);
    return result;
}

/**
 * MapELFFile - Maps an ELF file into memory and retrieves the address of a specified symbol.
 *
 * @param baseAddr The base address of the ELF library in memory.
 * @param path The file path of the ELF library.
 * @param symbolName The name of the symbol to find.
 * @return The absolute address of the symbol, or -1 if not found.
 */
uintptr_t HideImport::MapELFFile(uintptr_t baseAddr, std::string path, std::string symbolName) {
    uintptr_t result = static_cast<uintptr_t>(-1);

    int fd = syscall(__NR_open, path.c_str(), O_RDONLY);
    if (fd < 0) {
        return result;
    }

    struct stat elfStat;
    if (fstat(fd, &elfStat) < 0) {
        close(fd);
        return result;
    }

    void *entryRaw = (void *)syscall(__NR_mmap, NULL, static_cast<size_t>(elfStat.st_size), PROT_READ, MAP_SHARED, fd, 0);
    if (entryRaw == MAP_FAILED) {
        close(fd);
        return result;
    }

    // Get the symbol offset and calculate the absolute address
    auto* elfEntry = static_cast<Elf_Ehdr*>(entryRaw);
    uintptr_t offset = GetELFSymbolOffset(reinterpret_cast<uintptr_t>(entryRaw), elfEntry, symbolName.c_str());
    result = baseAddr + offset;

    HI_LOGI("Found absolute address %p of symbol %s in %s", result, symbolName.c_str(), path.c_str());

    // Clean up
    syscall(__NR_munmap, entryRaw, static_cast<size_t>(elfStat.st_size));
    close(fd);

    return result;
}

/**
 * GetSymbol - Retrieves the address of a symbol within a specified ELF library.
 *
 * @param elfName The name of the ELF library.
 * @param symbolName The name of the symbol to find.
 * @return The address of the symbol, or 0 if not found.
 */
HI_INLINE uintptr_t HideImport::GetSymbol(std::string elfName, std::string symbolName) {
    std::string key = elfName + ":" + symbolName;
    {
        // Check the cache first
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (symbolCache.find(key) != symbolCache.end()) {
            HI_LOGI("Cache hit for symbol %s in %s", symbolName.c_str(), elfName.c_str());
            return symbolCache[key];
        }
    }

    uintptr_t base = Memory::FindLibraryBase(elfName);
    if (base == 0) {
        return 0;
    }
    HI_LOGI("Found memory base: %p", base);

    std::string path = Memory::GetLibraryPath(elfName);
    uintptr_t result = MapELFFile(base, path, symbolName);

    // Cache the result
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        symbolCache[key] = result;
    }

    return result;
}
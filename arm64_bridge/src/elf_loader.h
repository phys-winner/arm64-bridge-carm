#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <elf.h>

struct ElfSegment {
    uint32_t vaddr;
    uint32_t memsz;
    uint32_t filesz;
    uint32_t flags;
    uint32_t offset;
};

struct ElfSymbol {
    std::string name;
    uint32_t value;
    uint32_t size;
    uint8_t bind;
    uint8_t type;
    uint16_t shndx;
};

using SymbolResolver = std::function<uint32_t(const std::string& name)>;

class ElfLoader {
public:
    ElfLoader(uint8_t* guest_memory_base, uint32_t load_base_addr = 0x40000000);
    ~ElfLoader();

    bool Load(const std::string& filepath);
    bool LoadFromMemory(const uint8_t* data, size_t size);
    bool Relocate(const SymbolResolver& resolver);

    uint32_t GetSymbolAddress(const std::string& name) const;
    uint32_t GetBaseAddress() const { return m_load_base; }
    uint32_t GetImageSize() const { return m_image_size; }
    bool ContainsAddress(uint32_t guest_address) const;
    const std::vector<uint32_t>& GetInitArray() const { return m_init_array; }
    const std::vector<std::string>& GetNeededLibraries() const { return m_needed_libs; }
    const std::vector<std::string>& GetUndefinedSymbols() const { return m_undefined_symbols; }
    // Guest addresses of .ARM.exidx (start and one-past-end). Used by the
    // __gnu_Unwind_Find_exidx thunk so guest C++ exceptions can unwind.
    uint32_t GetExidxStart() const { return m_exidx_start; }
    uint32_t GetExidxEnd() const { return m_exidx_end; }
    // W335 (run448): GOT location + plt-entry count, for the shadow+heal
    // scan that repairs wild-written import slots.
    uint32_t GetGotVaddr() const { return m_got_vaddr; }
    uint32_t GetPltRelSize() const { return m_plt_rel_size; }

private:
    bool ParseHeader(const uint8_t* data, size_t size);
    bool LoadSegments(const uint8_t* data, size_t size);
    bool ParseDynamic(const uint8_t* data, size_t size);
    bool ProcessRelocations(const SymbolResolver& resolver);
    void ParseExidx(const uint8_t* data, size_t size);

    uint8_t* m_guest_mem;
    uint32_t m_load_base;
    uint32_t m_image_size = 0;
    uint32_t m_exidx_start = 0;
    uint32_t m_exidx_end = 0;

    std::vector<ElfSegment> m_segments;
    std::unordered_map<std::string, ElfSymbol> m_exported_symbols;
    std::vector<std::string> m_undefined_symbols;
    std::vector<std::string> m_needed_libs;
    std::vector<uint32_t> m_init_array;
    uint32_t m_init_func = 0;

    // Dynamic section metadata
    uint32_t m_strtab_vaddr = 0;
    uint32_t m_symtab_vaddr = 0;
    uint32_t m_rel_vaddr = 0;
    uint32_t m_rel_size = 0;
    uint32_t m_plt_rel_vaddr = 0;
    uint32_t m_plt_rel_size = 0;
    uint32_t m_got_vaddr = 0;
};

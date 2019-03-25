#ifndef H_ELF_PARSER
#define H_ELF_PARSER

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include "hash.hpp"

#ifndef ARM32
#include <elf.h>
static constexpr uint64_t bits = 64u;
#else
#include "./elf.h"
static constexpr uint64_t bits = 32u;
#endif

namespace elf_parser {
  
  using section_t = struct section_t
                    {
                      int section_index = 0;
                      std::intptr_t section_offset;
                      std::intptr_t section_addr;
                      uint64_t section_name_hash;
                      uint64_t section_type_hash;
                      uint64_t section_size;
                      uint64_t section_ent_size;
                      uint64_t section_addr_align;
  };

  using segment_t = struct segment_t
                    {
                      uint64_t segment_name_hash;
                      uint64_t segment_type_hash;
                      uint64_t segment_flags_hash;
                      uint64_t segment_offset;
                      uint64_t segment_virtaddr;
                      uint64_t segment_physaddr;
                      uint64_t segment_filesize;
                      uint64_t segment_memsize;
                      uint64_t segment_align;
  };

  using symbol_t = struct symbol_t
                   {
                     uint64_t symbol_name_hash;
                     uint64_t symbol_index_hash;
                     std::intptr_t symbol_value;
                     uint64_t symbol_num = 0u;
                     uint64_t symbol_size = 0u;
                     uint64_t symbol_type_hash;
                     uint64_t symbol_bind_hash;
                     uint64_t symbol_visibility_hash;
                     uint64_t symbol_section_hash;
  };

  using relocation_t = struct relocation_t
                       {
                         std::intptr_t relocation_offset;
                         std::intptr_t relocation_info;
                         std::intptr_t relocation_symbol_value;
                         std::intptr_t relocation_plt_address;
                         uint64_t relocation_type_hash;
                         uint64_t relocation_symbol_name_hash;
                         uint64_t relocation_section_name_hash;
  };

  class Elf_parser
  {
  public:
	
    using Elf_Ehdr = std::conditional_t< bits == 64u, Elf64_Ehdr, Elf32_Ehdr >;
    using Elf_Shdr = std::conditional_t< bits == 64u, Elf64_Shdr, Elf32_Shdr >;
    using Elf_Phdr = std::conditional_t< bits == 64u, Elf64_Phdr, Elf32_Phdr >;
    using Elf_Sym = std::conditional_t< bits == 64u, Elf64_Sym, Elf32_Sym >;
    using Elf_Rela = std::conditional_t< bits == 64u, Elf64_Rela, Elf32_Rela >;
    using Elf_Rel = std::conditional_t< bits == 64u, Elf64_Rel, Elf32_Rel >;

    Elf_parser( const char * program_path ) : m_program_path( program_path )
    {
      load_memory_map();
    }

    std::vector< section_t > get_sections();
    std::vector< segment_t > get_segments();
    std::vector< symbol_t > get_symbols();
    std::vector< relocation_t > get_relocations();
    uint8_t * get_memory_map();

  private:

    void load_memory_map();
    uint64_t get_section_type_hash( int tt );
    uint64_t get_segment_type_hash( uint32_t & seg_type );
    uint64_t get_segment_flags_hash( uint32_t & seg_flags );
    uint64_t get_symbol_type_hash( uint8_t & sym_type );
    uint64_t get_symbol_bind_hash( uint8_t & sym_bind );
    uint64_t get_symbol_visibility_hash( uint8_t & sym_vis);
    uint64_t get_symbol_index_hash( uint16_t & sym_idx);
    uint64_t get_relocation_type_hash( uint64_t rela_type);
    std::intptr_t get_rel_symbol_value( uint64_t sym_idx, std::vector< symbol_t > & syms );
    uint64_t get_rel_symbol_name_hash( uint64_t sym_idx, std::vector< symbol_t > & syms );
    const char * m_program_path;
    uint8_t * m_mmap_program;
  };
}
#endif

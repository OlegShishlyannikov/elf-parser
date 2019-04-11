#ifndef H_ELF_PARSER
#define H_ELF_PARSER

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdint>
// #include <elf.h>
#include "hash.hpp"
#include "./elf.h"

static constexpr uint64_t bits = 32u;

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

  class elf_parser
  {
  public:
	
    using Elf_Ehdr = Elf32_Ehdr;
    using Elf_Shdr = Elf32_Shdr;
    using Elf_Phdr = Elf32_Phdr;
    using Elf_Sym = Elf32_Sym;
    using Elf_Rela = Elf32_Rela;
    using Elf_Rel = Elf32_Rel;

    elf_parser( const char * program_path ) : m_program_path( program_path )
    {
      load_memory_map();
    }

    int get_sections( section_t ** sections_array );
    int get_segments( segment_t ** segments_array );
    int get_symbols( symbol_t ** symbols_array );
    int get_relocations( relocation_t ** relocations_array );
    int get_memory_map( uint8_t ** mmap );

  private:

    void load_memory_map();
    uint64_t get_section_type_hash( int tt );
    uint64_t get_segment_type_hash( uint32_t & seg_type );
    uint64_t get_segment_flags_hash( uint32_t & seg_flags );
    uint64_t get_symbol_type_hash( uint8_t & sym_type );
    uint64_t get_symbol_bind_hash( uint8_t & sym_bind );
    uint64_t get_symbol_visibility_hash( uint8_t & sym_vis );
    uint64_t get_symbol_index_hash( uint16_t & sym_idx );
    uint64_t get_relocation_type_hash( uint64_t rela_type );
    std::intptr_t get_rel_symbol_value( uint64_t sym_idx, symbol_t * syms, int syms_count );
    uint64_t get_rel_symbol_name_hash( uint64_t sym_idx, symbol_t * syms, int syms_count );
    const char * m_program_path;
    uint8_t * m_mmap_program;
  };
}
#endif

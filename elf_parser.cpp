#include "elf_parser.hpp"

using namespace elf_parser;

std::vector< section_t > Elf_parser::get_sections()
{
  Elf_Ehdr * ehdr = ( Elf_Ehdr * ) m_mmap_program;
  Elf_Shdr * shdr = ( Elf_Shdr * )( m_mmap_program + ehdr->e_shoff );
  int shnum = ehdr->e_shnum;

  Elf_Shdr *sh_strtab = &shdr[ ehdr->e_shstrndx ];
  const char *const sh_strtab_p = ( char * ) m_mmap_program + sh_strtab->sh_offset;

  std::vector< section_t > sections;

  for( int i = 0; i < shnum; ++ i ){

    section_t section;
    section.section_index = i;
    section.section_name_hash = hash_64_fnv1a( sh_strtab_p + shdr[ i ].sh_name, std::strlen( static_cast< const char * >( sh_strtab_p + shdr[ i ].sh_name )));
    section.section_type_hash = get_section_type_hash( shdr[ i ].sh_type );
    section.section_addr = shdr[ i ].sh_addr;
    section.section_offset = shdr[ i ].sh_offset;
    section.section_size = shdr[ i ].sh_size;
    section.section_ent_size = shdr[ i ].sh_entsize;
    section.section_addr_align = shdr[ i ].sh_addralign;
    sections.push_back( section );
  }

  return sections;
}

std::vector< segment_t > Elf_parser::get_segments()
{
  Elf_Ehdr * ehdr = ( Elf_Ehdr * ) m_mmap_program;
  Elf_Phdr * phdr = ( Elf_Phdr * )( m_mmap_program + ehdr->e_phoff );
  int phnum = ehdr->e_phnum;

  Elf_Shdr * shdr = ( Elf_Shdr * )( m_mmap_program + ehdr->e_shoff );
  Elf_Shdr * sh_strtab = &shdr[ ehdr->e_shstrndx ];
  const char * const sh_strtab_p = ( char * ) m_mmap_program + sh_strtab->sh_offset;

  std::vector< segment_t > segments;

  for( int i = 0; i < phnum; ++ i ){

    segment_t segment;
    segment.segment_type_hash = get_segment_type_hash( phdr[ i ].p_type );
    segment.segment_offset = phdr[ i ].p_offset;
    segment.segment_virtaddr = phdr[ i ].p_vaddr;
    segment.segment_physaddr = phdr[ i ].p_paddr;
    segment.segment_filesize = phdr[ i ].p_filesz;
    segment.segment_memsize = phdr[ i ].p_memsz;
    segment.segment_flags_hash = get_segment_flags_hash( phdr[ i ].p_flags );
    segment.segment_align = phdr[ i ].p_align;
    segments.push_back( segment );
  }

  return segments;
}

std::vector< symbol_t > Elf_parser::get_symbols()
{
  std::vector< section_t > secs = get_sections();

  Elf_Ehdr * ehdr = ( Elf_Ehdr * ) m_mmap_program;
  Elf_Shdr * shdr = ( Elf_Shdr * )( m_mmap_program + ehdr->e_shoff );

  char * sh_strtab_p = nullptr;

  for( section_t & sec: secs ){

    if(( sec.section_type_hash == hash_64_fnv1a_const( "SHT_STRTAB" ))
       && ( sec.section_name_hash == hash_64_fnv1a_const( ".strtab" ))){

      sh_strtab_p = ( char * ) m_mmap_program + sec.section_offset;
      break;
    }
  }

  char * sh_dynstr_p = nullptr;

  for( section_t & sec: secs ){

    if(( sec.section_type_hash == hash_64_fnv1a_const( "SHT_STRTAB" ))
       && ( sec.section_name_hash == hash_64_fnv1a_const( ".dynstr" ))){

      sh_dynstr_p = ( char * ) m_mmap_program + sec.section_offset;
      break;
    }
  }

  std::vector< symbol_t > symbols;

  for( section_t & sec: secs ){

    if(( sec.section_type_hash != hash_64_fnv1a_const( "SHT_SYMTAB" ))
       && ( sec.section_type_hash != hash_64_fnv1a_const( "SHT_DYNSYM" )))
      continue;

    uint64_t total_syms = sec.section_size / sizeof( Elf_Sym );
    Elf_Sym * syms_data = ( Elf_Sym * )( m_mmap_program + sec.section_offset );

    for( int i = 0; i < total_syms; ++ i ){

      symbol_t symbol;
      symbol.symbol_num = i;
      symbol.symbol_value = syms_data[ i ].st_value;
      symbol.symbol_size = syms_data[ i ].st_size;
      symbol.symbol_type_hash = get_symbol_type_hash( syms_data[ i ].st_info );
      symbol.symbol_bind_hash = get_symbol_bind_hash( syms_data[ i ].st_info );
      symbol.symbol_visibility_hash = get_symbol_visibility_hash( syms_data[ i ].st_other );
      symbol.symbol_index_hash = get_symbol_index_hash( syms_data[ i ].st_shndx );
      symbol.symbol_section_hash = sec.section_name_hash;

      if( sec.section_type_hash == hash_64_fnv1a_const( "SHT_SYMTAB" ))
        symbol.symbol_name_hash = hash_64_fnv1a( sh_strtab_p + syms_data[ i ].st_name,
                                                 std::strlen( static_cast< const char * >( sh_strtab_p + syms_data[ i ].st_name )));

      if( sec.section_type_hash == hash_64_fnv1a_const( "SHT_DYNSYM" ))
        symbol.symbol_name_hash = hash_64_fnv1a( sh_dynstr_p + syms_data[ i ].st_name,
                                                 std::strlen( static_cast< const char * >( sh_dynstr_p + syms_data[ i ].st_name )));

      symbols.push_back( symbol );
    }
  }

  return symbols;
}

std::vector< relocation_t > Elf_parser::get_relocations()
{
  std::vector< section_t > secs = get_sections();
  std::vector< symbol_t > syms = get_symbols();

  int  plt_entry_size = 0;
  long plt_vma_address = 0;

  for( section_t & sec : secs ){

    if( sec.section_name_hash == hash_64_fnv1a_const( ".plt" )){

      plt_entry_size = sec.section_ent_size;
      plt_vma_address = sec.section_addr;
      break;
    }
  }

  std::vector< relocation_t > relocations;

  for( section_t & sec : secs ){

    if( sec.section_type_hash == hash_64_fnv1a_const( "SHT_RELA" )){

      uint64_t total_relas = sec.section_size / sizeof( Elf_Rela );
      Elf_Rela * relas_data  = ( Elf_Rela * )( m_mmap_program + sec.section_offset );

      for( uint64_t i = 0; i < total_relas; ++ i ){

        relocation_t rel;
        rel.relocation_offset = static_cast< std::intptr_t >( relas_data[ i ].r_offset );
        rel.relocation_info = static_cast< std::intptr_t >( relas_data[ i ].r_info );
        rel.relocation_type_hash = get_relocation_type_hash( relas_data[ i ].r_info );
        rel.relocation_symbol_value = get_rel_symbol_value( relas_data[ i ].r_info, syms );
        rel.relocation_symbol_name_hash = get_rel_symbol_name_hash( relas_data[ i ].r_info, syms );
        rel.relocation_plt_address = plt_vma_address + ( i + 1 ) * plt_entry_size;
        rel.relocation_section_name_hash = sec.section_name_hash;
        relocations.push_back( rel );

      }
    } else if( sec.section_type_hash == hash_64_fnv1a_const( "SHT_REL" )){

      uint64_t total_relas = sec.section_size / sizeof( Elf_Rel );
      Elf_Rel * relas_data  = ( Elf_Rel * )( m_mmap_program + sec.section_offset );

      for( uint64_t i = 0; i < total_relas; ++ i ){

        relocation_t rel;
        rel.relocation_offset = static_cast< std::intptr_t >( relas_data[ i ].r_offset );
        rel.relocation_info = static_cast< std::intptr_t >( relas_data[ i ].r_info );
        rel.relocation_type_hash = get_relocation_type_hash( relas_data[ i ].r_info );
        rel.relocation_symbol_value = get_rel_symbol_value( relas_data[ i ].r_info, syms );
        rel.relocation_symbol_name_hash = get_rel_symbol_name_hash( relas_data[ i ].r_info, syms );
        rel.relocation_plt_address = plt_vma_address + ( i + 1 ) * plt_entry_size;
        rel.relocation_section_name_hash = sec.section_name_hash;
        relocations.push_back( rel );

      }

    } else {

      continue;

    }
  }

  return relocations;
}

uint8_t * Elf_parser::get_memory_map()
{
  return m_mmap_program;
}

void Elf_parser::load_memory_map()
{
  FILE * f = fopen( m_program_path, "rb" );

  if( f == NULL ){

    std::printf( "Error during opening file ...\r\n" );
    std::exit( 1 );
  }

  fseek( f, 0, SEEK_END );
  unsigned long f_size = ftell( f );
  fseek( f, 0, SEEK_SET );

  m_mmap_program = static_cast< uint8_t * >( std::malloc( f_size ));
  fread( m_mmap_program, f_size, 1, f );
  fclose( f );

  Elf_Ehdr * header = ( Elf_Ehdr * ) m_mmap_program;
}

uint64_t Elf_parser::get_section_type_hash( int tt ){

  if( tt < 0 ) return hash_64_fnv1a_const( "UNKNOWN" );

  switch( tt ){

  case 0: return hash_64_fnv1a_const( "SHT_NULL" );      /* Section header table entry unused */
  case 1: return hash_64_fnv1a_const( "SHT_PROGBITS" );  /* Program data */
  case 2: return hash_64_fnv1a_const( "SHT_SYMTAB" );    /* Symbol table */
  case 3: return hash_64_fnv1a_const( "SHT_STRTAB" );    /* String table */
  case 4: return hash_64_fnv1a_const( "SHT_RELA" );      /* Relocation entries with addends */
  case 5: return hash_64_fnv1a_const( "SHT_HASH" );      /* Symbol hash table */
  case 6: return hash_64_fnv1a_const( "SHT_DYNAMIC" );   /* Dynamic linking information */
  case 7: return hash_64_fnv1a_const( "SHT_NOTE" );      /* Notes */
  case 8: return hash_64_fnv1a_const( "SHT_NOBITS" );    /* Program space with no data (bss) */
  case 9: return hash_64_fnv1a_const( "SHT_REL" );       /* Relocation entries, no addends */
  case 11: return hash_64_fnv1a_const( "SHT_DYNSYM" );   /* Dynamic linker symbol table */
  default: return hash_64_fnv1a_const( "UNKNOWN" );
  }

  return hash_64_fnv1a_const( "UNKNOWN" );
}

uint64_t Elf_parser::get_segment_type_hash( uint32_t & seg_type )
{
  switch( seg_type ){

  case PT_NULL:   return hash_64_fnv1a_const( "NULL" );                  /* Program header table entry unused */
  case PT_LOAD: return hash_64_fnv1a_const( "LOAD" );                    /* Loadable program segment */
  case PT_DYNAMIC: return hash_64_fnv1a_const( "DYNAMIC" );              /* Dynamic linking information */
  case PT_INTERP: return hash_64_fnv1a_const( "INTERP" );                /* Program interpreter */
  case PT_NOTE: return hash_64_fnv1a_const( "NOTE" );                    /* Auxiliary information */
  case PT_SHLIB: return hash_64_fnv1a_const( "SHLIB" );                  /* Reserved */
  case PT_PHDR: return hash_64_fnv1a_const( "PHDR" );                    /* Entry for header table itself */
  case PT_TLS: return hash_64_fnv1a_const( "TLS" );                      /* Thread-local storage segment */
  case PT_NUM: return hash_64_fnv1a_const( "NUM" );                      /* Number of defined types */
  case PT_LOOS: return hash_64_fnv1a_const( "LOOS" );                    /* Start of OS-specific */
  case PT_GNU_EH_FRAME: return hash_64_fnv1a_const( "GNU_EH_FRAME" );    /* GCC .eh_frame_hdr segment */
  case PT_GNU_STACK: return hash_64_fnv1a_const( "GNU_STACK" );          /* Indicates stack executability */
  case PT_GNU_RELRO: return hash_64_fnv1a_const( "GNU_RELRO" );          /* Read-only after relocation */
  case PT_SUNWBSS: return hash_64_fnv1a_const( "SUNWBSS" );              /* Sun Specific segment */
  case PT_SUNWSTACK: return hash_64_fnv1a_const( "SUNWSTACK" );          /* Stack segment */
  case PT_HIOS: return hash_64_fnv1a_const( "HIOS" );                    /* End of OS-specific */
  case PT_LOPROC: return hash_64_fnv1a_const( "LOPROC" );                /* Start of processor-specific */
  case PT_HIPROC: return hash_64_fnv1a_const( "HIPROC" );                /* End of processor-specific */
  default: return hash_64_fnv1a_const( "UNKNOWN" );
  }

  return hash_64_fnv1a_const( "UNKNOWN" );
}

uint64_t Elf_parser::get_segment_flags_hash( uint32_t & seg_flags )
{
  if(( seg_flags & PF_R ) && ( seg_flags & PF_W ) && ( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "RWX" );

  } else if(( seg_flags & PF_R ) && ( seg_flags & PF_W ) && !( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "RW" );

  } else if(( seg_flags & PF_R ) && !( seg_flags & PF_W ) && ( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "RX" );

  } else if(( seg_flags & PF_R ) && !( seg_flags & PF_W ) && !( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "R" );

  } else if(!( seg_flags & PF_R ) && ( seg_flags & PF_W ) && ( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "WX" );

  } else if(!( seg_flags & PF_R ) && ( seg_flags & PF_W ) && !( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "W" );

  } else if(!( seg_flags & PF_R ) && !( seg_flags & PF_W ) && ( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "X" );

  } else if(!( seg_flags & PF_R ) && !( seg_flags & PF_W ) && !( seg_flags & PF_X )){

    return hash_64_fnv1a_const( "" );

  } else {

    return hash_64_fnv1a_const( "" );

  }
}

uint64_t Elf_parser::get_symbol_type_hash( uint8_t & sym_type )
{
  switch( ELF32_ST_TYPE( sym_type )){

  case 0: return hash_64_fnv1a_const( "NOTYPE" );
  case 1: return hash_64_fnv1a_const( "OBJECT" );
  case 2: return hash_64_fnv1a_const( "FUNC" );
  case 3: return hash_64_fnv1a_const( "SECTION" );
  case 4: return hash_64_fnv1a_const( "FILE" );
  case 6: return hash_64_fnv1a_const( "TLS" );
  case 7: return hash_64_fnv1a_const( "NUM" );
  case 10: return hash_64_fnv1a_const( "LOOS" );
  case 12: return hash_64_fnv1a_const( "HIOS" );
  default: return hash_64_fnv1a_const( "UNKNOWN" );
  }

  return hash_64_fnv1a_const( "UNKNOWN" );
}
uint64_t Elf_parser::get_symbol_bind_hash( uint8_t & sym_bind )
{
  switch( ELF32_ST_BIND( sym_bind )){

  case 0: return hash_64_fnv1a_const( "LOCAL" );
  case 1: return hash_64_fnv1a_const( "GLOBAL" );
  case 2: return hash_64_fnv1a_const( "WEAK" );
  case 3: return hash_64_fnv1a_const( "NUM" );
  case 10: return hash_64_fnv1a_const( "UNIQUE" );
  case 12: return hash_64_fnv1a_const( "HIOS" );
  case 13: return hash_64_fnv1a_const( "LOPROC" );
  default: return hash_64_fnv1a_const( "UNKNOWN" );
  }

  return hash_64_fnv1a_const( "UNKNOWN" );
}

uint64_t Elf_parser::get_symbol_visibility_hash( uint8_t & sym_vis )
{
  switch( ELF32_ST_VISIBILITY( sym_vis )){

  case 0: return hash_64_fnv1a_const( "DEFAULT" );
  case 1: return hash_64_fnv1a_const( "INTERNAL" );
  case 2: return hash_64_fnv1a_const( "HIDDEN" );
  case 3: return hash_64_fnv1a_const( "PROTECTED" );
  default: return hash_64_fnv1a_const( "UNKNOWN" );
  }

  return hash_64_fnv1a_const( "UNKNOWN" );
}

uint64_t Elf_parser::get_symbol_index_hash( uint16_t & sym_idx )
{
  char str[ 2 ];
  std::snprintf( str, sizeof( sym_idx ), "%u", sym_idx );

  switch( sym_idx ){
	
  case SHN_ABS : return hash_64_fnv1a_const( "ABS" );
  case SHN_COMMON : return hash_64_fnv1a_const( "COM" );
  case SHN_UNDEF : return hash_64_fnv1a_const( "UND" );
  case SHN_XINDEX : return hash_64_fnv1a_const( "COM" );
  default : return hash_64_fnv1a( str, sizeof( str ) / sizeof( str[ 0 ]));
  }

  return hash_64_fnv1a( str, sizeof( str ) / sizeof( str[ 0 ]));
}

uint64_t Elf_parser::get_relocation_type_hash( uint64_t rela_type )
{
#ifdef ARM32
  switch( ELF32_R_TYPE( rela_type )){
  case 0 : return hash_64_fnv1a_const( "R_ARM_NONE" );
  case 1 : return hash_64_fnv1a_const( "R_ARM_PC24" );
  case 2 : return hash_64_fnv1a_const( "R_ARM_ABS32" );
  case 5 : return hash_64_fnv1a_const( "R_ARM_REL32" );
  case 6 : return hash_64_fnv1a_const( "R_ARM_PC13" );
  case 7 :  return hash_64_fnv1a_const( "R_ARM_ABS16" );
  default: return hash_64_fnv1a_const( "OTHERS" );
  }

#else
  switch( ELF64_R_TYPE( rela_type )){
  case 0 : return hash_64_fnv1a_const( "R_X86_64_NONE" );
  case 1 : return hash_64_fnv1a_const( "R_X86_64_32" );
  case 2 : return hash_64_fnv1a_const( "R_X86_64_PC32" );
  case 5 : return hash_64_fnv1a_const( "R_X86_64_COPY" );
  case 6 : return hash_64_fnv1a_const( "R_X86_64_GLOB_DAT" );
  case 7 :  return hash_64_fnv1a_const( "R_X86_64_JUMP_SLOT" );
  default: return hash_64_fnv1a_const( "OTHERS" );
  }
#endif

  return hash_64_fnv1a_const( "OTHERS" );
}

std::intptr_t Elf_parser::get_rel_symbol_value( uint64_t sym_idx, std::vector< symbol_t > & syms )
{
  std::intptr_t sym_val = 0;

  for( symbol_t & sym: syms ){

    if( sym.symbol_num == ELF64_R_SYM( sym_idx )){

      sym_val = sym.symbol_value;
      break;
    }
  }

  return sym_val;
}

uint64_t Elf_parser::get_rel_symbol_name_hash( uint64_t sym_idx, std::vector< symbol_t > & syms )
{
  uint64_t sym_name;

  for( symbol_t & sym: syms ){

#ifdef ARM32
    if( sym.symbol_num == ELF32_R_SYM( sym_idx )){

      sym_name = sym.symbol_name_hash;
      break;
    }
  }

#else
  if( sym.symbol_num == ELF64_R_SYM( sym_idx )){

    sym_name = sym.symbol_name_hash;
    break;
  }
}

#endif /* ARM32 */
return sym_name;
}

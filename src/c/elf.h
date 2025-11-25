
#pragma once

#include <elf.h>

struct DymSegment
{
    Elf64_Rela *rela;
    int rela_ent_count;

    Elf64_Sym *dynsym;
    char* dynstr;
};

int get_phdr(uint64_t base, Elf64_Ehdr *ehdr, Elf64_Phdr* *p_phdr);
Elf64_Dyn* get_dynamic(uint64_t base, Elf64_Phdr *phdr, int size);
void parse_dyn_segment(uint64_t base, Elf64_Dyn *dynmaic, struct DymSegment* ds);
Elf64_Rela* find_sym_rela(uint64_t base, struct DymSegment* ds, const char* name);


// elf.c

#include "elf.h"
#include <stddef.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>

int get_phdr(uint64_t base, Elf64_Ehdr *ehdr, Elf64_Phdr* *p_phdr)
{
    Elf64_Phdr* p = (Elf64_Phdr*)(ehdr->e_phoff + base);
    *p_phdr = p;
    return ehdr->e_phnum;
}

Elf64_Dyn* get_dynamic(uint64_t base, Elf64_Phdr *phdr, int size)
{
    for(int i = 0; i < size; i += 1)
    {
        if (phdr[i].p_type == PT_DYNAMIC)
        {
            return (Elf64_Dyn*)(phdr[i].p_vaddr + base);
        }
    }

    return NULL;
}


void parse_dyn_segment(uint64_t base, Elf64_Dyn *dynmaic, struct DymSegment* ds)
{
    int i = 0;
    size_t rela_sz = 0, rela_ent = 0;

    while (dynmaic[i].d_tag != DT_NULL)
    {
        switch (dynmaic[i].d_tag)
        {
        case DT_RELASZ:
            rela_sz = dynmaic[i].d_un.d_val;
            break;
        case DT_RELAENT:
            rela_ent = dynmaic[i].d_un.d_val;
            break;
        case DT_RELA:
            ds->rela = (Elf64_Rela*)(dynmaic[i].d_un.d_ptr);
            break;
        case DT_SYMTAB:
            ds->dynsym = (Elf64_Sym*)(dynmaic[i].d_un.d_ptr);
            break;
        case DT_STRTAB:
            ds->dynstr = (char*)(dynmaic[i].d_un.d_ptr);
            break;
        default:
            break;
        }
        i++;
    }
    ds->rela_ent_count = rela_sz / rela_ent;
}

static Elf64_Sym* get_dynsym(uint64_t base, struct DymSegment* ds, Elf64_Rela* rela)
{
    uint32_t sym_index = rela->r_info >> 32;
    if (sym_index)
    {
        return &ds->dynsym[sym_index];
    }

    return NULL;
}

Elf64_Rela* find_sym_rela(uint64_t base, struct DymSegment* ds, const char* name)
{
    for (int i = 0; i< ds->rela_ent_count; i++)
    {
        Elf64_Sym* s = get_dynsym(base, ds, &ds->rela[i]);
        if (s)
        {
            char* sym_name = ds->dynstr + s->st_name;

            if(strcmp(sym_name, name) == 0)
            {
                return &ds->rela[i];
            }
        }
    }

    return NULL;
}
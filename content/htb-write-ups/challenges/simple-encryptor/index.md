+++
title = "Simple Encryptor"
date = "2023-12-09"
description = "This is a very easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Reversing

**Release date**: 2022-07-22

**Created by**: [Leeky](https://app.hackthebox.com/users/129896)

**Description**: On our regular checkups of our secret flag storage server we found out that we were hit by ransomware! The original flag data is nowhere to be found, but luckily we not only have the encrypted file but also the encryption program itself.

# Setup

I'll complete this challenge using a Linux VM. I'll create a `workspace` directory at `/` to hold all the files related to this challenge. The commands ran on my machine will be prefixed with `❯` for clarity.

# Identification

```sh
❯ tree -a "/workspace"
```

```
/workspace
├── encrypt
└── flag.enc

<SNIP>
```

The challenge is comprised of two files: `encrypt` and `flag.enc`.

The `flag.enc` file contains a bunch of random data. The `.enc` extension hints this is the encrypted version of the flag file.

The `encrypt` file is a binary probably meant to be run on Linux. But let's confirm this by running `file` on it.

```sh
❯ file /workspace/encrypt
```

```
/workspace/encrypt: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0bddc0a794eca6f6e2e9dac0b6190b62f07c4c75, for GNU/Linux 3.2.0, not stripped
```

Okay, so it looks like this is a ELF 64-bit, LSB executable.

Let's find more information about it using `zn-bin`.

```sh
❯ rz-bin -I /workspace/encrypt
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x00003b1e
bintype  elf
bits     64
class    ELF64
compiler GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
dbg_file N/A
endian   LE
hdr.csum N/A
guid     N/A
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x00000000
lang     c
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
os       linux
cc       N/A
pcalign  0
relro    full
rpath    NONE
subsys   linux
stripped false
crypto   false
havecode true
va       true
sanitiz  false
static   false
linenum  true
lsyms    true
canary   true
PIE      true
RELROCS  true
NX       true
```

This confirms the information we got with `file`.

We notice that there are a few protections in place. This is not a binary exploitation challenge, but it's still interesting to know.

# Libraries

Let's find the list of libraries used by this binary.

```sh
❯ rz-bin -l /workspace/encrypt
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
❯ rz-bin -i /workspace/encrypt
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
2   0x000010f0 GLOBAL FUNC       fread
3   0x00001100 GLOBAL FUNC       fclose
4   0x00001110 GLOBAL FUNC       __stack_chk_fail
5   ---------- GLOBAL FUNC       __libc_start_main
6   0x00001120 GLOBAL FUNC       srand
7   0x00001130 GLOBAL FUNC       ftell
8   ---------- WEAK   NOTYPE     __gmon_start__
9   0x00001140 GLOBAL FUNC       time
10  0x00001150 GLOBAL FUNC       malloc
11  0x00001160 GLOBAL FUNC       fseek
12  0x00001170 GLOBAL FUNC       fopen
13  0x00001180 GLOBAL FUNC       fwrite
14  ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
15  0x00001190 GLOBAL FUNC       rand
16  ---------- WEAK   FUNC       __cxa_finalize
```

So this binary imports functions like `time` and `srand` probably to generate random numbers. It also calls `fread`, `fopen`, `fclose` and the likes to read and write to files. Finally, the `fwrite` function is likely used to print text to the terminal.

# Symbols

Let's find the list of symbols for this binary.

```sh
❯ rz-bin -s /workspace/encrypt
```

```
[Symbols]
nth paddr      vaddr      bind   type   size lib name                                   
----------------------------------------------------------------------------------------
1   0x00000318 0x00000318 LOCAL  SECT   0        .interp
2   0x00000338 0x00000338 LOCAL  SECT   0        .note.gnu.property
3   0x00000358 0x00000358 LOCAL  SECT   0        .note.gnu.build-id
4   0x0000037c 0x0000037c LOCAL  SECT   0        .note.ABI-tag
5   0x000003a0 0x000003a0 LOCAL  SECT   0        .gnu.hash
6   0x000003c8 0x000003c8 LOCAL  SECT   0        .dynsym
7   0x00000560 0x00000560 LOCAL  SECT   0        .dynstr
8   0x00000630 0x00000630 LOCAL  SECT   0        .gnu.version
9   0x00000658 0x00000658 LOCAL  SECT   0        .gnu.version_r
10  0x00000688 0x00000688 LOCAL  SECT   0        .rela.dyn
11  0x00000748 0x00000748 LOCAL  SECT   0        .rela.plt
12  0x00001000 0x00001000 LOCAL  SECT   0        .init
13  0x00001020 0x00001020 LOCAL  SECT   0        .plt
14  0x000010e0 0x000010e0 LOCAL  SECT   0        .plt.got
15  0x000010f0 0x000010f0 LOCAL  SECT   0        .plt.sec
16  0x000011a0 0x000011a0 LOCAL  SECT   0        .text
17  0x000014b8 0x000014b8 LOCAL  SECT   0        .fini
18  0x00002000 0x00002000 LOCAL  SECT   0        .rodata
19  0x00002018 0x00002018 LOCAL  SECT   0        .eh_frame_hdr
20  0x00002060 0x00002060 LOCAL  SECT   0        .eh_frame
21  0x00002d68 0x00003d68 LOCAL  SECT   0        .init_array
22  0x00002d70 0x00003d70 LOCAL  SECT   0        .fini_array
23  0x00002d78 0x00003d78 LOCAL  SECT   0        .dynamic
24  0x00002f68 0x00003f68 LOCAL  SECT   0        .got
25  0x00003000 0x00004000 LOCAL  SECT   0        .data
26  ---------- 0x00004010 LOCAL  SECT   0        .bss
27  0x00000000 0x00000000 LOCAL  SECT   0        .comment
28  0x00000000 0x00000000 LOCAL  FILE   0        crtstuff.c
29  0x000011d0 0x000011d0 LOCAL  FUNC   0        deregister_tm_clones
30  0x00001200 0x00001200 LOCAL  FUNC   0        register_tm_clones
31  0x00001240 0x00001240 LOCAL  FUNC   0        __do_global_dtors_aux
32  ---------- 0x00004010 LOCAL  OBJ    1        completed.8061
33  0x00002d70 0x00003d70 LOCAL  OBJ    0        __do_global_dtors_aux_fini_array_entry
34  0x00001280 0x00001280 LOCAL  FUNC   0        frame_dummy
35  0x00002d68 0x00003d68 LOCAL  OBJ    0        __frame_dummy_init_array_entry
36  0x00000000 0x00000000 LOCAL  FILE   0        encrypt.c
37  0x00000000 0x00000000 LOCAL  FILE   0        crtstuff.c
38  0x00002164 0x00002164 LOCAL  OBJ    0        __FRAME_END__
39  0x00000000 0x00000000 LOCAL  FILE   0        
40  0x00002d70 0x00003d70 LOCAL  NOTYPE 0        __init_array_end
41  0x00002d78 0x00003d78 LOCAL  OBJ    0        _DYNAMIC
42  0x00002d68 0x00003d68 LOCAL  NOTYPE 0        __init_array_start
43  0x00002018 0x00002018 LOCAL  NOTYPE 0        __GNU_EH_FRAME_HDR
44  0x00002f68 0x00003f68 LOCAL  OBJ    0        _GLOBAL_OFFSET_TABLE_
45  0x00001000 0x00001000 LOCAL  FUNC   0        _init
46  0x000014b0 0x000014b0 GLOBAL FUNC   5        __libc_csu_fini
48  0x00003000 0x00004000 WEAK   NOTYPE 0        data_start
50  ---------- 0x00004010 GLOBAL NOTYPE 0        _edata
52  0x000014b8 0x000014b8 GLOBAL FUNC   0        _fini
56  0x00003000 0x00004000 GLOBAL NOTYPE 0        __data_start
59  0x00003008 0x00004008 GLOBAL OBJ    0        __dso_handle
60  0x00002000 0x00002000 GLOBAL OBJ    4        _IO_stdin_used
62  0x00001440 0x00001440 GLOBAL FUNC   101      __libc_csu_init
64  ---------- 0x00004018 GLOBAL NOTYPE 0        _end
65  0x000011a0 0x000011a0 GLOBAL FUNC   47       _start
67  ---------- 0x00004010 GLOBAL NOTYPE 0        __bss_start
68  0x00001289 0x00001289 GLOBAL FUNC   437      main
71  ---------- 0x00004010 GLOBAL OBJ    0        __TMC_END__
1   ---------- ---------- WEAK   NOTYPE 0        imp._ITM_deregisterTMCloneTable
2   0x000010f0 0x000010f0 GLOBAL FUNC   16       imp.fread
3   0x00001100 0x00001100 GLOBAL FUNC   16       imp.fclose
4   0x00001110 0x00001110 GLOBAL FUNC   16       imp.__stack_chk_fail
5   ---------- ---------- GLOBAL FUNC   0        imp.__libc_start_main
6   0x00001120 0x00001120 GLOBAL FUNC   16       imp.srand
7   0x00001130 0x00001130 GLOBAL FUNC   16       imp.ftell
8   ---------- ---------- WEAK   NOTYPE 0        imp.__gmon_start__
9   0x00001140 0x00001140 GLOBAL FUNC   16       imp.time
10  0x00001150 0x00001150 GLOBAL FUNC   16       imp.malloc
11  0x00001160 0x00001160 GLOBAL FUNC   16       imp.fseek
12  0x00001170 0x00001170 GLOBAL FUNC   16       imp.fopen
13  0x00001180 0x00001180 GLOBAL FUNC   16       imp.fwrite
14  ---------- ---------- WEAK   NOTYPE 0        imp._ITM_registerTMCloneTable
15  0x00001190 0x00001190 GLOBAL FUNC   16       imp.rand
16  ---------- ---------- WEAK   FUNC   0        imp.__cxa_finalize
```

We notice a `main.c` entry, and some of the functions we discovered in the last section.

# Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z /workspace/encrypt
```

```
[Strings]
nth paddr      vaddr      len size section type  string   
----------------------------------------------------------
0   0x00002007 0x00002007 4   5    .rodata ascii flag
1   0x0000200f 0x0000200f 8   9    .rodata ascii flag.enc
```

There's only `2` strings.

The first one is `flag`, and the second is `flag.enc`. We already have a `flag.enc` file, but not a `flag` one. We can assume that the program reads the input of `flag` and outputs it to `flag.enc` in a somehow encrypted form.

# Execution

Let's execute this binary and see how it behaves.

```sh
❯ /workspace/encrypt
```

```
zsh: segmentation fault  /workspace/encrypt
```

Alright, there's not much to learn here.

# Decompilation

Now that we have an of idea of how this C program behaves and of what its dependencies are, let's decompile it and explore it using [Ghidra](https://github.com/NationalSecurityAgency/ghidra). I'm going to load `encrypt` with the default options, and I'll analyze it, once again with the default options.

As usual, I'll start by exploring the `main` function.

## `main`

Let's decompile this function.

```c,linenos
void main(void)
{
    int iVar1;
    time_t tVar2;
    long in_FS_OFFSET;
    uint local_40;
    uint local_3c;
    long local_38;
    FILE * local_30;
    size_t local_28;
    void * local_20;
    FILE * local_18;
    long local_10;

    local_10 = * (long * )(in_FS_OFFSET + 0x28);
    local_30 = fopen("flag", "rb");
    fseek(local_30, 0, 2);
    local_28 = ftell(local_30);
    fseek(local_30, 0, 0);
    local_20 = malloc(local_28);
    fread(local_20, local_28, 1, local_30);
    fclose(local_30);
    tVar2 = time((time_t * ) 0x0);
    local_40 = (uint) tVar2;
    srand(local_40);
    for (local_38 = 0; local_38 < (long) local_28; local_38 = local_38 + 1) {
        iVar1 = rand();
        *(byte * )((long) local_20 + local_38) = * (byte * )((long) local_20 + local_38) ^ (byte) iVar1;
        local_3c = rand();
        local_3c = local_3c & 7;
        *(byte * )((long) local_20 + local_38) = *
        (byte * )((long) local_20 + local_38) << (sbyte) local_3c |
            *
            (byte * )((long) local_20 + local_38) >> 8 - (sbyte) local_3c;
    }
    local_18 = fopen("flag.enc", "wb");
    fwrite( & local_40, 1, 4, local_18);
    fwrite(local_20, 1, local_28, local_18);
    fclose(local_18);
    if (local_10 != * (long * )(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
    return;
}
```

There's a few things going on here. Let's break down its most notable instructions.

### Reading unencrypted data

The line `16` opens a file named `flag` in read-only mode, as indicated by `rb`, and assigns the file pointer to the variable stream.

The lines `17` to `19` seek to the end of the file, determine the file size using `ftell`, and then rewind the file pointer to the beginning.

The lines `20` to `22` allocate memory dynamically using `malloc` to store the contents of the file. Then they read the entire content of the file into the allocated memory and close the file.

### Calculations

The line `23` initializes a `tVar2` variable to the current time.

The line `25` seeds the random number generator `srand` to the value of `tVar2`.

The line `28` XORs the byte at the current position with a random value.

The lines `31` to `34` shift the bits of the byte at the current position to the left by the value specified by `local_3c` and ORs it with the result of shifting the same bits to the right.

### Writing encrypted data

Finally, the lines `36` to `39` open a new file named `flag.enc` in write mode, as indicated by `wb`, write the 4-byte seed value followed by the encrypted data, and then close the file.

# Putting it all together

There's a few things involved in the encryption of the flag file, but since the seed value is saved in the encrypted file, we should be able to unencrypt it by applying the operations in the reverse order.

## Strategy

Here's what we have do to obtain the recover the flag file:

- Open `flag.enc`
- Read the first 4 bytes of the file to obtain the seed
- Read the rest of the file to obtain the encrypted data
- Reverse the encryption operations
- Write the data to `flag`

## Code

This is obviously very cumbersome to do by hand, so here's how we would write it in C (it was generated by ChatGPT and modified by me, I'm not familiar enough with C to write it all by myself):

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void decryptFile(const char *inputFileName, const char *outputFileName);

int main(void) {
    decryptFile("flag.enc", "flag");
    return 0;
}

void decryptFile(const char *inputFileName, const char *outputFileName) {

    // Open the input file
    FILE *inputFile = fopen(inputFileName, "rb");
    if (inputFile == NULL) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    // Read the seed value
    uint32_t seed;
    fread(&seed, sizeof(seed), 1, inputFile);
    printf("Seed: %u\n", seed);

    // Open the output file
    FILE *outputFile = fopen(outputFileName, "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    // Get the size of the encrypted data
    fseek(inputFile, 0, SEEK_END);
    long size = ftell(inputFile) - sizeof(seed);
    fseek(inputFile, sizeof(seed), SEEK_SET);

    // Allocate memory to store the encrypted data
    uint8_t *encryptedData = malloc(size);
    if (encryptedData == NULL) {
        perror("Memory allocation error");
        fclose(inputFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }

    // Read the encrypted data
    fread(encryptedData, size, 1, inputFile);
    fclose(inputFile);

    // Seed the random number generator with the decrypted seed
    srand(seed);

    // Decrypt the data
    for (long i = 0; i < size; i++) {
        uint8_t xorKey = rand();
        uint8_t rightShiftKey = rand() & 7;
        encryptedData[i] = encryptedData[i] >> rightShiftKey | encryptedData[i] << (8 - rightShiftKey);
        encryptedData[i] ^= xorKey;
    }

    // Write the decrypted data to the output file
    fwrite(encryptedData, size, 1, outputFile);

    // Clean up
    free(encryptedData);
    fclose(outputFile);
}
```

## Compilation

I'll save it as `decrypt.c` and compile it:

```sh
❯ gcc -o decrypt decrypt.c
```

## Testing

Now let's try the `decrypt` executable to see if it successfully decrypts the `flag.enc` file.

```sh
❯ /workspace/decrypt /workspace/flag.enc
```

```
Seed: 1655780698
```

So apparently the seed used to encrypt the file is `1655780698`. Let's check the contenf of `flag` to see if it was successfully decrypted:

```sh
❯ cat /workspace/flag
```

```
HTB{vRy_s1MplE_F1LE3nCryp0r}
```

It worked. Nice!

# Afterwords

![Success](success.png)

That's it for this challenge! I found it kinda easy, the hard part was writing the C code to reverse the enryption. As I mentioned in this write-up, I'm not familiar enough with C to write the full script myself, so I used ChatGPT. It generated a very good snippet, but it didn't quite work, it got the decryption operations wrong. I had to debug it a bit to get it to work. It was really interesting though!

Thanks for reading!

+++
title = "WIDE"
date = "2024-03-21"
description = "This is a very easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Reversing

**Release date**: 2022-05-27

**Created by**: [clubby789](https://app.hackthebox.com/users/83743)

**Description**: We've received reports that Draeger has stashed a huge arsenal
in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded
access terminal to the Widely Inflated Dimension Editor from his headquarters,
but the entry for the dimension has been encrypted. Can you make it inside and
take control?

# Setup

I'll complete this challenge using a Kali Linux VM. I'll create a `workspace`
directory at `/` to hold all the files related to this challenge, and the
commands ran on my machine will be prefixed with `❯` for clarity.

# Files

```sh
❯ tree -a "/workspace"
```

```
/workspace
└── rev_wide
    ├── db.ex
    └── wide

<SNIP>
```

This challenge is comprised of a file named `db.ex` and a file named `wide`.
There's no extension, so we can infer that it's meant to be run on Linux.

# Static analysis

Let's start by statically analyzing the `wide` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I "/workspace/rev_wide/wide"
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x00002b7b
bintype  elf
bits     64
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
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
canary   false
PIE      true
RELROCS  true
NX       true
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/rev_wide/wide"
```

```
[Libs]
library   
----------
libc.so.6
```

This binary uses the `libc.so.6` library, which provides the fundamental
functionalities for programs written in C.

## Imports

Now, let's find the list of objects imported by this binary.

```sh
❯ rz-bin -i "/workspace/rev_wide/wide"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x00000800 GLOBAL FUNC       wcscmp
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x00000810 GLOBAL FUNC       puts
4   0x00000820 GLOBAL FUNC       fread
5   0x00000830 GLOBAL FUNC       mbstowcs
6   0x00000840 GLOBAL FUNC       fclose
7   0x00000850 GLOBAL FUNC       printf
8   ---------- GLOBAL FUNC       __libc_start_main
9   0x00000860 GLOBAL FUNC       fgets
10  0x00000870 GLOBAL FUNC       calloc
11  0x00000880 GLOBAL FUNC       ftell
12  ---------- WEAK   NOTYPE     __gmon_start__
13  0x00000890 GLOBAL FUNC       strtol
14  0x000008a0 GLOBAL FUNC       fseek
15  0x000008b0 GLOBAL FUNC       fopen
16  0x000008c0 GLOBAL FUNC       exit
17  ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
18  0x000008d0 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `puts`, but also `fopen`, `fread` and
`fclose`, so we can expect to see text printed to the terminal and the binary
probably deals with files.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E "/workspace/rev_wide/wide"
```

```
[Exports]
nth paddr      vaddr      bind   type   size lib name               
--------------------------------------------------------------------
19  ---------- 0x00202010 GLOBAL OBJ    8        stdin
43  0x00001070 0x00001070 GLOBAL FUNC   2        __libc_csu_fini
49  ---------- 0x00202010 GLOBAL OBJ    8        stdin@@GLIBC_2.2.5
51  ---------- 0x00202010 GLOBAL NOTYPE 0        _edata
53  0x000009ea 0x000009ea GLOBAL FUNC   1016     menu
54  0x00001074 0x00001074 GLOBAL FUNC   0        _fini
59  0x00002000 0x00202000 GLOBAL NOTYPE 0        __data_start
63  0x00002008 0x00202008 GLOBAL OBJ    0        __dso_handle
64  0x00001080 0x00001080 GLOBAL OBJ    4        _IO_stdin_used
65  0x00001000 0x00001000 GLOBAL FUNC   101      __libc_csu_init
66  ---------- 0x00202020 GLOBAL NOTYPE 0        _end
67  0x000008e0 0x000008e0 GLOBAL FUNC   43       _start
69  ---------- 0x00202010 GLOBAL NOTYPE 0        __bss_start
70  0x00000de2 0x00000de2 GLOBAL FUNC   536      main
73  ---------- 0x00202010 GLOBAL OBJ    0        __TMC_END__
76  0x000007d0 0x000007d0 GLOBAL FUNC   0        _init
```

We notice the classic `main` function, but also `menu`.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/rev_wide/wide"
```

```
[Strings]
nth paddr      vaddr      len size section type    string                                                                       
--------------------------------------------------------------------------------------------------------------------------------
0   0x00001088 0x00001088 43  44   .rodata ascii   Which dimension would you like to examine? 
1   0x000010b4 0x000010b4 24  25   .rodata ascii   That option was invalid.
2   0x000010d0 0x000010d0 69  70   .rodata ascii   [X] That entry is encrypted - please enter your WIDE decryption key: 
3   0x00001118 0x00001118 15  64   .rodata utf32le sup3rs3cr3tw1d3
4   0x00001158 0x00001158 76  77   .rodata ascii   [X]                          Key was incorrect                           [X]
5   0x000011a5 0x000011a5 16  17   .rodata ascii   Usage: %s db.ex\n
6   0x000011b8 0x000011b8 76  77   .rodata ascii   [*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
7   0x00001208 0x00001208 76  77   .rodata ascii   [*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
8   0x00001258 0x00001258 51  52   .rodata ascii   [x] There was a problem accessing your database [x]
9   0x00001290 0x00001290 76  77   .rodata ascii   [*]                       Displaying Dimensions....                      [*]
10  0x000012e0 0x000012e0 76  77   .rodata ascii   [*]       Name       |              Code                |   Encrypted    [*]
11  0x00001330 0x00001330 33  34   .rodata ascii   [X] %-16s | %-32s | %6s%c%7s [*]\n
```

According to these strings, we're given the possibility of selecting a dimension
to examine, but we require a key to do so. The `sup3rs3cr3tw1d3` string would
make a great key...

There's also a string indicating that the binary expects a `db.ex` file to run.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/rev_wide/wide" "/workspace/rev_wide/db.ex"
```

```
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine?
```

We're asked to enter a dimension to examine. I can enter numbers from `0` to `6`
to specify the dimension.

The most interesting is the seventh, which is encrypted with a key.

```
[X] That entry is encrypted - please enter your WIDE decryption key:
```

I'm pretty sure this corresponds to the `sup3rs3cr3tw1d3` string in the
[Strings section](#strings), but I won't go further yet. If we enter a wrong
input, we get the message `Key was incorrect`.

# Static analysis

## Decompilation

I'll load `wide` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int32_t main(int32_t argc, char **argv, char **envp) {
    if (argc <= 1) {
        printf("Usage: %s db.ex\n", *(uint64_t *)argv);
        exit(EXIT_FAILURE);
    }
    puts("[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension "
         "Editor [*]");
    puts("[*]    Serving your pocket dimension storage needs since 14,012.5 B  "
         "  "
         "  [*]");
    FILE *fp = fopen(argv[1], "r");
    if (fp == 0) {
        puts("[x] There was a problem accessing your database [x]");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    int64_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint32_t dimensionCount =
        ((int32_t)(((fileSize * 0) + ((fileSize / 180) * 180)) / 180));
    void *dimensionData = calloc(((int64_t)dimensionCount), 180);
    fread(dimensionData, 180, ((int64_t)dimensionCount), fp);
    fclose(fp);
    puts("[*]                       Displaying Dimensions....                  "
         "  "
         "  [*]");
    puts("[*]       Name       |              Code                |   "
         "Encrypted  "
         "  [*]");
    for (int32_t i = 0; i < dimensionCount; i = (i + 1)) {
        int32_t encryptionIndicator;
        if (*(uint32_t *)((char *)dimensionData + (((int64_t)i) * 180)) == 0) {
            encryptionIndicator = ' ';
        } else {
            encryptionIndicator = '*';
        }
        printf("[X] %-16s | %-32s | %6s%c%7s [*]\n",
               (((char *)dimensionData + (((int64_t)i) * 180)) + 4),
               (((char *)dimensionData + (((int64_t)i) * 180)) + 0x14),
               "\x00\x00\x00", ((uint64_t)encryptionIndicator), "\x00\x00\x00",
               argv);
    }
    menu(dimensionData, dimensionCount);
}
```

This function reads the database passed as a parameter, and displays the
dimensions contained in the database. It then calls the `menu` function with the
`dimensionData` and the `dimensionCount`.

### `menu`

```c
void menu(void *dimensionData, int32_t dimensionCount) {
    int64_t inputDimension;
    __builtin_memset(&inputDimension, 0, 32);
    while (true) {
        printf("Which dimension would you like to examine? ");
        fgets(&inputDimension, 32, __TMC_END__);
        int32_t selectedDimension = strtol(&inputDimension, NULL, 10);
        if ((selectedDimension >= 0 && selectedDimension < dimensionCount)) {
            int64_t *selectedDimensionData =
                ((char *)dimensionData + (((int64_t)selectedDimension) * 180));
            int32_t dataType = ((int32_t) * (uint64_t *)selectedDimensionData);
            int64_t encryptedString = selectedDimensionData[6];
            if (dataType == 0) {
                puts(&*(uint64_t *)((char *)encryptedString)[4]);
                continue;
            } else {
                int64_t decryptedString = encryptedString;
                printf("[X] That entry is encrypted - please enter your WIDE "
                       "decryption key: ");
                void inputKey;
                fgets(&inputKey, 16, __TMC_END__);
                void wideInputKey;
                mbstowcs(&wideInputKey, &inputKey, 16);
                if (wcscmp(&wideInputKey, U"sup3rs3cr3tw1d3") != 0) {
                    puts("[X]                          Key was incorrect       "
                         "          "
                         "          [X]");
                    continue;
                } else {
                    for (int32_t i = 0; i <= 127; i = (i + 1)) {
                        if (*(uint8_t *)(&decryptedString + ((int64_t)i)) ==
                            0) {
                            break;
                        }
                        uint64_t temp = ((uint64_t)(i * 3));
                        int32_t shiftedValue = (((int32_t)(temp << 3)) + temp);
                        int32_t divisor = (shiftedValue / 0xff);
                        *(uint8_t *)(&decryptedString + ((int64_t)i)) =
                            (*(uint8_t *)(&decryptedString + ((int64_t)i)) ^
                             (shiftedValue -
                              (((int8_t)(divisor << 8)) - divisor)));
                    }
                    puts(&decryptedString);
                    continue;
                }
            }
        }
        puts("That option was invalid.");
    }
}
```

This function reads the user input corresponding to the selected dimension. If
it's valid, the function checks if it's associated to an encrypted dimension,
and if it is it asks for a key. If this key is `sup3rs3cr3tw1d3`, it performs a
bunch of calculations on the dimension data and prints the result to the
terminal.

# Putting it all together

To access the encrypted dimension content, we need to input the
`sup3rs3cr3tw1d3` key.

If we run the binary once again and input this key, we get the flag `HTB{som3_str1ng5_4r3_w1d3}`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Piece of cake'. The decompiled code was really close
to the reality, and it was easy to understand. It wasn't even necessary to
decompile this binary, we could just read the strings and guess the key.

Thanks for reading!

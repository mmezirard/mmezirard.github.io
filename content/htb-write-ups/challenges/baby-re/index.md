+++
title = "Baby RE"
date = "2024-03-21"
description = "This is an easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Easy

**Category**: Reversing

**Release date**: 2019-10-25

**Created by**: [Xh4H](https://app.hackthebox.com/users/21439)

**Description**: Show us your basic skills! (P.S. There are 4 ways to solve
this, are you willing to try them all?)

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
└── baby

<SNIP>
```

This challenge is comprised of a single file named `baby`. There's no
extension, so we can infer that it's meant to be run on Linux.

# Static analysis

Let's start by statically analyzing the `baby` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I "/workspace/baby"
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x000039f3
bintype  elf
bits     64
class    ELF64
compiler GCC: (Debian 9.2.1-8) 9.2.1 20190909
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
relro    partial
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
❯ rz-bin -l "/workspace/baby"
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
❯ rz-bin -i "/workspace/baby"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
2   0x00001030 GLOBAL FUNC       puts
3   ---------- GLOBAL FUNC       __libc_start_main
4   0x00001040 GLOBAL FUNC       fgets
5   0x00001050 GLOBAL FUNC       strcmp
6   ---------- WEAK   NOTYPE     __gmon_start__
7   ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
8   0x00001060 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `puts`, but also `fgets`, so we can expect to
see text printed to the terminal and to be asked for input.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E "/workspace/baby"
```

```
[Exports]
nth paddr      vaddr      bind   type   size lib name               
--------------------------------------------------------------------
9   ---------- 0x00004040 GLOBAL OBJ    8        stdin
45  0x00001250 0x00001250 GLOBAL FUNC   1        __libc_csu_fini
49  ---------- 0x00004040 GLOBAL OBJ    8        stdin@@GLIBC_2.2.5
50  ---------- 0x00004040 GLOBAL NOTYPE 0        _edata
51  0x00001254 0x00001254 GLOBAL FUNC   0        _fini
54  0x00003030 0x00004030 GLOBAL NOTYPE 0        __data_start
57  0x00003038 0x00004038 GLOBAL OBJ    0        __dso_handle
58  0x00002000 0x00002000 GLOBAL OBJ    4        _IO_stdin_used
59  0x000011f0 0x000011f0 GLOBAL FUNC   93       __libc_csu_init
60  ---------- 0x00004050 GLOBAL NOTYPE 0        _end
61  0x00001070 0x00001070 GLOBAL FUNC   43       _start
62  ---------- 0x00004040 GLOBAL NOTYPE 0        __bss_start
63  0x00001155 0x00001155 GLOBAL FUNC   152      main
64  ---------- 0x00004040 GLOBAL OBJ    0        __TMC_END__
```

We notice the classic `main` function.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/baby"
```

```
[Strings]
nth paddr      vaddr      len size section type  string                                                        
---------------------------------------------------------------------------------------------------------------
0   0x00002008 0x00002008 61  62   .rodata ascii Dont run `strings` on this challenge, that is not the way!!!!
1   0x00002046 0x00002046 12  13   .rodata ascii Insert key: 
2   0x00002053 0x00002053 12  13   .rodata ascii abcde122313\n
3   0x00002060 0x00002060 16  17   .rodata ascii Try again later.
```

According to these strings, we're asked to enter a key. The `abcde122313` string
would make a great one!

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/baby"
```

```
Insert key:
```

We're asked for a key. I'm pretty sure this corresponds to the `abcde122313`
string in the [Strings section](#strings), but I won't go further yet. If we
enter a wrong input, we get the message `Try again later`.

# Static analysis

## Decompilation

I'll load `baby` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {
    char input[20];
    puts("Insert key: ");
    fgets(input, sizeof(input), stdin);

    if (strcmp(input, "abcde122313\n") != 0) {
        puts("Try again later.");
    } else {
        char password[22];
        strncpy(password, "HTB{B4BY_R3V_TH4TS_EZ}", sizeof(password));
        puts(password);
    }

    return 0;
}
```

This program asks the user to enter a key. If the input is equal to
`abcde122313`, the string `HTB{B4BY_R3V_TH4TS_EZ}` is printed in the terminal.

# Putting everything together

A reverse engineering challenge couldn't be easier. The flag is clearly written
in the code.

If we run the binary once again and input the `abcde122313` string, we indeed
see the `HTB{B4BY_R3V_TH4TS_EZ}` flag printed to the terminal.

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Piece of cake'. The decompiled code was minimal, and
extremely easy to understand.

Thanks for reading!

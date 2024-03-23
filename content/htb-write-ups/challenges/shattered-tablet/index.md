+++
title = "Shattered Tablet"
date = "2024-03-23"
description = "This is a very easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Reversing

**Release date**: 2023-04-28

**Created by**: [clubby789](https://app.hackthebox.com/users/83743)

**Description**: Deep in an ancient tomb, you've discovered a stone tablet with
secret information on the locations of other relics. However, while dodging a
poison dart, it slipped from your hands and shattered into hundreds of pieces.
Can you reassemble it and read the clues?

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
└── rev_shattered_tablet
    └── tablet

<SNIP>
```

This challenge is comprised of a single file named `tablet`. There's no
extension, so we can infer that it's meant to be run on Linux.

# Static analysis

Let's start by statically analyzing the `tablet` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I "/workspace/rev_shattered_tablet/tablet"
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x000039ec
bintype  elf
bits     64
class    ELF64
compiler GCC: (Debian 10.2.1-6) 10.2.1 20210110
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
❯ rz-bin -l "/workspace/rev_shattered_tablet/tablet"
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
❯ rz-bin -i "/workspace/rev_shattered_tablet/tablet"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
2   0x00001030 GLOBAL FUNC       puts
3   0x00001040 GLOBAL FUNC       printf
4   ---------- GLOBAL FUNC       __libc_start_main
5   0x00001050 GLOBAL FUNC       fgets
6   ---------- WEAK   NOTYPE     __gmon_start__
7   ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
8   0x00001060 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `puts`, but also `fgets`, so we can expect to
see text printed to the terminal and to be asked for input.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E "/workspace/rev_shattered_tablet/tablet"
```

```
[Exports]
nth paddr      vaddr      bind   type   size lib name              
-------------------------------------------------------------------
9   ---------- 0x00004040 GLOBAL OBJ    8        stdin
45  0x000013f0 0x000013f0 GLOBAL FUNC   1        __libc_csu_fini
49  ---------- 0x00004040 GLOBAL OBJ    8        stdin@GLIBC_2.2.5
50  ---------- 0x00004040 GLOBAL NOTYPE 0        _edata
51  0x000013f4 0x000013f4 GLOBAL FUNC   0        _fini
55  0x00003030 0x00004030 GLOBAL NOTYPE 0        __data_start
57  0x00003038 0x00004038 GLOBAL OBJ    0        __dso_handle
58  0x00002000 0x00002000 GLOBAL OBJ    4        _IO_stdin_used
59  0x00001390 0x00001390 GLOBAL FUNC   93       __libc_csu_init
60  ---------- 0x00004050 GLOBAL NOTYPE 0        _end
61  0x00001070 0x00001070 GLOBAL FUNC   43       _start
62  ---------- 0x00004040 GLOBAL NOTYPE 0        __bss_start
63  0x00001155 0x00001155 GLOBAL FUNC   566      main
64  ---------- 0x00004040 GLOBAL OBJ    0        __TMC_END__
```

We notice the classic `main` function.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/rev_shattered_tablet/tablet"
```

```
[Strings]
nth paddr      vaddr      len size section type  string                             
------------------------------------------------------------------------------------
0   0x00002008 0x00002008 34  35   .rodata ascii Hmmmm... I think the tablet says: 
1   0x0000202b 0x0000202b 18  19   .rodata ascii Yes! That's right!
2   0x0000203e 0x0000203e 14  15   .rodata ascii No... not that
```

We find a few mysterious strings.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/rev_shattered_tablet/tablet"
```

```
Hmmmm... I think the tablet says:
```

We're asked to enter what the tablet says. I don't know what it's supposed to
say though, so I'll just enter something random:

```
Hmmmm... I think the tablet says: hello?
No... not that
```

# Static analysis

## Decompilation

I'll load `tablet` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {
    char input[64];
    memset(input, 0, sizeof(input));
    printf("Hmmmm... I think the tablet says…");
    fgets(input, sizeof(input), stdin);

    if (input[0] != 'H' || input[1] != 'T' || input[2] != 'B' ||
        input[3] != '{' || input[4] != 'b' || input[5] != 'r' ||
        input[6] != '0' || input[7] != 'k' || input[8] != '3' ||
        input[9] != 'n' || input[10] != '_' || input[11] != '4' ||
        input[12] != 'p' || input[13] != '4' || input[14] != 'r' ||
        input[15] != 't' || input[16] != '.' || input[17] != '.' ||
        input[18] != '.' || input[19] != 'n' || input[20] != '3' ||
        input[21] != 'v' || input[22] != 'e' || input[23] != 'r' ||
        input[24] != '_' || input[25] != 't' || input[26] != '0' ||
        input[27] != '_' || input[28] != 'b' || input[29] != '3' ||
        input[30] != '_' || input[31] != 'r' || input[32] != '3' ||
        input[33] != 'p' || input[34] != '4' || input[35] != '1' ||
        input[36] != 'r' || input[37] != '3' || input[38] != 'd' ||
        input[39] != '}') {
        puts("No... not that");
    } else {
        puts("Yes! That's right!");
    }

    return 0;
}
```

HTB{br0k3n_4p4rt...n3ver_t0_b3_r3p41r3d}

# Putting it all together

The user input is compared against many indivual characters.

If we concatenate all these characters, we obtain the flag
`HTB{br0k3n_4p4rt...n3ver_t0_b3_r3p41r3d}`!

If we run the binary once again and input this string, we get the message
`Yes! That's right!`, which confirms that this is the flag.

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Very easy'. The decompiled code was really close to
the reality, and it was easy to understand. It was just annoying to sort the
comparisons in the correct order and to find the characters corresponding to the
hexadecimal values.

Thanks for reading!

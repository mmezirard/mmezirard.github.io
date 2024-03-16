+++
title = "Ouija"
date = "2024-03-14"
description = "This is an easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Easy

**Category**: Reversing

**Release date**: 2022-11-04

**Created by**: [clubby789](https://app.hackthebox.com/users/83743)

**Description**: You've made contact with a spirit from beyond the grave!
Unfortunately, they speak in an ancient tongue of flags, so you can't understand
a word. You've enlisted a medium who can translate it, but they like to take
their time...

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
└── rev_ouija
    └── ouija

<SNIP>
```

This challenge is comprised of a single file named `ouija`. There's no
extension, so we can infer that it's meant to be run on Linux.

# Static analysis

Let's start by statically analyzing the `ouija` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I /workspace/rev_ouija/ouija
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x00003aaa
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

We also notice that there are a few protections in place. This is not a binary
exploitation challenge, but it's still interesting to know.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l /workspace/rev_ouija/ouija
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
❯ rz-bin -i /workspace/rev_ouija/ouija
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x00001030 GLOBAL FUNC       putchar
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x00001040 GLOBAL FUNC       puts
4   0x00001050 GLOBAL FUNC       printf
5   ---------- GLOBAL FUNC       __libc_start_main
6   ---------- WEAK   NOTYPE     __gmon_start__
7   0x00001060 GLOBAL FUNC       setvbuf
8   ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
9   0x00001070 GLOBAL FUNC       strdup
10  0x00001080 GLOBAL FUNC       sleep
12  0x00001090 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `putchar`, `puts` and `printf`, but also
`sleep`, so we can expect to see text printed to the terminal and waiting times.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E /workspace/rev_ouija/ouija
```

```
[Exports]
nth paddr      vaddr      bind   type   size lib name               
--------------------------------------------------------------------
11  ---------- 0x00004060 GLOBAL OBJ    8        stdout
45  0x00001910 0x00001910 GLOBAL FUNC   1        __libc_csu_fini
48  ---------- 0x00004060 GLOBAL OBJ    8        stdout@GLIBC_2.2.5
51  ---------- 0x0000405c GLOBAL NOTYPE 0        _edata
52  0x00003058 0x00004058 GLOBAL OBJ    4        key
53  0x00001914 0x00001914 GLOBAL FUNC   0        _fini
56  0x00003048 0x00004048 GLOBAL NOTYPE 0        __data_start
58  0x00003050 0x00004050 GLOBAL OBJ    0        __dso_handle
59  0x00002000 0x00002000 GLOBAL OBJ    4        _IO_stdin_used
60  0x000018b0 0x000018b0 GLOBAL FUNC   93       __libc_csu_init
61  ---------- 0x00004070 GLOBAL NOTYPE 0        _end
62  0x000010a0 0x000010a0 GLOBAL FUNC   43       _start
63  ---------- 0x0000405c GLOBAL NOTYPE 0        __bss_start
64  0x00001185 0x00001185 GLOBAL FUNC   1828     main
66  ---------- 0x00004060 GLOBAL OBJ    0        __TMC_END__
```

We notice a `main` function, and a `key` object.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z /workspace/rev_ouija/ouija
```

```
[Strings]
nth paddr      vaddr      len size section type  string                                                                                                      
-------------------------------------------------------------------------------------------------------------------------------------------------------------
0   0x00002008 0x00002008 15  16   .rodata ascii Retrieving key.
1   0x00002018 0x00002018 6   7    .rodata ascii \r     
2   0x0000201f 0x0000201f 6   7    .rodata ascii  done!
3   0x00002028 0x00002028 49  50   .rodata ascii Hmm, I don't like that one. Let's pick a new one.
4   0x0000205a 0x0000205a 23  24   .rodata ascii Yes, 18 will do nicely.
5   0x00002078 0x00002078 50  51   .rodata ascii Let's get ready to start. This might take a while!
6   0x000020ab 0x000020ab 29  30   .rodata ascii This one's a lowercase letter
7   0x000020c9 0x000020c9 20  21   .rodata ascii Wrapping it round...
8   0x000020e0 0x000020e0 31  32   .rodata ascii This one's an uppercase letter!
9   0x00002100 0x00002100 28  29   .rodata ascii We can leave this one alone.
10  0x00002120 0x00002120 107 108  .rodata ascii Okay, let's write down this letter! This is a pretty complex operation, you might want to check back later.
11  0x00002190 0x00002190 18  19   .rodata ascii You're still here?
```

I don't see anything noteworthy.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ /workspace/rev_ouija/ouija
```

```
Retrieving key.
     ..... done!
Hmm, I don't like that one. Let's pick a new one.
     ..... done!
Yes, 18 will do nicely.
     ..... done!
Let's get ready to start. This might take a while!
     ..... done!
This one's an uppercase letter!
     ..... done!
Okay, let's write down this letter! This is a pretty complex operation, you might want to check back later.
     ..... done!
H
This one's an uppercase letter!
<SNIP>
```

This program takes forever! There's a massive amount of waiting time between the
outputs, but it does eventually give out letters one by one.

This must be the medium in question in the challenge's description! He indeed
likes to take his time... Although he does find valid letters. We could just
wait until he finishes to get the flag, but this would be extremely uneffective,
and in truth really boring.

# Static analysis

## Decompilation

I'll load `ouija` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c,linenos
int32_t main(int32_t argc, char **argv, char **envp) {
    int64_t s;
    __builtin_memset(&s, 0, 0x1f);
    __builtin_strncpy(&s, "ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}", 0x1f);
    setvbuf(__TMC_END__, nullptr, 2, 0);
    char *rax = strdup(&s);
    puts("Retrieving key.");
    sleep(0xa);
    for (int32_t i = 1; i <= 0x1d; i = (i + 1)) {
        if ((i % 5) == 0) {
            printf("\r     ");
        }
        putchar(0x2e);
        sleep(1);
    }
    puts(" done!");
    uint32_t key_1 = key;
    puts("Hmm, I don't like that one. Let's pick a new one.");
    sleep(0xa);
    for (int32_t i_1 = 1; i_1 <= 0x1d; i_1 = (i_1 + 1)) {
        if ((i_1 % 5) == 0) {
            printf("\r     ");
        }
        putchar(0x2e);
        sleep(1);
    }
    puts(" done!");
    int32_t var_4c_1 = (key_1 + 5);
    puts("Yes, 18 will do nicely.");
    sleep(0xa);
    for (int32_t i_2 = 1; i_2 <= 0x13; i_2 = (i_2 + 1)) {
        if ((i_2 % 5) == 0) {
            printf("\r     ");
        }
        putchar(0x2e);
        sleep(1);
    }
    puts(" done!");
    char *var_20 = rax;
    puts("Let's get ready to start. This might take a while!");
    sleep(0xa);
    for (int32_t i_3 = 1; i_3 <= 0x31; i_3 = (i_3 + 1)) {
        if ((i_3 % 5) == 0) {
            printf("\r     ");
        }
        putchar(0x2e);
        sleep(1);
    }
    puts(" done!");
    while (*(uint8_t *)var_20 != 0) {
        if ((*(uint8_t *)var_20 > 0x60 && *(uint8_t *)var_20 <= 0x7a)) {
            puts("This one's a lowercase letter");
            sleep(0xa);
            for (int32_t i_4 = 1; i_4 <= 0x13; i_4 = (i_4 + 1)) {
                if ((i_4 % 5) == 0) {
                    printf("\r     ");
                }
                putchar(0x2e);
                sleep(1);
            }
            puts(" done!");
            if ((((int32_t) * (uint8_t *)var_20) - var_4c_1) <= 0x60) {
                puts("Wrapping it round...");
                sleep(0xa);
                for (int32_t i_5 = 1; i_5 <= 0x31; i_5 = (i_5 + 1)) {
                    if ((i_5 % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar(0x2e);
                    sleep(1);
                }
                puts(" done!");
                *(uint8_t *)var_20 = (*(uint8_t *)var_20 + 0x1a);
            }
            *(uint8_t *)var_20 = (*(uint8_t *)var_20 - var_4c_1);
        }
        if ((*(uint8_t *)var_20 <= 0x60 ||
             (*(uint8_t *)var_20 > 0x60 && *(uint8_t *)var_20 > 0x7a))) {
            if ((*(uint8_t *)var_20 <= 0x40 ||
                 (*(uint8_t *)var_20 > 0x40 && *(uint8_t *)var_20 > 0x5a))) {
                puts("We can leave this one alone.");
                sleep(0xa);
                for (int32_t i_6 = 1; i_6 <= 9; i_6 = (i_6 + 1)) {
                    if ((i_6 % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar(0x2e);
                    sleep(1);
                }
                puts(" done!");
            }
            if ((*(uint8_t *)var_20 > 0x40 && *(uint8_t *)var_20 <= 0x5a)) {
                puts("This one's an uppercase letter!");
                sleep(0xa);
                for (int32_t i_7 = 1; i_7 <= 0x13; i_7 = (i_7 + 1)) {
                    if ((i_7 % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar(0x2e);
                    sleep(1);
                }
                puts(" done!");
                if ((((int32_t) * (uint8_t *)var_20) - var_4c_1) <= 0x40) {
                    puts("Wrapping it round...");
                    sleep(0xa);
                    for (int32_t i_8 = 1; i_8 <= 0x31; i_8 = (i_8 + 1)) {
                        if ((i_8 % 5) == 0) {
                            printf("\r     ");
                        }
                        putchar(0x2e);
                        sleep(1);
                    }
                    puts(" done!");
                    *(uint8_t *)var_20 = (*(uint8_t *)var_20 + 0x1a);
                }
                *(uint8_t *)var_20 = (*(uint8_t *)var_20 - var_4c_1);
            }
        }
        puts("Okay, let's write down this letter! This is a pretty complex "
             "operation, you might want to check back later.");
        sleep(0xa);
        for (int32_t i_9 = 1; i_9 <= 0x12b; i_9 = (i_9 + 1)) {
            if ((i_9 % 5) == 0) {
                printf("\r     ");
            }
            putchar(0x2e);
            sleep(1);
        }
        puts(" done!");
        printf(&data_218c, ((uint64_t)((int32_t) * (uint8_t *)var_20)));
        var_20 = &var_20[1];
    }
    puts("You're still here?");
    return 0;
}
```

There's a lot going on, so let's break down the major instructions of this
function step by step.

#### Preparation

The lines `2` to `4` declare a variable `s`, initialize `s` with zeroes, and
copy the string `ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}` (probably the encrypted flag)
into the memory location pointed to by `s`. The copy operation is limited to
copying `0x1f` (31) bytes, but the string is 28 characters long, meaning that
there will be three zeroes at the end of `s`, so the string will be correctly
terminated.

The line `6` duplicates the string pointed to by `s` using the `strdup` function
and stores the result in the variable `rax`, meaning that this variable now
points to the beginning of the encrypted flag.

The lines `8` to `16` are just artificial waiting times and print dots `.` to
simulate that something is happening. This is actually something that will come
up really often in this program to slow it up. Therefore, we can ignore these
parts, as there's no consequential logic behind.

The line `17` creates a `key_1` variable and sets it to the value of `key`,
which is `0xd` (13).

The line `28` creates a `var_4c_1` variable and sets it to the value of
`key_1 + 5`, which is `0x12` (18).

Then, the line `39` creates a `var_20` variable pointing to `rax`, meaning that
the `var_20` variable now also points to the beginning of the encrypted flag.

#### Calculations

The lines `50` to `132` are repeated while the `var_20` is different than a
zero. Since this variable points to a character of the endoded string flag, and
since C strings end with zeroes, these lines will be repeated until `var_20`
reaches the end of the string. Note that `var_20` is incremented at the line
`131`, so there's no infinite loop.

There's three branches at this point:

- From line `51` to line `76`, if `var_20` is between `0x61` (a) and `0x7a` (z),
  so if the `var_20` points to a lowercase character, the value of `var_4c_1`
  (which is `18`) is substracted to this character. Note that this character is
  increased by `0x1a` (26) if it becomes smaller than `a`, so it's essentially
  wrapped so that it stays a lowercase character.

- From line `92` to line `117`, if `var_20` is between `0x41` (A) and `0x5a`
  (Z), so if the `var_20` points to an uppercase character, the exact same logic
  applies.

- From line `79` to line `91`, if `var_20` is not a letter, it doesn't change.

# Putting it all together

From what we could understand, this program iterates over each character of the
hardcoded string `ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}`. If the character is a
letter, whether uppercase or lowercase, its value is decreased by `18`, and this
character is wrapped to stay a lowercase or uppercase character.

This is an example of a Caesar cypher with a left shift of `18`. This means that
the flag has been encrypted with the ROT18 algorithm.

Therefore, we simply have to apply the ROT8 algorithm on the encrypted flag to
decrypt it!

I'll run this Python script for this:

```py
# Define the string containing the encrypted flag
FLAG = "ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}"

# Function to apply the ROT8 algorithm
def rot8(text):
    result = ""
    for char in text:
        # Check if the character is alphabetic
        if char.isalpha():
            # Check if the character is lowercase
            if char.islower():
                # Apply rotation for lowercase letters
                result += chr(((ord(char) - ord('a') + 8) % 26) + ord('a'))
            else:
                # Apply rotation for uppercase letters
                result += chr(((ord(char) - ord('A') + 8) % 26) + ord('A'))
        else:
            # If the character is not alphabetic, keep it unchanged
            result += char
    return result

# Decode the encoded flag using the rot8 function and print the result
print(rot8(FLAG))
```

We get the `HTB{Sleping_is_not_obfuscation}` flag!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Very easy'. The decompiled code was really close to
the reality, and it was easy to decipher.

Thanks for reading!

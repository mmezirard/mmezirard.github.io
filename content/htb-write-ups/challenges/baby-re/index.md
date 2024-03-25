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

This challenge is comprised of a single file named `baby`.

# Static analysis

Let's start by statically analyzing the `baby` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ file "/workspace/baby"
```

```
baby: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=25adc53b89f781335a27bf1b81f5c4cb74581022, for GNU/Linux 3.2.0, not stripped
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

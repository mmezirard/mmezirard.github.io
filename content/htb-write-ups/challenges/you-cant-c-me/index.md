+++
title = "You Cant C Me"
date = "2024-03-21"
description = "This is an easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Easy

**Category**: Reversing

**Release date**: 2021-04-12

**Created by**: [MinatoTW](https://app.hackthebox.com/users/8308)

**Description**: Can you see me?

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
└── auth

<SNIP>
```

This challenge is comprised of a single file named `auth`.

# Static analysis

Let's start by statically analyzing the `auth` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ file "/workspace/auth"
```

```
auth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/auth"
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
❯ rz-bin -i "/workspace/auth"
```

```
[Imports]
nth vaddr      bind   type   lib name              
---------------------------------------------------
1   0x00401030 GLOBAL FUNC       printf
2   ---------- GLOBAL FUNC       __libc_start_main
3   0x00401040 GLOBAL FUNC       fgets
4   0x00401050 GLOBAL FUNC       strcmp
5   ---------- WEAK   NOTYPE     __gmon_start__
6   0x00401060 GLOBAL FUNC       malloc
```

This binary imports functions like `printf`, but also `fgets`, so we can expect
to see text printed to the terminal and to be asked for input.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/auth"
```

```
[Strings]
nth paddr      vaddr      len size section type  string                    
---------------------------------------------------------------------------
0   0x00002004 0x00402004 9   10   .rodata ascii Welcome!\n
1   0x0000200e 0x0040200e 24  25   .rodata ascii I said, you can't c me!\n
2   0x00002027 0x00402027 8   9    .rodata ascii HTB{%s}\n
3   0x00002030 0x00402030 20  21   .rodata ascii this_is_the_password
4   0x00002050 0x00402050 6   7    .rodata ascii m^&&fi
5   0x00002057 0x00402057 13  13   .rodata ascii Uo&kUZ'ZUYUc)
```

The `HTB{%s}\n` string is likely formated with another string to form the flag.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/auth"
```

```
Welcome!
```

The program waits for user input. I'll enter something random.

```
hello?
I said, you can't c me!
```

# Static analysis

## Decompilation

I'll load `auth` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {
    printf("Welcome!\n");

    char password[21];
    const char *real_password = "\x6d\x5e\x26\x26\x66\x69\x15\x55\x6f\x26\x6b"
                                "\x55\x5a\x27\x5a\x55\x59\x55\x63\x29";

    for (int i = 0; i < 20; i++) {
        password[i] = real_password[i] + 10;
    }

    char *input = malloc(21);
    fgets(input, 21, stdin);

    if (strcmp(password, input) == 0) {
        printf("HTB{%s}\n", input);
    } else {
        printf("I said, you can't c me!\n");
    }

    free(input);

    return 0;
}
```

This function iterates over each character of the `real_password`, adds `10` to
it, and assigns the result to the corresponding character of the `password`.

# Putting it all together

This program shifts each character of the
`\x6d\x5e\x26\x26\x66\x69\x15\x55\x6f\x26\x6b\x55\x5a\x27\x5a\x55\x59\x55\x63\x29`
string by `10`.

Therefore, we simply have to shift each character to obtain the valid password!

I'll run this Python script for this:

```py
# Define the password bytes as a list
PASSWORD = [
    0x6d,
    0x5e,
    0x26,
    0x26,
    0x66,
    0x69,
    0x15,
    0x55,
    0x6f,
    0x26,
    0x6b,
    0x55,
    0x5a,
    0x27,
    0x5a,
    0x55,
    0x59,
    0x55,
    0x63,
    0x29,
]

# Initialize an empty string to store the shifted characters
result = ""

# Iterate over each byte in the password
for char in PASSWORD:
    # Shift the byte by 10 (using modulo 256 to ensure it stays within byte range)
    shifted_value = (char + 10) % 256
    # Convert the shifted byte value to a character and append it to the result string
    result += chr(shifted_value)

# Print the result as a string
print(result)
```

We get the `wh00ps!_y0u_d1d_c_m3` string.

If we run the binary once again and input this string, the program prints the
flag `HTB{wh00ps!_y0u_d1d_c_m3}`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Very easy'. The decompiled code was really close to
the reality, and it was quite easy to decipher, although finding the exact
operations performed by the program was a bit troublesome.

Thanks for reading!

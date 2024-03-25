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

This challenge is comprised of a single file named `ouija`.

# Static analysis

Let's start by statically analyzing the `ouija` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ file "/workspace/rev_ouija/ouija"
```

```
ouija: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=53a9e0435f7c7041c557e9d4a8418cb6a916f339, for GNU/Linux 3.2.0, not stripped
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/rev_ouija/ouija"
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
❯ rz-bin -i "/workspace/rev_ouija/ouija"
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

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/rev_ouija/ouija"
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

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/rev_ouija/ouija"
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

```c
int main(int argc, char **argv, char **envp) {
    char ciphertext[31];
    memset(ciphertext, 0, sizeof(ciphertext));
    strncpy(ciphertext, "ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}", sizeof(ciphertext));
    setvbuf(stdout, NULL, _IONBF, 0);
    char *plaintext = strdup(ciphertext);

    puts("Retrieving key.");
    sleep(10);
    for (int i = 1; i <= 29; i++) {
        if ((i % 5) == 0) {
            printf("\r     ");
        }
        putchar('.');
        sleep(10);
    }
    puts(" done!");

    unsigned int key = 13;

    puts("Hmm, I don't like that one. Let's pick a new one.");
    sleep(10);
    for (int i = 1; i <= 29; i++) {
        if ((i % 5) == 0) {
            printf("\r     ");
        }
        putchar('.');
        sleep(10);
    }
    puts(" done!");

    int shift = key + 5;

    puts("Yes, 18 will do nicely.");
    sleep(10);

    for (int i = 1; i <= 19; i++) {
        if ((i % 5) == 0) {
            printf("\r     ");
        }
        putchar('.');
        sleep(10);
    }
    puts(" done!");

    char *current_char = plaintext;

    puts("Let's get ready to start. This might take a while!");
    sleep(10);
    for (int i = 1; i <= 49; i++) {
        if ((i % 5) == 0) {
            printf("\r     ");
        }
        putchar('.');
        sleep(10);
    }
    puts(" done!");

    while (*current_char != 0) {
        if ((*current_char >= 'a' && *current_char <= 'z')) {
            puts("This one's a lowercase letter");
            sleep(10);
            for (int i = 1; i <= 19; i++) {
                if ((i % 5) == 0) {
                    printf("\r     ");
                }
                putchar('.');
                sleep(10);
            }
            puts(" done!");

            if ((*current_char - shift) < 'a') {
                puts("Wrapping it round...");

                sleep(10);
                for (int i = 1; i <= 49; i++) {
                    if ((i % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar('.');
                    sleep(10);
                }
                puts(" done!");

                *current_char = (*current_char + 26);
            }

            *current_char = (*current_char - shift);
        }

        if ((*current_char < 'a' || *current_char > 'z')) {
            if ((*current_char < 'A' || *current_char > 'Z')) {
                puts("We can leave this one alone.");
                sleep(10);

                for (int i = 1; i <= 9; i++) {
                    if ((i % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar('.');
                    sleep(10);
                }
                puts(" done!");
            }

            if ((*current_char >= 'A' && *current_char <= 'Z')) {
                puts("This one's an uppercase letter!");
                sleep(10);

                for (int i = 1; i <= 19; i++) {
                    if ((i % 5) == 0) {
                        printf("\r     ");
                    }
                    putchar('.');
                    sleep(10);
                }
                puts(" done!");

                if ((*current_char - shift) < 'A') {
                    puts("Wrapping it round...");
                    sleep(10);

                    for (int i = 1; i <= 49; i++) {
                        if ((i % 5) == 0) {
                            printf("\r     ");
                        }
                        putchar('.');
                        sleep(10);
                    }
                    puts(" done!");

                    *current_char = (*current_char + 26);
                }

                *current_char = (*current_char - shift);
            }
        }

        puts("Okay, let's write down this letter! This is a pretty complex "
             "operation, you might want to check back later.");
        sleep(10);
        for (int i = 1; i <= 299; i++) {
            if ((i % 5) == 0) {
                printf("\r     ");
            }
            putchar('.');
            sleep(10);
        }
        puts(" done!");
        printf("%c\n", *current_char);

        current_char++;
    }

    puts("You're still here?");
    return 0;
}
```

This program iterates over each character of the ciphertext
`ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}`. If the character is a letter, whether
uppercase or lowercase, its value is decreased by `18`, and this character is
wrapped to stay a lowercase or uppercase character.

# Putting everything together

This is an example of a Caesar cipher with a left shift of `18`. This means that
the flag has been encrypted with the ROT18 algorithm.

Therefore, we simply have to apply the ROT8 algorithm on the encrypted flag to
decrypt it!

I'll run this Python script for this:

```py
# Define the string containing the encrypted flag
FLAG = "ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}"

# Apply the ROT8 algorithm
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

# Print the result as a string
print(result)
```

We get the `HTB{Sleping_is_not_obfuscation}` flag!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Very easy'. The decompiled code was really close to
the reality, and it was easy to understand.

Thanks for reading!

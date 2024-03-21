+++
title = "Hunting License"
date = "2024-03-16"
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

**Description**: STOP! Adventurer, have you got an up to date relic hunting
license? If you don't, you'll need to take the exam again before you'll be
allowed passage into the spacelanes!

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
└── rev_hunting_license
    └── license

<SNIP>
```

This challenge is comprised of a single file named `license`. There's no
extension, so we can infer that it's meant to be run on Linux.

We're also given the `94.237.63.83:54974` socket, which is running the `license`
binary.

# Static analysis

Let's start by statically analyzing the `license` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I /workspace/rev_hunting_license/license
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00400000
binsz    0x00003a7c
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
PIE      false
RELROCS  true
NX       true
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l /workspace/rev_hunting_license/license
```

```
[Libs]
library          
-----------------
libreadline.so.8
libc.so.6
```

This binary uses the `libc.so.6` library, which provides the fundamental
functionalities for programs written in C. It also uses the `libreadline.so.8`
libary, which provides line-editing and history capabilities for interactive CLI
programs.

## Imports

Now, let's find the list of objects imported by this binary.

```sh
❯ rz-bin -i /workspace/rev_hunting_license/license
```

```
[Imports]
nth vaddr      bind   type   lib name              
---------------------------------------------------
1   0x00401030 GLOBAL FUNC       free
2   0x00401040 GLOBAL FUNC       puts
3   0x00401050 GLOBAL FUNC       readline
4   ---------- GLOBAL FUNC       __libc_start_main
5   0x00401060 GLOBAL FUNC       strcmp
6   0x00401070 GLOBAL FUNC       getchar
7   ---------- WEAK   NOTYPE     __gmon_start__
8   0x00401080 GLOBAL FUNC       exit
```

This binary imports functions like `puts`, but also `readline`, so we can expect
to see text printed to the terminal and to be asked for input.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E /workspace/rev_hunting_license/license
```

```
[Exports]
nth paddr      vaddr      bind   type   size lib name                    
-------------------------------------------------------------------------
43  0x00001420 0x00401420 GLOBAL FUNC   1        __libc_csu_fini
44  0x000011e1 0x004011e1 GLOBAL FUNC   86       reverse
48  0x00003060 0x00404060 GLOBAL OBJ    12       t
49  ---------- 0x00404081 GLOBAL NOTYPE 0        _edata
50  0x00001424 0x00401424 GLOBAL FUNC   0        _fini
53  0x0000128a 0x0040128a GLOBAL FUNC   300      exam
54  0x00003050 0x00404050 GLOBAL NOTYPE 0        __data_start
58  0x00003058 0x00404058 GLOBAL OBJ    0        __dso_handle
59  0x00002000 0x00402000 GLOBAL OBJ    4        _IO_stdin_used
60  0x000013c0 0x004013c0 GLOBAL FUNC   93       __libc_csu_init
61  ---------- 0x00404088 GLOBAL NOTYPE 0        _end
62  0x000010c0 0x004010c0 GLOBAL FUNC   1        _dl_relocate_static_pie
63  0x00001090 0x00401090 GLOBAL FUNC   43       _start
64  0x00001237 0x00401237 GLOBAL FUNC   83       xor
65  ---------- 0x00404081 GLOBAL NOTYPE 0        __bss_start
66  0x00001172 0x00401172 GLOBAL FUNC   111      main
67  0x00003070 0x00404070 GLOBAL OBJ    17       t2
69  ---------- 0x00404088 GLOBAL OBJ    0        __TMC_END__
70  0x00001000 0x00401000 GLOBAL FUNC   0        _init
```

We notice the classic `main` function, but also `reverse` and `xor`.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z /workspace/rev_hunting_license/license
```

```
[Strings]
nth paddr      vaddr      len size section type  string                                                                               
--------------------------------------------------------------------------------------------------------------------------------------
0   0x00002008 0x00402008 34  35   .rodata ascii So, you want to be a relic hunter?
1   0x00002030 0x00402030 81  82   .rodata ascii First, you're going to need your license, and for that you need to pass the exam.
2   0x00002088 0x00402088 84  85   .rodata ascii It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
3   0x000020dd 0x004020dd 15  16   .rodata ascii Not many are...
4   0x000020f0 0x004020f0 47  48   .rodata ascii Well done hunter - consider yourself certified!
5   0x00002120 0x00402120 79  80   .rodata ascii Okay, first, a warmup - what's the first password? This one's not even hidden: 
6   0x00002170 0x00402170 17  18   .rodata ascii PasswordNumeroUno
7   0x00002182 0x00402182 15  16   .rodata ascii Not even close!
8   0x00002198 0x00402198 45  46   .rodata ascii Getting harder - what's the second password? 
9   0x000021c8 0x004021c8 30  31   .rodata ascii You've got it all backwards...
10  0x000021e8 0x004021e8 67  68   .rodata ascii Your final test - give me the third, and most protected, password: 
11  0x0000222c 0x0040222c 27  28   .rodata ascii Failed at the final hurdle!
12  0x00003060 0x00404060 11  12   .data   ascii 0wTdr0wss4P
13  0x00003070 0x00404070 12  13   .data   ascii G{zawR}wUz}r
```

There's a few intriguing strings, we'll see later what they correspond to.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ /workspace/rev_hunting_license/license
```

```
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
```

We're asked whether we accept the challenge to become a relic hunter. If we
enter `n`, the program prints `Not many are...` and exists, so let's enter `y`:

```
Okay, first, a warmup - what's the first password? This one's not even hidden:
```

Now we're asked for a password. I'm pretty sure this corresponds to the
`PasswordNumeroUno` string in the [Strings section](#strings), but I won't go
further yet. If we enter a wrong input, we get the message `Not even close!`.

# Static analysis

## Decompilation

I'll load `license` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int32_t main(int32_t argc, char **argv, char **envp) {
    puts("So, you want to be a relic hunter?");
    puts("First, you're going to need your license, and for that you need to "
         "pass the exam.");
    puts("It's short, but it's not for the faint of heart. Are you up to the "
         "challenge?! (y/n)");
    char input = getchar();
    if ((input != 'y' && (input != 'Y' && input != '\n'))) {
        puts("Not many are...");
        exit(EXIT_FAILURE);
    }
    exam();
    puts("Well done hunter - consider yourself certified!");
    return 0;
}
```

This function checks if the user is ready to start the challenge, and calls the
`exam` function if he is.

### `exam`

```c
int64_t exam() {
    char *first_input = readline("Okay, first, a warmup - what's the first "
                                 "password? This one's not even hidden: ");
    if (strcmp(first_input, "PasswordNumeroUno") != 0) {
        puts("Not even close!");
        exit(EXIT_FAILURE);
    }
    free(first_input);

    int64_t second_password = 0;
    reverse(&second_password, "0wTdr0wss4P", 11);
    char *second_input =
        readline("Getting harder - what's the second password? ");
    if (strcmp(second_input, &second_password) != 0) {
        puts("You've got it all backwards...");
        exit(EXIT_FAILURE);
    }
    free(second_input);

    int64_t third_password;
    __builtin_memset(&third_password, 0, 17);
    xor(&third_password,
        "\x47\x7b\x7a\x61\x77\x52\x7d\x77\x55\x7a\x7d\x72\x7f\x32\x32\x32\x13",
        17, 19);
    char *third_input = readline(
        "Your final test - give me the third, and most protected, password: ");
    if (strcmp(third_input, &third_password) == 0) {
        return free(third_input);
    }
    puts("Failed at the final hurdle!");
    exit(EXIT_FAILURE);
}
```

This function can be broken down into three separate parts, each one requiring
the user to enter a password.

The first part checks if the user entered `PasswordNumeroUno`.

The second part checks if the user entered the result of the `reverse` function
called with `second_password`, `0wTdr0wss4P` and `11`.

Finally, the third part checks if the user entered the result of the `xor`
function called with `third_password`,
`\x47\x7b\x7a\x61\x77\x52\x7d\x77\x55\x7a\x7d\x72\x7f\x32\x32\x32\x13`, `17` and
`19`.

### `reverse`

```c
int64_t reverse(void *destination, void *source, int64_t length) {
    int32_t index = 0;
    int64_t final_index;
    while (true) {
        final_index = ((int64_t)index);
        if (length <= final_index) {
            break;
        }
        *(uint8_t *)((char *)destination + ((int64_t)index)) =
            *(uint8_t *)((char *)source + ((length - ((int64_t)index)) - 1));
        index = (index + 1);
    }
    return final_index;
}
```

This function reverses the contents of a memory block from the `source` memory
region to the `destination` memory region, iterating over a specified `length`
in bytes.

### `xor`

```c
int64_t xor(void *destination, void *source, int64_t length, char key) {
    int32_t index = 0;
    int64_t final_index;
    while (true) {
        final_index = ((int64_t)index);
        if (length <= final_index) {
            break;
        }
        *(uint8_t *)((char *)destination + ((int64_t)index)) =
            (*(uint8_t *)((char *)source + ((int64_t)index)) ^ key);
        index = (index + 1);
    }
    return final_index;
}
```

This function performs an XOR operation between the contents of a memory block
from the `source` memory region and a given `key`, storing the result in the
`destination` memory region. The operation is performed over a specified
`length` in bytes.

# Putting it all together

## Local

The solution to the first challenge is quite obvious, it's `PasswordNumeroUno`.

The solution to the second challenge is the string `0wTdr0wss4P` reversed up to
`11` characters, which is its size, so it's `P4ssw0rdTw0`.

The solution to the third challenge is the string
`\x47\x7b\x7a\x61\x77\x52\x7d\x77\x55\x7a\x7d\x72\x7f\x32\x32\x32\x13` XOR'ed
with `19` up to `17` characters, which is the length of this string. To obtain
the result of this operation, I'll run this Python script:

```py
# Define the password bytes as a list
PASSWORD = [
    0x47,
    0x7b,
    0x7a,
    0x61,
    0x77,
    0x52,
    0x7d,
    0x77,
    0x55,
    0x7a,
    0x7d,
    0x72,
    0x7f,
    0x32,
    0x32,
    0x32,
    0x13,
]

# Define the key for XOR operation
KEY = 0x13

# Perform XOR operation on each byte in the PASSWORD list with the KEY
result = "".join(chr(byte ^ KEY) for byte in PASSWORD)

# Print the result as a string
print(result)
```

We get the `ThirdAndFinal!!!` password!

If we run the binary once again and input these passwords, they all work!

## Remote

Now let's connect to the socket we were given.

```sh
❯ nc "94.237.63.83" "54974"
```

```
What is the file format of the executable?
>
```

There's a bunch of extra questions to guide us that weren't in the provided
binary.

In the [Properties](#properties) section, we found that the file was an ELF
binary.

```
> elf
[+] Correct!

What is the CPU architecture of the executable?
>
```

In the [Properties](#properties) section, we also found that the file was meant
to run on x86_64 systems.

```
> x86_64
[+] Correct!

What library is used to read lines for user answers? (`ldd` may help)
>
```

In the [Libraries](#libraries) section, we found that this is
`libreadline.so.8`.

```
> libreadline.so.8
[+] Correct!

What is the address of the `main` function?
>
```

We can simply open Binary Ninja to get `main`'s address, and see what that it's
`0x401172`.

```
> 0x401172
[+] Correct!

How many calls to `puts` are there in `main`? (using a decompiler may help)
>
```

If we go back to the [Decompilation](#main) section, we see that there's 5 calls
to `puts`.

```
> 5
[+] Correct!

What is the first password?
>
```

Let's enter `PasswordNumeroUno`.

```
> PasswordNumeroUno
[+] Correct!

What is the reversed form of the second password?
>
```

This is `0wTdr0wss4P`.

```
> 0wTdr0wss4P
[+] Correct!

What is the real second password?
>
```

Let's enter `P4ssw0rdTw0`.

```
> P4ssw0rdTw0
[+] Correct!

What is the XOR key used to encode the third password?
>
```

This is `19`.

```
> 19
[+] Correct!

What is the third password?
>
```

Let's enter `ThirdAndFinal!!!`.

```
> ThirdAndFinal!!!
[+] Correct!

[+] Here is the flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`
```

We got the flag!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Very easy'. The decompiled code was really close to
the reality, and it was easy to decipher and to understand.

Thanks for reading!

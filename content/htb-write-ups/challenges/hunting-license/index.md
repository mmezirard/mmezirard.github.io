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

I'll complete this challenge using a Linux VM. I'll create a `workspace`
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

We also notice that there are a few protections in place. This is not a binary
exploitation challenge, but it's still interesting to know.

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

We notice a `main` function.

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

```c,linenos
int32_t main(int32_t argc, char **argv, char **envp) {
    puts("So, you want to be a relic hunter?");
    puts("First, you're going to need your license, and for that you need to "
         "pass the exam.");
    puts("It's short, but it's not for the faint of heart. Are you up to the "
         "challenge?! (y/n)");
    char rax = getchar();
    if ((rax != 0x79 && (rax != 0x59 && rax != 0xa))) {
        puts("Not many are...");
        exit(0xffffffff);
        /* no return */
    }
    exam();
    puts("Well done hunter - consider your…");
    return 0;
}
```

The lines `3` to `5` print the welcome message indicating that this is an exam
to become a relic hunter.

The line `6` assigns the `rax` variable to the result of the `getchar`, so it
contains the first character of the user input.

The lines `7` to `12` check if the user input is different than `y`, than `Y`
and than a new line. If it's the case, it means that the user refused the
challenge, so the program exits.

If the user accepted the challebnge, the `exam` function is called line `13`.

### `exam`

```c,linenos
int64_t exam() {
    char *rax = readline("Okay, first, a warmup - what's the first password? "
                         "This one's not even hidden: ");
    if (strcmp(rax, "PasswordNumeroUno") != 0) {
        puts("Not even close!");
        exit(0xffffffff);
        /* no return */
    }
    free(rax);
    int64_t var_1c = 0;
    int32_t var_14 = 0;
    reverse(&var_1c, "0wTdr0wss4P", 0xb);
    char *rax_4 = readline("Getting harder - what's the second password? ");
    if (strcmp(rax_4, &var_1c) != 0) {
        puts("You've got it all backwards...");
        exit(0xffffffff);
        /* no return */
    }
    free(rax_4);
    int64_t s;
    __builtin_memset(&s, 0, 0x11);
    xor(&s, &t2, 0x11, 0x13);
    char *rax_8 = readline(
        "Your final test - give me the third, and most protected, password: ");
    if (strcmp(rax_8, &s) == 0) {
        return free(rax_8);
    }
    puts("Failed at the final hurdle!");
    exit(0xffffffff);
    /* no return */
}
```

This function contains three challenges in sequence.

#### First challenge

The line `2` calls `readline` to read a line of text from the user, and saves
the pointer to the first character in the `rax` variable. This variable now
holds the user input for the first challenge.

Then, the lines `4` to `8` check if the `rax` variable is equal to the string
`PasswordNumeroUno`. If it's not, they print a message and exit the program.

#### Second challenge

The lines `10` declares a `var_1c` variable initialized to `0`.

Then, the line `12` calls the `reverse` function with a reference to the
`var_1c` variable, the string `0wTdr0wss4P` and the value `0xb` (11) as
parameters.

Next, the line `13` calls `readline` to read a line of text from the user, and
saves the pointer to the first character in the `rax_4` variable. This variable
now holds the user input for the second challenge.

Then, the lines `14` to `18` check if the `rax_4` variable is equal to the value
of the `var_1c` variable, which holds the result of the `reverse` function
call. If it's not, they print a message and exit the program.

#### Third challenge

The lines `20` and `21` declare a `s` variable, and set `0x11` (17) bytes of
memory starting from the address of `s` to `0`.

Next, the line `22` calls the `xor` function with a reference to the `s`
variable, a reference to the `t2` variable (set to
`0x47 0x7b 0x7a 0x61 0x77 0x52 0x7d 0x77 0x55 0x7a 0x7d 0x72 0x7f 0x32 0x32 0x32 0x13`),
the value `0x11` (17) and the value `0x13` (19) as parameters.

Then, the lines `23` and `24` call `readline` to read a line of text from the
user, and saves the pointer to the first character in the `rax_8` variable. This
variable now holds the user input for the third challenge.

Finally, the lines `25` to `27` check if the `rax_8` variable is equal to the
value of the `s` variable, which holds the result of the `xor` function call. If
it is, it returns the result of the `free` function call. However, if it's not,
they print a message and exit the program.

---

Okay, so the solution to the first challenge is pretty obvious, as the string is
written in clear in the code. We'll have to explore the `reverse` and `xor`
functions to solve the second and third challenges.

### `reverse`

```c,linenos
int64_t reverse(void *arg1, void *arg2, int64_t arg3) {
    int32_t var_c = 0;
    int64_t rax_8;
    while (true) {
        rax_8 = ((int64_t)var_c);
        if (arg3 <= rax_8) {
            break;
        }
        *(uint8_t *)((char *)arg1 + ((int64_t)var_c)) =
            *(uint8_t *)((char *)arg2 + ((arg3 - ((int64_t)var_c)) - 1));
        var_c = (var_c + 1);
    }
    return rax_8;
}
```

This function takes three arguments: `arg1`, which corresponds to the buffer
that should hold the result string, `arg2` corresponding to the buffer holding
the string to processed and `arg3` corresponding to the size of the string that
should be processed.

The line `2` defines a `var_c` variable set to `0`.

The lines `4` to `12` are an infinite loop, which continuously assign the
`rax_8` variable to the value of `var_c` and check if `rax_8` is greater or
equal to the value of `arg3`. If this is the case, the program hits a `break`
instruction. Since the `var_c` variable is increased by one at the end of the
infinite loop, it acts as a counter for this loop, and it counts the number of
characters processed.

The lines `9` and `10` inside this loop copy the byte at the current position in
the memory pointed to by `arg2` (starting from the end) to the memory pointed to
by `arg1` at the current position.

This function seems to be designed to reverse the contents of a memory region by
copying bytes from one memory location to another in reverse order. In the end,
the `arg1` variable contains the bytes of the `arg2` variable in reverse order.

### `xor`

```c,linenos
int64_t xor (void *arg1, void *arg2, int64_t arg3, char arg4) {
    int32_t var_c = 0;
    int64_t rax_6;
    while (true) {
        rax_6 = ((int64_t)var_c);
        if (arg3 <= rax_6) {
            break;
        }
        *(uint8_t *)((char *)arg1 + ((int64_t)var_c)) =
            (*(uint8_t *)((char *)arg2 + ((int64_t)var_c)) ^ arg4);
        var_c = (var_c + 1);
    }
    return rax_6;
}
```

This function takes four arguments: `arg1`, which corresponds to the buffer that
should hold the result string, `arg2` corresponding to the buffer holding the
string to should be processed, `arg3` corresponding to the size of the string
that should be processed and `arg4` corresponding to the value used for
processing.

The line `2` defines a `var_c` variable set to `0`.

The lines `4` to `12` are an infinite loop, which continuously assign the
`rax_6` variable to the value of `var_c` and check if `rax_6` is greater or
equal to the value of `arg3`. If this is the case, the program hits a `break`
instruction. Since the `var_c` variable is increased by one at the end of the
infinite loop, it acts as a counter for this loop, and it counts the number of
characters processed.

The lines `9` and `10` inside this loop perform bitwise XOR operation on the
byte at the current position in the memory pointed to by `arg2` with the
character `arg4`, and stores the result in the memory pointed to by `arg1` at
the same position.

This function seems to be designed to XOR each byte in the memory region pointed
to by `arg2` with the character `arg4`, and stores the result in the memory
region pointed to by `arg1`. The function iterates over the memory regions up to
the specified length `arg3`.

# Putting it all together

## Local

The solution to the first challenge is quite obvious, it's `PasswordNumeroUno`.

The solution to the second challenge is the string `0wTdr0wss4P` reversed up to
`0xb` (12) characters, which is its size, so it's the `P4ssw0rdTw0`.

The solution to the third challenge is the string
`0x47 0x7b 0x7a 0x61 0x77 0x52 0x7d 0x77 0x55 0x7a 0x7d 0x72 0x7f 0x32 0x32 0x32 0x13`
XOR'ed with `0x13` (19) up to `0x11` (17) characters, which is the length of this
string. To obtain the result of this operation, I'll run this Python script:

```py
# Define the password bytes as a list
PASSWORD = [0x47, 0x7b, 0x7a, 0x61, 0x77, 0x52, 0x7d, 0x77, 0x55, 0x7a, 0x7d, 0x72, 0x7f, 0x32, 0x32, 0x32, 0x13]

# Define the key for XOR operation
KEY = 0x13

# Perform XOR operation on each byte in the PASSWORD list with the KEY
result = ''.join(chr(byte ^ KEY) for byte in PASSWORD)

# Print the result as a string
print(result)
```

If we run it, we get the `ThirdAndFinal!!!` password!

We can try these passwords for the binary questions, and they all work!

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

This is `0x13`.

```
> 0x13
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

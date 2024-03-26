+++
title = "Teleport"
date = "2024-03-24"
description = "This is a medium Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Medium

**Category**: Reversing

**Release date**: 2022-05-27

**Created by**: [clubby789](https://app.hackthebox.com/users/83743)

**Description**: You've been sent to a strange planet, inhabited by a species
with the natural ability to teleport. If you're able to capture one, you may be
able to synthesise lightweight teleportation technology. However, they don't
want to be caught, and disappear out of your grasp - can you get the drop on
them?

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
└── rev_teleport
    └── teleport

<SNIP>
```

This challenge is comprised of a single file named `teleport`.

# Static analysis

Let's start by statically analyzing the `teleport` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ file "/workspace/rev_teleport/teleport"
```

```
teleport: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1f87fe68fd7d1deaffefcf08ed2b30d660ee2d0b, stripped
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/rev_teleport/teleport"
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
❯ rz-bin -i "/workspace/rev_teleport/teleport"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x000009d0 GLOBAL FUNC       strncpy
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x000009e0 GLOBAL FUNC       puts
4   ---------- GLOBAL FUNC       __libc_start_main
5   0x000009f0 GLOBAL FUNC       _setjmp
6   ---------- WEAK   NOTYPE     __gmon_start__
7   0x00000a00 GLOBAL FUNC       longjmp
8   ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
9   0x00000a10 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `puts`, but also `setjmp` and `longjmp` so we
can expect to see text printed to the terminal and jumps in the program.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/rev_teleport/teleport"
```

```
[Strings]
nth paddr      vaddr      len size section type  string               
----------------------------------------------------------------------
0   0x00001814 0x00001814 16  17   .rodata ascii Missing password
1   0x00001825 0x00001825 17  18   .rodata ascii Looks good to me!
2   0x00001837 0x00001837 20  21   .rodata ascii Something's wrong...
```

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/rev_teleport/teleport"
```

```
Missing password
```

I assume that we have to provide a password as an argument to the program, so
let's enter a random one.

```sh
❯ "/workspace/rev_teleport/teleport" "hello?"
```

```
Something's wrong...
```

# Static analysis

## Decompilation

I'll load `teleport` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {

    if (argc != 2) {
        puts("Missing password");
        return EXIT_FAILURE;
    }

    strncpy(&firstCharPassword, argv[1], 100);

    for (int i = 0; i <= 42; i++) {
        &checkTwentyThirdCharPasswordPtr[i]();
    }

    int jmp_result = setjmp(&mainEnv);

    if (jmp_result == 100) {
        puts("Looks good to me!");
    } else {
        if (jmp_result != 101) {
            longjmp(&checkFirstCharPasswordEnv + (jmp_result * 200), 1);
        }
        puts("Something's wrong...");
    }

    return 0;
}
```

This program asks the user for input, and saves it in `firstCharPassword`.

The `firstCharPassword` symbol is defined in the `.bss` section of the binary:

```
00000000: char firstCharPassword = 0x0
00000000: char secondCharPassword = 0x0
00000000: char thirdCharPassword = 0x0
00000000: char fourthCharPassword = 0x0
00000000: char fifthCharPassword = 0x0
00000000: char sixthCharPassword = 0x0
00000000: char seventhCharPassword = 0x0
00000000: char eighthCharPassword = 0x0
00000000: char ninthCharPassword = 0x0
00000000: char tenthCharPassword = 0x0
00000000: char eleventhCharPassword = 0x0
00000000: char twelfthCharPassword = 0x0
00000000: char thirteenthCharPassword = 0x0
00000000: char fourtheenthCharPassword = 0x0
00000000: char fifteenthCharPassword = 0x0
00000000: char sixteenthCharPassword = 0x0
00000010: char seventeenthCharPassword = 0x0
00000010: char eighteenthCharPassword = 0x0
00000010: char nineteenthCharPassword = 0x0
00000010: char twentiethCharPassword = 0x0
00000010: char twentyFirstCharPassword = 0x0
00000010: char twentySecondCharPassword = 0x0
00000010: char twentyThirdCharPassword = 0x0
00000010: char twentyFourthCharPassword = 0x0
00000010: char twentyFifthCharPassword = 0x0
00000010: char twentySixthCharPassword = 0x0
00000010: char twentySeventhCharPassword = 0x0
00000010: char twentyEighthCharPassword = 0x0
00000010: char twentyNinthCharPassword = 0x0
00000010: char thirtiethCharPassword = 0x0
00000010: char thirtyFirstCharPassword = 0x0
00000010: char thirtySecondCharPassword = 0x0
00000020: char thirtyThirdCharPassword = 0x0
00000020: char thirtyFourthCharPassword = 0x0
00000020: char thirtyFifthCharPassword = 0x0
00000020: char thirtySixthCharPassword = 0x0
00000020: char thirtySeventhCharPassword = 0x0
00000020: char thirtyEighthCharPassword = 0x0
00000020: char thirtyNinthCharPassword = 0x0
00000020: char fortiethCharPassword = 0x0
00000020: char fortyFirstCharPassword = 0x0
00000020: char fortySecondCharPassword = 0x0
00000020: char fortyThirdCharPassword = 0x0

00000020:                                  00 00 00 00 00             .....
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

The first 43 characters of the password we give to the program are actually
assigned to global variables.

Then, the program executes the `checkTwentyThirdCharPasswordPtr[i]` function,
where `i` varies between `0` and `42`.

The `checkTwentyThirdCharPasswordPtr` symbol is defined in the `.data` section
of the binary:

```
00000000: void* checkTwentyThirdCharPasswordPtr = checkTwentyThirdCharPassword
00000000: void* checkThirtyEighthCharPasswordPtr = checkThirtyEighthCharPassword
00000010: void* checkSecondCharPasswordPtr = checkSecondCharPassword
00000010: void* checkThirtySecondCharPasswordPtr = checkThirtySecondCharPassword
00000020: void* checkFortyFirstCharPasswordPtr = checkFortyFirstCharPassword
00000020: void* checkTwentiethCharPasswordPtr = checkTwentiethCharPassword
00000030: void* checkThirtySixthCharPasswordPtr = checkThirtySixthCharPassword
00000030: void* checkThirtySeventhCharPasswordPtr = checkThirtySeventhCharPassword
00000040: void* checkThirtyThirdCharPasswordPtr = checkThirtyThirdCharPassword
00000040: void* checkFifthCharPasswordPtr = checkFifthCharPassword
00000050: void* checkSeventhCharPasswordPtr = checkSeventhCharPassword
00000050: void* checkTwentySixthCharPasswordPtr = checkTwentySixthCharPassword
00000060: void* checkFourthCharPasswordPtr = checkFourthCharPassword
00000060: void* checkEighteenthCharPasswordPtr = checkEighteenthCharPassword
00000070: void* checkTenthCharPasswordPtr = checkTenthCharPassword
00000070: void* checkTwentyEighthCharPasswordPtr = checkTwentyEighthCharPassword
00000080: void* checkThirtyFifthCharPasswordPtr = checkThirtyFifthCharPassword
00000080: void* checkThirtyFourthCharPasswordPtr = checkThirtyFourthCharPassword
00000090: void* checkThirtyFirstCharPasswordPtr = checkThirtyFirstCharPassword
00000090: void* checkTwentyFourthCharPasswordPtr = checkTwentyFourthCharPassword
000000a0: void* checkSixteenthCharPasswordPtr = checkSixteenthCharPassword
000000a0: void* checkThirtiethCharPasswordPtr = checkThirtiethCharPassword
000000b0: void* checkFortySecondCharPasswordPtr = checkFortySecondCharPassword
000000b0: void* checkFortyThirdCharPasswordPtr = checkFortyThirdCharPassword
000000c0: void* checkSixthCharPasswordPtr = checkSixthCharPassword
000000c0: void* checkThirdCharPasswordPtr = checkThirdCharPassword
000000d0: void* checkFourtheenthCharPasswordPtr = checkFourtheenthCharPassword
000000d0: void* checkFortiethCharPasswordPtr = checkFortiethCharPassword
000000e0: void* checkEighthCharPasswordPtr = checkEighthCharPassword
000000e0: void* checkTwelfthCharPasswordPtr = checkTwelfthCharPassword
000000f0: void* checkTwentySecondCharPasswordPtr = checkTwentySecondCharPassword
000000f0: void* checkFirstCharPasswordPtr = checkFirstCharPassword
00000100: void* checkTwentyFirstCharPasswordPtr = checkTwentyFirstCharPassword
00000100: void* nineteenthCharPasswordPtr = checkNineteenthCharPassword
00000110: void* checkSeventeenthCharPasswordPtr = checkSeventeenthCharPassword
00000110: void* checkFifteenthCharPasswordPtr = checkFifteenthCharPassword
00000120: void* checkThirteenthCharPasswordPtr = checkThirteenthCharPassword
00000120: void* checkNinthCharPasswordPtr = checkNinthCharPassword
00000130: void* checkEleventhCharPasswordPtr = checkEleventhCharPassword
00000130: void* checkTwentySeventhCharPasswordPtr = checkTwentySeventhCharPassword
00000140: void* checkTwentyFifthCharPasswordPtr = checkTwentyFifthCharPassword
00000140: void* checkThirtyNinthCharPasswordPtr = checkThirtyNinthCharPassword
00000150: void* checkTwentyNinthCharPasswordPtr = checkTwentyNinthCharPassword
```

This means that all of these functions are executed by the loop.

Then, this function calls `setjmp` with the `mainEnv` symbol, defined in `.bss`:

```
00000000: mainEnv:
00000000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

This effectively stores the `main` function context at this address.

The `jmp_result` is then compared to values. If it's `100`, it's a success, and
if it's `101`, it's a failure.

If it's neither `100` nor `101`, it calls `longjmp` with the
`checkFirstCharPasswordEnv` symbol, plus an offset. This symbol is also defined
in the `.bss` segment:

```
00000000  checkFirstCharPasswordEnv:
00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000c0  00 00 00 00 00 00 00 00                          ........
000000c0  checkSecondCharPasswordEnv:
000000c0                          00 00 00 00 00 00 00 00          ........
000000d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000180  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000190  checkThirdCharPasswordEnv:
00000190  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000200  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000210  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000220  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000230  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000240  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000250  00 00 00 00 00 00 00 00                          ........
<SNIP>
000020d0  checkFortyThirdCharPasswordEnv:
000020d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

In fact, there's 43 global variables next to each other, which are meant to
store the context for the 43 functions we discovered previously.

### `checkTwentyThirdCharPassword`

```c
long long int checkTwentyThirdCharPassword() {
    int jmp_result = setjmp(&checkTwentyThirdCharPasswordEnv);
    if (jmp_result == 0) {
        return jmp_result;
    }

    if (twentyThirdCharPassword != 'p') {
        longjmp(&mainEnv, 101);
    }
    longjmp(&mainEnv, 23);
}
```

This function checks if `twentyThirdCharPassword` is equal to the character `p`.
Depending on the result, it jumps to the `main` function context either with a
value of `101`, which indicates an error, or a value of `23`, which is the
offset of the context for the next character check from the `checkFirstCharEnv`
context.

Note that this function isn't entirely executed the first time it gets called,
since `jmp_result` is then equal to `0`. The first execution only sets up the
context in the global variable `checkTwentyThirdCharPasswordEnv`.

### `checkThirtyEighthCharPassword`

```c
long long int checkThirtyEighthCharPassword() {
    int jmp_result = setjmp(&checkThirtyEighthCharPasswordEnv);
    if (jmp_result == 0) {
        return jmp_result;
    }

    if (thirtyEighthCharPassword != 'n') {
        longjmp(&mainEnv, 101);
    }
    longjmp(&mainEnv, 38);
}
```

This function checks if `thirtyEighthCharPassword` is equal to the character
`n`. Depending on the result, it jumps to the `main` function context either
with a value of `101`, which indicates an error, or a value of `38`, which is
the offset of the context for the next character check from the
`checkFirstCharEnv` context.

Note that this function isn't entirely executed the first time it gets called,
since `jmp_result` is then equal to `0`. The first execution only sets up the
context in the global variable `checkThirtyEighthCharPasswordEnv`.

I won't show you the 43 functions, but they're all like these ones. They all set
up jumps values the first time they're executed, and jump to the main function
with different values the second time.

# Putting everything together

When we give a password as an argument to this program, it's stored in an array
of characters indexed with global variable names. The program then calls 43
functions, which set up an array of context values indexed with global variable
names too, containing return points.

Then, the `main` function jumps to the addresses of these functions with the
value `1`. This is when the characters of the user input are actually checked.
If they don't match, a value of `101` is returned. If they do match, the array
context index of the next check to perform is returned. This process is repeated
until it reaches the return value of `100`, indicating a success.

Therefore, we can reconstruct the flag by checking the comparison performed by
each of these functions!

It takes a bit of time, but we end up with the flag
`HTB{jump1ng_thru_th3_sp4c3_t1m3_c0nt1nuum!}`.

If we run the binary once again with this string as the argument, we receive the
message `Looks good to me!`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Easy'. The decompiled code was really close to the
reality, but not so easy to understand due the complex control flow. It was also
really annoying to retrieve the characters of the flag one by one.

Thanks for reading!

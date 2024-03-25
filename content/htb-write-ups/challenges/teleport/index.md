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
0000555555603280  char firstCharPassword = 0x0
0000555555603281  char secondCharPassword = 0x0
0000555555603282  char thirdCharPassword = 0x0
0000555555603283  char fourthCharPassword = 0x0
0000555555603284  char fifthCharPassword = 0x0
0000555555603285  char sixthCharPassword = 0x0
0000555555603286  char seventhCharPassword = 0x0
0000555555603287  char eighthCharPassword = 0x0
0000555555603288  char ninthCharPassword = 0x0
0000555555603289  char tenthCharPassword = 0x0
000055555560328a  char eleventhCharPassword = 0x0
000055555560328b  char twelfthCharPassword = 0x0
000055555560328c  char thirteenthCharPassword = 0x0
000055555560328d  char fourtheenthCharPassword = 0x0
000055555560328e  char fifteenthCharPassword = 0x0
000055555560328f  char sixteenthCharPassword = 0x0
0000555555603290  char seventeenthCharPassword = 0x0
0000555555603291  char eighteenthCharPassword = 0x0
0000555555603292  char nineteenthCharPassword = 0x0
0000555555603293  char twentiethCharPassword = 0x0
0000555555603294  char twentyFirstCharPassword = 0x0
0000555555603295  char twentySecondCharPassword = 0x0
0000555555603296  char twentyThirdCharPassword = 0x0
0000555555603297  char twentyFourthCharPassword = 0x0
0000555555603298  char twentyFifthCharPassword = 0x0
0000555555603299  char twentySixthCharPassword = 0x0
000055555560329a  char twentySeventhCharPassword = 0x0
000055555560329b  char twentyEighthCharPassword = 0x0
000055555560329c  char twentyNinthCharPassword = 0x0
000055555560329d  char thirtiethCharPassword = 0x0
000055555560329e  char thirtyFirstCharPassword = 0x0
000055555560329f  char thirtySecondCharPassword = 0x0
00005555556032a0  char thirtyThirdCharPassword = 0x0
00005555556032a1  char thirtyFourthCharPassword = 0x0
00005555556032a2  char thirtyFifthCharPassword = 0x0
00005555556032a3  char thirtySixthCharPassword = 0x0
00005555556032a4  char thirtySeventhCharPassword = 0x0
00005555556032a5  char thirtyEighthCharPassword = 0x0
00005555556032a6  char thirtyNinthCharPassword = 0x0
00005555556032a7  char fortiethCharPassword = 0x0
00005555556032a8  char fortyFirstCharPassword = 0x0
00005555556032a9  char fortySecondCharPassword = 0x0
00005555556032aa  char fortyThirdCharPassword = 0x0

00005555556032ab                                   00 00 00 00 00             .....
00005555556032b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556032c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556032d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556032e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556032f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

The first 43 characters of the password we give to the program are actually
assigned to global variables.

Then, the program executes the `checkTwentyThirdCharPasswordPtr[i]` function,
where `i` varies between `0` and `42`.

The `checkTwentyThirdCharPasswordPtr` symbol is defined in the `.data` section
of the binary:

```
0000555555603020  void* checkTwentyThirdCharPasswordPtr = checkTwentyThirdCharPassword
0000555555603028  void* checkThirtyEighthCharPasswordPtr = checkThirtyEighthCharPassword
0000555555603030  void* checkSecondCharPasswordPtr = checkSecondCharPassword
0000555555603038  void* checkThirtySecondCharPasswordPtr = checkThirtySecondCharPassword
0000555555603040  void* checkFortyFirstCharPasswordPtr = checkFortyFirstCharPassword
0000555555603048  void* checkTwentiethCharPasswordPtr = checkTwentiethCharPassword
0000555555603050  void* checkThirtySixthCharPasswordPtr = checkThirtySixthCharPassword
0000555555603058  void* checkThirtySeventhCharPasswordPtr = checkThirtySeventhCharPassword
0000555555603060  void* checkThirtyThirdCharPasswordPtr = checkThirtyThirdCharPassword
0000555555603068  void* checkFifthCharPasswordPtr = checkFifthCharPassword
0000555555603070  void* checkSeventhCharPasswordPtr = checkSeventhCharPassword
0000555555603078  void* checkTwentySixthCharPasswordPtr = checkTwentySixthCharPassword
0000555555603080  void* checkFourthCharPasswordPtr = checkFourthCharPassword
0000555555603088  void* checkEighteenthCharPasswordPtr = checkEighteenthCharPassword
0000555555603090  void* checkTenthCharPasswordPtr = checkTenthCharPassword
0000555555603098  void* checkTwentyEighthCharPasswordPtr = checkTwentyEighthCharPassword
00005555556030a0  void* checkThirtyFifthCharPasswordPtr = checkThirtyFifthCharPassword
00005555556030a8  void* checkThirtyFourthCharPasswordPtr = checkThirtyFourthCharPassword
00005555556030b0  void* checkThirtyFirstCharPasswordPtr = checkThirtyFirstCharPassword
00005555556030b8  void* checkTwentyFourthCharPasswordPtr = checkTwentyFourthCharPassword
00005555556030c0  void* checkSixteenthCharPasswordPtr = checkSixteenthCharPassword
00005555556030c8  void* checkThirtiethCharPasswordPtr = checkThirtiethCharPassword
00005555556030d0  void* checkFortySecondCharPasswordPtr = checkFortySecondCharPassword
00005555556030d8  void* checkFortyThirdCharPasswordPtr = checkFortyThirdCharPassword
00005555556030e0  void* checkSixthCharPasswordPtr = checkSixthCharPassword
00005555556030e8  void* checkThirdCharPasswordPtr = checkThirdCharPassword
00005555556030f0  void* checkFourtheenthCharPasswordPtr = checkFourtheenthCharPassword
00005555556030f8  void* checkFortiethCharPasswordPtr = checkFortiethCharPassword
0000555555603100  void* checkEighthCharPasswordPtr = checkEighthCharPassword
0000555555603108  void* checkTwelfthCharPasswordPtr = checkTwelfthCharPassword
0000555555603110  void* checkTwentySecondCharPasswordPtr = checkTwentySecondCharPassword
0000555555603118  void* checkFirstCharPasswordPtr = checkFirstCharPassword
0000555555603120  void* checkTwentyFirstCharPasswordPtr = checkTwentyFirstCharPassword
0000555555603128  void* nineteenthCharPasswordPtr = checkNineteenthCharPassword
0000555555603130  void* checkSeventeenthCharPasswordPtr = checkSeventeenthCharPassword
0000555555603138  void* checkFifteenthCharPasswordPtr = checkFifteenthCharPassword
0000555555603140  void* checkThirteenthCharPasswordPtr = checkThirteenthCharPassword
0000555555603148  void* checkNinthCharPasswordPtr = checkNinthCharPassword
0000555555603150  void* checkEleventhCharPasswordPtr = checkEleventhCharPassword
0000555555603158  void* checkTwentySeventhCharPasswordPtr = checkTwentySeventhCharPassword
0000555555603160  void* checkTwentyFifthCharPasswordPtr = checkTwentyFifthCharPassword
0000555555603168  void* checkThirtyNinthCharPasswordPtr = checkThirtyNinthCharPassword
0000555555603170  void* checkTwentyNinthCharPasswordPtr = checkTwentyNinthCharPassword
```

This means that all of these functions are executed by the loop.

Then, this function calls `setjmp` with the `mainEnv` symbol, defined in `.bss`:

```
00005555556031a0  mainEnv:
00005555556031a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556031b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556031c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556031d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556031e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556031f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603200  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603210  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603220  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603230  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603240  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603250  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603260  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603270  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

This effectively stores the `main` function context at this address.

The `jmp_result` is then compared to values. If it's `100`, it's a success, and
if it's `101`, it's a failure.

If it's neither `100` nor `101`, it calls `longjmp` with the
`checkFirstCharPasswordEnv` symbol, plus an offset. This symbol is also defined
in the `.bss` segment:

```
0000555555603300  checkFirstCharPasswordEnv:
0000555555603300  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603310  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603320  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603330  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603340  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603350  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603360  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603370  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603380  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603390  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556033a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556033b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556033c0  00 00 00 00 00 00 00 00                          ........
00005555556033c8  checkSecondCharPasswordEnv:
00005555556033c8                          00 00 00 00 00 00 00 00          ........
00005555556033d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556033e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556033f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603400  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603420  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603430  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603440  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603450  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603460  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603470  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603480  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603490  checkThirdCharPasswordEnv:
0000555555603490  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556034f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603500  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603510  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603540  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555603550  00 00 00 00 00 00 00 00                          ........
<SNIP>
00005555556053d0  checkFortyThirdCharPasswordEnv:
00005555556053d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556053e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556053f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605400  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605420  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605430  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605440  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605450  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605460  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605470  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605480  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605490  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005555556054f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605500  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605510  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605540  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0000555555605550  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
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

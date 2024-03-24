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

This challenge is comprised of a single file named `teleport`. There's no
extension, so we can infer that it's meant to be run on Linux.

# Static analysis

Let's start by statically analyzing the `teleport` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I "/workspace/rev_teleport/teleport"
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x0000328f
bintype  elf
bits     64
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
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
relro    full
rpath    NONE
subsys   linux
stripped true
crypto   false
havecode true
va       true
sanitiz  false
static   false
linenum  false
lsyms    false
canary   false
PIE      true
RELROCS  false
NX       true
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

This binary imports functions like `puts`, but also `_setjmp` and `longjmp` so
we can expect to see text printed to the terminal and jumps in the program.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E "/workspace/rev_teleport/teleport"
```

```
[Exports]
nth paddr vaddr bind type size lib name 
----------------------------------------
```

This binary is stripped, so there's nothing.

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

That's really mysterious.

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

    int jmp_result = setjmp(&env);

    if (jmp_result == 100) {
        puts("Looks good to me!");
    } else {
        if (jmp_result != 101) {
            longjmp(&envs + (jmp_result * 200), 1);
        }
        puts("Something's wrong...");
    }

    return 0;
}
```

This program asks the user for input, and saves it in `firstCharPassword`.

The `firstCharPassword` symbol is defined in the `.bss` section of the binary.
Here's an overview of this section:

```c
char firstCharPassword = 0x0
char secondCharPassword = 0x0
char thirdCharPassword = 0x0
char fourthCharPassword = 0x0
char fifthCharPassword = 0x0
char sixthCharPassword = 0x0
char seventhCharPassword = 0x0
char eighthCharPassword = 0x0
char ninthCharPassword = 0x0
char tenthCharPassword = 0x0
char eleventhCharPassword = 0x0
char twelfthCharPassword = 0x0
char thirteenthCharPassword = 0x0
char fourtheenthCharPassword = 0x0
char fifteenthCharPassword = 0x0
char sixteenthCharPassword = 0x0
char seventeenthCharPassword = 0x0
char eighteenthCharPassword = 0x0
char nineteenthCharPassword = 0x0
char twentiethCharPassword = 0x0
char twentyFirstCharPassword = 0x0
char twentySecondCharPassword = 0x0
char twentyThirdCharPassword = 0x0
char twentyFourthCharPassword = 0x0
char twentyFifthCharPassword = 0x0
char twentySixthCharPassword = 0x0
char twentySeventhCharPassword = 0x0
char twentyEighthCharPassword = 0x0
char twentyNinthCharPassword = 0x0
char thirtiethCharPassword = 0x0
char thirtyFirstCharPassword = 0x0
char thirtySecondCharPassword = 0x0
char thirtyThirdCharPassword = 0x0
char thirtyFourthCharPassword = 0x0
char thirtyFifthCharPassword = 0x0
char thirtySixthCharPassword = 0x0
char thirtySeventhCharPassword = 0x0
char thirtyEighthCharPassword = 0x0
char thirtyNinthCharPassword = 0x0
char fortiethCharPassword = 0x0
char fortyFirstCharPassword = 0x0
char fortySecondCharPassword = 0x0
char fortyThirdCharPassword = 0x0
```

This means that the first 43 characters of the password we give to the program
have symbols assigned to them.

Then, the program executes the `checkTwentyThirdCharPasswordPtr[i]` function,
where `i` varies between `0` and `42`.

The `checkTwentyThirdCharPasswordPtr` symbol is defined in the `.data` section
of the binary. Here's an overview of this section:

```c
void* checkTwentyThirdCharPasswordPtr = checkTwentyThirdCharPassword
void* checkThirtyEighthCharPasswordPtr = checkThirtyEighthCharPassword
void* checkSecondCharPasswordPtr = checkSecondCharPassword
void* checkThirtySecondCharPasswordPtr = checkThirtySecondCharPassword
void* checkFortyFirstCharPasswordPtr = checkFortyFirstCharPassword
void* checkTwentiethCharPasswordPtr = checkTwentiethCharPassword
void* checkThirtySixthCharPasswordPtr = checkThirtySixthCharPassword
void* checkThirtySeventhCharPasswordPtr = checkThirtySeventhCharPassword
void* checkThirtyThirdCharPasswordPtr = checkThirtyThirdCharPassword
void* checkFifthCharPasswordPtr = checkFifthCharPassword
void* checkSeventhCharPasswordPtr = checkSeventhCharPassword
void* checkTwentySixthCharPasswordPtr = checkTwentySixthCharPassword
void* checkFourthCharPasswordPtr = checkFourthCharPassword
void* checkEighteenthCharPasswordPtr = checkEighteenthCharPassword
void* checkTenthCharPasswordPtr = checkTenthCharPassword
void* checkTwentyEighthCharPasswordPtr = checkTwentyEighthCharPassword
void* checkThirtyFifthCharPasswordPtr = checkThirtyFifthCharPassword
void* checkThirtyFourthCharPasswordPtr = checkThirtyFourthCharPassword
void* checkThirtyFirstCharPasswordPtr = checkThirtyFirstCharPassword
void* checkTwentyFourthCharPasswordPtr = checkTwentyFourthCharPassword
void* checkSixteenthCharPasswordPtr = checkSixteenthCharPassword
void* checkThirtiethCharPasswordPtr = checkThirtiethCharPassword
void* checkFortySecondCharPasswordPtr = checkFortySecondCharPassword
void* checkFortyThirdCharPasswordPtr = checkFortyThirdCharPassword
void* checkSixthCharPasswordPtr = checkSixthCharPassword
void* checkThirdCharPasswordPtr = checkThirdCharPassword
void* checkFourtheenthCharPasswordPtr = checkFourtheenthCharPassword
void* checkFortiethCharPasswordPtr = checkFortiethCharPassword
void* checkEighthCharPasswordPtr = checkEighthCharPassword
void* checkTwelfthCharPasswordPtr = checkTwelfthCharPassword
void* checkTwentySecondCharPasswordPtr = checkTwentySecondCharPassword
void* checkFirstCharPasswordPtr = checkFirstCharPassword
void* checkTwentyFirstCharPasswordPtr = checkTwentyFirstCharPassword
void* nineteenthCharPasswordPtr = checkNineteenthCharPassword
void* checkSeventeenthCharPasswordPtr = checkSeventeenthCharPassword
void* checkFifteenthCharPasswordPtr = checkFifteenthCharPassword
void* checkThirteenthCharPasswordPtr = checkThirteenthCharPassword
void* checkNinthCharPasswordPtr = checkNinthCharPassword
void* checkEleventhCharPasswordPtr = checkEleventhCharPassword
void* checkTwentySeventhCharPasswordPtr = checkTwentySeventhCharPassword
void* checkTwentyFifthCharPasswordPtr = checkTwentyFifthCharPassword
void* checkThirtyNinthCharPasswordPtr = checkThirtyNinthCharPassword
void* checkTwentyNinthCharPasswordPtr = checkTwentyNinthCharPassword
```

This means that all of these functions are executed by the loop.

Then, this function calls `setjmp`. If it returns `100`, it's a success, and if
it's `101`, it's a failure.

If it's neither `100` nor `101`, it calls `longjmp`.

### `checkTwentyThirdCharPassword`

```c
long long int checkTwentyThirdCharPassword() {
    int jmp_result = _setjmp(&envs[33]);
    if (jmp_result == 0) {
        return jmp_result;
    }

    if (twentyThirdCharPassword != 'p') {
        longjmp(&env, 101);
    }
    longjmp(&env, 23);
}
```

This function checks if `twentyThirdCharPassword` is equal to the character `p`.
Depending on the result, it performs jumps with different values.

Note that this function isn't entirely executed the first time it gets called,
since `jmp_result` is then equal to `0`.

### `checkThirtyEighthCharPassword`

```c
long long int checkThirtyEighthCharPassword() {
    int jmp_result = _setjmp(&envs[38]);
    if (jmp_result == 0) {
        return jmp_result;
    }

    if (thirtyEighthCharPassword != 'n') {
        longjmp(&unknown2, 101);
    }
    longjmp(&unknown2, 38);
}
```

This function checks if `thirtyEighthCharPassword` is equal to the character `n`.
Depending on the result, it performs different jumps.

Note that this function isn't entirely executed the first time it gets called,
since `jmp_result` is then equal to `0`.

I won't show you the 43 functions, but they're all like these ones. They all set
up jumps values the first time they're executed.

# Putting everything together

When this program, it stores the user input in an array of characters. It then
calls 43 functions, which set up an `envs` array of values containing return
points.

Then, it jumps to the addresses of these functions with the value `1`. This is
when the characters of the user input are actually checked. If they don't match,
a value of `101` is returned. If they do match, the `envs` index of the next
check to perform is returned. This process is repeated until it reaches the
return value of `100`, indicating a success.

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
reality, but not so easy to understand. It was also really annoying to retrieve
the characters of the flag one by one.

Thanks for reading!

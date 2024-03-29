+++
title = "WIDE"
date = "2024-03-21"
description = "This is a very easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Reversing

**Release date**: 2022-05-27

**Created by**: [clubby789](https://app.hackthebox.com/users/83743)

**Description**: We've received reports that Draeger has stashed a huge arsenal
in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded
access terminal to the Widely Inflated Dimension Editor from his headquarters,
but the entry for the dimension has been encrypted. Can you make it inside and
take control?

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
└── rev_wide
    ├── db.ex
    └── wide

<SNIP>
```

This challenge is comprised of a file named `db.ex` and a file named `wide`.

# Static analysis

Let's start by statically analyzing the `wide` file using the Rizin toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ file "/workspace/rev_wide/wide"
```

```
wide: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=13869bb7ce2c22f474b95ba21c9d7e9ff74ecc3f, not stripped
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/rev_wide/wide"
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
❯ rz-bin -i "/workspace/rev_wide/wide"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x00000800 GLOBAL FUNC       wcscmp
2   ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
3   0x00000810 GLOBAL FUNC       puts
4   0x00000820 GLOBAL FUNC       fread
5   0x00000830 GLOBAL FUNC       mbstowcs
6   0x00000840 GLOBAL FUNC       fclose
7   0x00000850 GLOBAL FUNC       printf
8   ---------- GLOBAL FUNC       __libc_start_main
9   0x00000860 GLOBAL FUNC       fgets
10  0x00000870 GLOBAL FUNC       calloc
11  0x00000880 GLOBAL FUNC       ftell
12  ---------- WEAK   NOTYPE     __gmon_start__
13  0x00000890 GLOBAL FUNC       strtol
14  0x000008a0 GLOBAL FUNC       fseek
15  0x000008b0 GLOBAL FUNC       fopen
16  0x000008c0 GLOBAL FUNC       exit
17  ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
18  0x000008d0 WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `puts`, but also `fopen`, `fread` and
`fclose`, so we can expect to see text printed to the terminal and the binary
probably deals with files.

## Strings

Finally, let's retrieve the list of strings contained in this binary.

```sh
❯ rz-bin -z "/workspace/rev_wide/wide"
```

```
[Strings]
nth paddr      vaddr      len size section type    string                                                                       
--------------------------------------------------------------------------------------------------------------------------------
0   0x00001088 0x00001088 43  44   .rodata ascii   Which dimension would you like to examine? 
1   0x000010b4 0x000010b4 24  25   .rodata ascii   That option was invalid.
2   0x000010d0 0x000010d0 69  70   .rodata ascii   [X] That entry is encrypted - please enter your WIDE decryption key: 
3   0x00001118 0x00001118 15  64   .rodata utf32le sup3rs3cr3tw1d3
4   0x00001158 0x00001158 76  77   .rodata ascii   [X]                          Key was incorrect                           [X]
5   0x000011a5 0x000011a5 16  17   .rodata ascii   Usage: %s db.ex\n
6   0x000011b8 0x000011b8 76  77   .rodata ascii   [*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
7   0x00001208 0x00001208 76  77   .rodata ascii   [*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
8   0x00001258 0x00001258 51  52   .rodata ascii   [x] There was a problem accessing your database [x]
9   0x00001290 0x00001290 76  77   .rodata ascii   [*]                       Displaying Dimensions....                      [*]
10  0x000012e0 0x000012e0 76  77   .rodata ascii   [*]       Name       |              Code                |   Encrypted    [*]
11  0x00001330 0x00001330 33  34   .rodata ascii   [X] %-16s | %-32s | %6s%c%7s [*]\n
```

According to these strings, we're given the possibility of selecting a dimension
to examine, but we require a key to do so. The `sup3rs3cr3tw1d3` string would
make a great key...

There's also a string indicating that the binary expects a `db.ex` file to run.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

Let's execute this binary on Linux.

```sh
❯ "/workspace/rev_wide/wide" "/workspace/rev_wide/db.ex"
```

```
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine?
```

We're asked to enter a dimension to examine. I can enter numbers from `0` to `6`
to specify the dimension.

The most interesting is the seventh, which is encrypted with a key.

```
[X] That entry is encrypted - please enter your WIDE decryption key:
```

I'm pretty sure this corresponds to the `sup3rs3cr3tw1d3` string in the
[Strings section](#strings), but I won't go further yet. If we enter a wrong
input, we get the message `Key was incorrect`.

# Static analysis

## Decompilation

I'll load `wide` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {
    if (argc <= 1) {
        printf("Usage: %s db.ex\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    puts("[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension "
         "Editor [*]");
    puts("[*]    Serving your pocket dimension storage needs since 14,012.5 B  "
         "  "
         "  [*]");

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        puts("[x] There was a problem accessing your database [x]");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    long long int fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    int dimensionCount = fileSize / 180;

    char *dimensionData = calloc(dimensionCount, 180);
    fread(dimensionData, 180, ((long long int)dimensionCount), fp);
    fclose(fp);

    puts("[*]                       Displaying Dimensions....                  "
         "  "
         "  [*]");
    puts("[*]       Name       |              Code                |   "
         "Encrypted  "
         "  [*]");

    for (int i = 0; i < dimensionCount; i++) {
        int encryptionIndicator;
        if (*(unsigned int *)(dimensionData + (i * 180)) == 0) {
            encryptionIndicator = ' ';
        } else {
            encryptionIndicator = '*';
        }

        printf("[X] %-16s | %-32s | %6s%c%7s [*]\n",
               dimensionData + (i * 180) + 4, dimensionData + (i * 180) + 20,
               "\x00\x00\x00", encryptionIndicator, "\x00\x00\x00", argv);
    }

    menu(dimensionData, dimensionCount);
    free(dimensionData);

    return 0;
}
```

This function reads the database passed as a parameter, and displays the
dimensions contained in the database. It then calls the `menu` function with the
`dimensionData` and the `dimensionCount`.

### `menu`

```c
void menu(char *dimensionData, int dimensionCount) {
    char inputDimension[32];
    memset(inputDimension, 0, sizeof(inputDimension));

    while (true) {
        printf("Which dimension would you like to examine? ");
        fgets(inputDimension, sizeof(inputDimension), stdin);

        int selectedDimension = strtol(inputDimension, NULL, 10);

        if (selectedDimension >= 0 && selectedDimension < dimensionCount) {
            char *selectedDimensionData =
                dimensionData + (selectedDimension * 180);

            int dataType = *(int *)(selectedDimensionData);
            char *encryptedString = selectedDimensionData + 6;

            if (dataType == 0) {
                puts(encryptedString + 4);
                continue;
            } else {
                printf("[X] That entry is encrypted - please enter your WIDE "
                       "decryption key: ");

                char inputKey[16];
                fgets(inputKey, sizeof(inputKey), stdin);

                wchar_t wideInputKey[16];
                mbstowcs(wideInputKey, inputKey, sizeof(wideInputKey));

                if (wcscmp(wideInputKey, U"sup3rs3cr3tw1d3") != 0) {
                    puts("[X]                          Key was incorrect       "
                         "[X]");
                    continue;
                } else {
                    char decryptedString[128];
                    memcpy(decryptedString, encryptedString,
                           sizeof(decryptedString));

                    for (int i = 0; i < 128; i++) {
                        if (decryptedString[i] == 0) {
                            break;
                        }

                        int temp = i * 3;
                        int shiftedValue = (temp << 3) + temp;
                        int divisor = shiftedValue / 0xff;

                        decryptedString[i] ^=
                            shiftedValue - ((divisor << 8) - divisor);
                    }

                    puts(decryptedString);
                    continue;
                }
            }
        } else {
            puts("That option was invalid.");
        }
    }
}
```

This function reads the user input corresponding to the selected dimension. If
it's valid, the function checks if it's associated to an encrypted dimension,
and if it is it asks for a key. If this key is `sup3rs3cr3tw1d3`, it performs a
bunch of calculations on the dimension data and prints the result to the
terminal.

# Putting it all together

To access the encrypted dimension content, we need to input the
`sup3rs3cr3tw1d3` key.

If we run the binary once again and input this key, we get the flag `HTB{som3_str1ng5_4r3_w1d3}`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Piece of cake'. The decompiled code was really close
to the reality, and it was easy to understand. It wasn't even necessary to
decompile this binary, we could just read the strings and guess the key.

Thanks for reading!

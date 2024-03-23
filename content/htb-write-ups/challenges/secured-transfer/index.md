+++
title = "Secured Transfer"
date = "2024-03-14"
description = "This is an easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Easy

**Category**: Reversing

**Release date**: 2022-11-18

**Created by**: [Leeky](https://app.hackthebox.com/users/129896)

**Description**: Ghosts have been sending messages to each other through the
aether, but we can't understand a word of it! Can you understand their riddles?

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
└── rev_securedtransfer
    ├── securetransfer
    └── trace.pcap

<SNIP>
```

This challenge is comprised of a file named `trace.pcap` and a file named
`securetransfer`. There's no extension, so we can infer that it's meant to be
run on Linux.

# Static analysis

Let's start by statically analyzing the `securetransfer` file using the Rizin
toolkit.

## Properties

Let's inspect the properties of this binary.

```sh
❯ rz-bin -I "/workspace/rev_securedtransfer/securetransfer"
```

```
[Info]
arch     x86
cpu      N/A
baddr    0x00000000
binsz    0x00003145
bintype  elf
bits     64
class    ELF64
compiler GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
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
canary   true
PIE      true
RELROCS  false
NX       true
```

This is an ELF 64-bit, LSB executable.

## Libraries

Let's find out which libraries are used by this binary.

```sh
❯ rz-bin -l "/workspace/rev_securedtransfer/securetransfer"
```

```
[Libs]
library          
-----------------
libcrypto.so.1.1
libc.so.6
```

This binary uses the `libc.so.6` library, which provides the fundamental
functionalities for programs written in C. It also uses the `libcrypto.so.1.1`
libary, which provides various cryptographic functions and protocols
implementation.

## Imports

Now, let's find the list of objects imported by this binary.

```sh
❯ rz-bin -i "/workspace/rev_securedtransfer/securetransfer"
```

```
[Imports]
nth vaddr      bind   type   lib name                        
-------------------------------------------------------------
1   0x00001240 GLOBAL FUNC       printf
2   0x00001250 GLOBAL FUNC       memset
3   0x00001260 GLOBAL FUNC       ftell
4   0x00001270 GLOBAL FUNC       inet_pton
5   0x00001280 GLOBAL FUNC       close
6   ---------- WEAK   NOTYPE     __gmon_start__
7   0x00001290 GLOBAL FUNC       puts
8   0x000012a0 GLOBAL FUNC       fseek
9   0x000012b0 GLOBAL FUNC       htons
10  0x000012c0 GLOBAL FUNC       read
11  0x000012d0 GLOBAL FUNC       malloc
12  0x000012e0 GLOBAL FUNC       fopen
13  ---------- GLOBAL FUNC       __libc_start_main
14  0x000012f0 GLOBAL FUNC       EVP_DecryptInit_ex
15  ---------- WEAK   NOTYPE     _ITM_deregisterTMCloneTable
16  0x00001300 GLOBAL FUNC       free
17  ---------- WEAK   NOTYPE     _ITM_registerTMCloneTable
18  0x00001310 GLOBAL FUNC       listen
19  0x00001320 GLOBAL FUNC       EVP_DecryptFinal_ex
20  0x00001330 GLOBAL FUNC       connect
21  0x00001340 GLOBAL FUNC       EVP_CIPHER_CTX_new
22  0x00001350 GLOBAL FUNC       socket
23  0x00001360 GLOBAL FUNC       fread
24  0x00001370 GLOBAL FUNC       EVP_aes_256_cbc
25  0x00001380 GLOBAL FUNC       __stack_chk_fail
26  0x00001390 GLOBAL FUNC       EVP_CIPHER_CTX_free
27  0x000013a0 GLOBAL FUNC       fclose
28  0x000013b0 GLOBAL FUNC       bind
29  0x000013c0 GLOBAL FUNC       htonl
30  0x000013d0 GLOBAL FUNC       OPENSSL_init_crypto
31  0x000013e0 GLOBAL FUNC       EVP_EncryptFinal_ex
32  0x000013f0 GLOBAL FUNC       write
33  0x00001400 GLOBAL FUNC       EVP_DecryptUpdate
34  0x00001410 GLOBAL FUNC       accept
35  0x00001420 GLOBAL FUNC       EVP_EncryptInit_ex
36  0x00001430 GLOBAL FUNC       EVP_EncryptUpdate
37  ---------- WEAK   FUNC       __cxa_finalize
```

This binary imports functions like `read`, `write` and `close`, but also
`socket`, `connect` and `accept`, and `OPENSSL_init_crypto`. Therefore, the
binary probably deals with files, opens connections to remote hosts, and uses
cryptographic functions.

## Exports

Now, let's find the list of objects exported by this binary.

```sh
❯ rz-bin -E "/workspace/rev_securedtransfer/securetransfer"
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
❯ rz-bin -z "/workspace/rev_securedtransfer/securetransfer"
```

```
[Strings]
nth paddr      vaddr      len size section type  string                                
---------------------------------------------------------------------------------------
0   0x00002008 0x00002008 16  17   .rodata ascii someinitialvalue
1   0x00002019 0x00002019 29  30   .rodata ascii ERROR: Socket creation failed
2   0x00002038 0x00002038 34  35   .rodata ascii ERROR: Invalid input address '%s'\n
3   0x0000205b 0x0000205b 24  25   .rodata ascii ERROR: Connection failed
4   0x00002078 0x00002078 32  33   .rodata ascii ERROR: Can't open the file '%s'\n
5   0x00002099 0x00002099 21  22   .rodata ascii ERROR: File too small
6   0x000020af 0x000020af 21  22   .rodata ascii ERROR: File too large
7   0x000020c8 0x000020c8 30  31   .rodata ascii ERROR: Failed reading the file
8   0x000020e7 0x000020e7 12  13   .rodata ascii File send...
9   0x000020f4 0x000020f4 25  26   .rodata ascii ERROR: Socket bind failed
10  0x0000210e 0x0000210e 20  21   .rodata ascii ERROR: Listen failed
11  0x00002123 0x00002123 20  21   .rodata ascii ERROR: Accept failed
12  0x00002138 0x00002138 28  29   .rodata ascii ERROR: Reading secret length
13  0x00002158 0x00002158 37  38   .rodata ascii ERROR: File send doesn't match length
14  0x0000217e 0x0000217e 20  21   .rodata ascii File Received...\n%s\n
15  0x00002193 0x00002193 23  24   .rodata ascii Sending File: %s to %s\n
16  0x000021ab 0x000021ab 14  15   .rodata ascii Receiving File
17  0x000021c0 0x000021c0 36  37   .rodata ascii Usage ./securetransfer [<ip> <file>]
```

The last string indicate how to use this binary. It's probably expecting an
optional IP and an optional file. The other strings indicate that the binary
deals with files and sockets.

# Dynamic analysis

Now that we have an idea of what this binary could be doing, let's see what it
really does.

## Execution

After installing OpenSSL version `1.1.1` from
[here](https://github.com/openssl/openssl/releases/tag/OpenSSL_1_1_1s) to have
the `libcrypto.so.1.1` library, let's execute the `securetransfer` binary on
Linux.

```sh
❯ "/workspace/rev_securedtransfer/securetransfer"
```

```
Receiving File
```

Nothing happens.

I also tried to start it with an IP and a file, but I failed to get it working.

# Static analysis

## Decompilation

I'll load `securetransfer` with the default options using Binary Ninja.

As usual, I'll start by exploring the `main` function.

### `main`

```c
int main(int argc, char **argv, char **envp) {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ADD_ALL_CIPHERS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    if (argc == 3) {
        printf("Sending File: %s to %s\n", argv[2], argv[1]);
        sendFile(argv[1], argv[2]);
    } else if (argc != 1) {
        puts("Usage ./securetransfer [<ip> <file>]");
    } else {
        puts("Receiving File");
        receiveFile();
    }
    
    return 0;
}
```

This function initializes OpenSSL crypto, and then either calls `sendFile` or
`receiveFile` depending on the number of arguments provided.

### `sendFile`

```c
int sendFile(char *ipAddress, char *filename) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        puts("ERROR: Socket creation failed");
        return 0;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ipAddress, &serverAddr.sin_addr) <= 0) {
        printf("ERROR: Invalid input address '%s'\n", ipAddress);
        close(fd);
        return 0;
    }

    serverAddr.sin_port = htons(1337);

    if (connect(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        puts("ERROR: Connection failed");
        close(fd);
        return 0;
    }

    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("ERROR: Can't open the file '%s'\n", filename);
        close(fd);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long long int fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize <= 15) {
        puts("ERROR: File too small");
        fclose(fp);
        close(fd);
        return 0;
    } else if (fileSize > 4096) {
        puts("ERROR: File too large");
        fclose(fp);
        close(fd);
        return 0;
    }

    char *fileContent = (char *)malloc(fileSize);
    char *encryptedFileContent = (char *)malloc(fileSize * 2);

    if (fread(fileContent, 1, fileSize, fp) == fileSize) {
        long long int encryptedFileSize =
            encryptData(fileContent, fileSize, encryptedFileContent);

        write(fd, &encryptedFileSize, sizeof(encryptedFileSize));
        write(fd, encryptedFileContent, encryptedFileSize);

        puts("File sent...");

        free(encryptedFileContent);
        free(fileContent);
        fclose(fp);
        close(fd);
        return 1;
    } else {
        puts("ERROR: Failed reading the file");
        free(encryptedFileContent);
        free(fileContent);
        fclose(fp);
        close(fd);
        return 0;
    }
}
```

This function creates a socket and connects to the `ipAddress` on port `1337`.
It then opens the `filename`, and if its content is within a certain range size,
it calls the `encryptData` function on it. Finally, both the size of the
encrypted file and the encrypted file content are sent over the socket.

### `encryptData`

```c
unsigned long long int encryptData(const char *plaintext, int plaintextSize, char *ciphertext) {
    char key[32];
    strncpy(key, "supersecretkeyusedforencryption!", sizeof(key));
    const char *initializationVector = "someinitialvalue";

    EVP_CIPHER_CTX *cipherContext = EVP_CIPHER_CTX_new();
    if (cipherContext == NULL) {
        return 0;
    }

    int ciphertextSize;
    unsigned long long int finalCiphertextSize = 0;

    if (EVP_EncryptInit_ex(cipherContext, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)key,
                           (unsigned char *)initializationVector) != 1) {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    if (EVP_EncryptUpdate(cipherContext, (unsigned char *)ciphertext,
                          &ciphertextSize, (unsigned char *)plaintext,
                          plaintextSize) != 1) {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    finalCiphertextSize += ciphertextSize;

    if (EVP_EncryptFinal_ex(cipherContext,
                            (unsigned char *)ciphertext + ciphertextSize,
                            &ciphertextSize) == 1) {
        finalCiphertextSize += ciphertextSize;
    } else {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipherContext);
    return finalCiphertextSize;
}
```

This function performs an AES-256 encryption in CBC mode. It takes the
`plaintext` content from a memory block along with the `plaintextSize`, and
encrypts it using a key `supersecretkeyusedforencryption` and IV
`someinitialvalue`. The result of the encryption is stored in a `ciphertext`
memory block, and the `ciphertextSize` is returned.

### `receiveFile`

```c
int receiveFile() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        puts("ERROR: Socket creation failed");
        return 0;
    }

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(1337);

    if (bind(fd, (struct sockaddr *)&localAddr, sizeof(localAddr)) != 0) {
        puts("ERROR: Socket bind failed");
        close(fd);
        return 0;
    } else if (listen(fd, 1) != 0) {
        puts("ERROR: Listen failed");
        close(fd);
        return 0;
    }

    struct sockaddr_in clientAddr;
    socklen_t clientAddrLength = sizeof(clientAddr);
    int clientSocket =
        accept(fd, (struct sockaddr *)&clientAddr, &clientAddrLength);
    if (clientSocket < 0) {
        puts("ERROR: Accept failed");
        close(fd);
        return 0;
    }

    unsigned long long int encryptedFileSize;
    if (read(clientSocket, &encryptedFileSize, sizeof(encryptedFileSize)) !=
        sizeof(encryptedFileSize)) {
        puts("ERROR: Reading secret length");
        close(clientSocket);
        close(fd);
        return 0;
    }

    if (encryptedFileSize <= 15) {
        puts("ERROR: File too small");
        close(clientSocket);
        close(fd);
        return 0;
    } else if (encryptedFileSize > 4096) {
        puts("ERROR: File too large");
        close(clientSocket);
        close(fd);
        return 0;
    }

    char *encryptedFileContent = malloc(encryptedFileSize);

    if (read(clientSocket, encryptedFileContent, encryptedFileSize) ==
        encryptedFileSize) {
        close(clientSocket);

        char *fileContent = malloc(encryptedFileSize);
        decryptData(encryptedFileContent, encryptedFileSize, fileContent);

        printf("File Received...\n%s\n", fileContent);
        free(fileContent);
        free(encryptedFileContent);
        close(fd);
        return 1;
    } else {
        puts("ERROR: File send doesn't match length");
        free(encryptedFileContent);
        close(clientSocket);
        close(fd);
        return 0;
    }
}
```

This function creates a socket and binds it to the port `1337`. It then listens
for incoming connections, and reads the size of the encrypted file. If it's
within a certain range, it reads the encrypted file content, calls the
`decryptData` function on it, and prints the decrypted file content.

### `decryptData`

```c
unsigned long long int decryptData(const char *ciphertext, int ciphertextSize, char *plaintext) {
    char key[32];
    strncpy(key, "supersecretkeyusedforencryption!", sizeof(key));
    const char *initializationVector = "someinitialvalue";

    EVP_CIPHER_CTX *cipherContext = EVP_CIPHER_CTX_new();
    if (cipherContext == NULL) {
        return 0;
    }

    int plaintextSize;
    unsigned long long int finalPlaintextSize = 0;

    if (EVP_DecryptInit_ex(cipherContext, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)key,
                           (unsigned char *)initializationVector) != 1) {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    if (EVP_DecryptUpdate(cipherContext, (unsigned char *)plaintext,
                          &plaintextSize, (unsigned char *)ciphertext,
                          ciphertextSize) != 1) {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    finalPlaintextSize += plaintextSize;

    if (EVP_DecryptFinal_ex(cipherContext,
                            (unsigned char *)plaintext + plaintextSize,
                            &plaintextSize) == 1) {
        finalPlaintextSize += plaintextSize;
    } else {
        EVP_CIPHER_CTX_free(cipherContext);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipherContext);
    return finalPlaintextSize;
}
```

This function performs an AES-256 decryption in CBC mode. It takes the
`ciphertext` content from a memory block along with the `ciphertextSize`, and
decrypts it using a key `supersecretkeyusedforencryption` and IV
`someinitialvalue`. The result of the decryption is stored in a `plaintext`
memory block, and the `plaintextSize` is returned.

# Putting it all together

This program can be used either as a client or a server. In both cases, it uses
the port `1337`.

If it's a client, it connects to the server, reads a file, sends `8` bytes to
the server corresponding to the file size, and sends the file content encrypted
with the AES-256 algorithm in CBC mode.

If it's a server, it opens a socket, waits for a connection, reads the first 8
bytes corresponding to the encrypted file size, reads the data up to the
encrypted file size, and saves the file content decrypted with the AES-256
algorithm in CBC mode.

The good news is that the key and IV used for this algorithm are hardcoded, so
we can decrypt any file sent with this program!

If we open `trace.pcap` with Wireshark, we notice a transmission between two
computers:

![Wireshark trace.pcap](wireshark-trace-pcap.png)

This transmission uses the port `1337`, and was in fact made using the
`secured_transfer` program, so we should be able to decrypt the file that has
been sent!

If we inspect the fourth packet, we notice a 'Data' field:

![Wireshark trace.pcap file size](wireshark-trace-pcap-file-size.png)

The data is 8 bytes long, so it corresponds to the file size. Here it's set to
`0x20 0x00 0x00 0x00 0x00 0x00 0x00 0x00`, so the file is `32` bytes long.

The sixth packet also has a 'Data' field:

![Wireshark trace.pcap file content](wireshark-trace-pcap-file-content.png)

The data is `32` bytes long, which corresponds to the file size. Here it's set
to
`0x17 0x27 0x5a 0x3d 0x91 0x63 0xb2 0x79 0x83 0x92 0x81 0x3b 0xf5 0xe6 0x82 0x66 0x57 0xbd 0x11 0x42 0x60 0x76 0xc9 0x10 0xa3 0x8b 0x68 0xc2 0xbc 0xbb 0xd3 0xa5`.

Now let's open [CyberChef](https://gchq.github.io/CyberChef/) and select AES
decrypt with the key set to `supersecretkeyusedforencryption!`, the IV set to
`someinitialvalue` and the mode set to CBC. Next, let's enter the encrypted file
content, and let's cook:

![CyberChef AES Decrypt encrypted flag](cyberchef-aes-decrypt-encrypted-flag.png)

The unencrypted file content is `HTB{3ncRyPt3d_F1LE_tr4nSf3r}`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Easy'. The decompiled code was really close to the
reality, and it was relatively easy to decipher. It was a bit long to explore
the different functions though, but luckily they were not too different. The
annoying part was installing the `libcrypto.so.1.1` library.

Thanks for reading!

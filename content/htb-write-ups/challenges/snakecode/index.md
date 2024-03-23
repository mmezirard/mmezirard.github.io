+++
title = "Snakecode"
date = "2024-03-21"
description = "This is an easy Reversing challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Easy

**Category**: Reversing

**Release date**: 2022-05-27

**Created by**: [Leeky](https://app.hackthebox.com/users/129896)

**Description**: We found this ancient text inscribed on a stone tablet. We
believe it describes the history and technology of a mighty but extinct
civilization, but we can't be certain as it's written in a dead language. Can
you use your specialist knowledge to uncover the truth, and recover their
technology?

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
└── rev_snakecode
    └── chall.pyc

<SNIP>
```

This challenge is comprised of a single file named `chall.pyc`. Based on the
extension, we can infer that it contains Python bytecode.

# Static analysis

Let's start by statically analyzing the `chall.pyc` file using the Rizin
toolkit.

## Properties

Let's inspect the properties of this file.

```sh
❯ rz-bin -I /workspace/rev_snakecode/chall.pyc
```

```
[Info]
arch     pyc
cpu      2.7a2+
baddr    0x00000000
binsz    0x00001619
bintype  pyc
bits     16
retguard false
class    Python byte-compiled file
compiler N/A
dbg_file N/A
endian   LE
hdr.csum N/A
guid     N/A
intrp    N/A
laddr    0x00000000
lang     N/A
machine  Python 2.7a2+ VM (rev edfed0e32cedf3b84c6e999052486a750a3f5bee)
maxopsz  16
minopsz  1
os       any
cc       N/A
pcalign  0
rpath    N/A
subsys   
stripped false
crypto   false
havecode true
va       false
sanitiz  false
static   true
linenum  false
lsyms    false
canary   false
PIE      false
RELROCS  false
NX       false
```

This is a Python version `2.7a2+` bytecode file.

## Strings

Let's retrieve the list of strings contained in this file.

```sh
❯ strings "/workspace/rev_snakecode/chall.pyc"
```

```
YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB
AIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl
c3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK
AAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA
cwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA
base64sz
eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB
CKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh
eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB
CKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1
eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz
8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5
eJxLZmRgYIBhZyAu5gISNQwMWQwMzQwMwRogcT8wWcIKJNJTS5IzIFxmIFGemacBpBjARDE7kLAp
LknJzLMr4QCxcxJzk1IS7cDKQSoAvuUPJw==
eJx1kL1uwkAQhOfOBsxPQZUmL+DOEnWUBghEQQbFIESVglUkY5ECX+lHoMz7Jrt7HCgSOWlGO/rm
1tbtIwBBY1b9zdYYkEFlcRqiAQoWxaginDJhjcUBijNQy+O24jxgfzsHdTxOFB8DtoqPoK7HPcXn
gCPFZ1BfcUGsdMA/lpc/fEqeUBq21Mp0L0rv/3grX/f5aELlbryVYzbXZnub7j42K5dcxslym7vu
Jby/zubrK1pMX9apPLOTraReqe9T3SlWd9ieakfl17OTb36OpFE/CDQDE5vHv7K/FKBNmA==
eJxVj00KAjEMhV+b8Q9040IZT9C9WxHEvRvBC1iFUhhk2sUIIwgexLWn1KQzI9qSl/DlhaZHDSDj
II4tR3ix1IBVyK1GXitImt/0l1JDSSih1rAZfIZyI4x9BRIkeKA8SLeF1Dl9clIHG+c9OakdZ35O
T/o+yiciZI2Hgvpt702Pt925Nx/HFZwSGbIYqaL87FS5aKSIgi5JbZR/F1WTrkZmk4QByypE64p1
ap6X4g8LaaoZ3zFGfzFVE/UBTuovhA==
eJw1zDsKgEAMBNCJilb2drZ7AEuxsbfxBOIHFFkWNqWdF3eyYJEXkgxZcwB/jazYkkdwUeAVCAcV
W3F4MjTt7ISZyWVUS7KEsPtN7cW9e2ddLeKTIXk7gkSsSB91O/2g9uToLBELO0otH2W6Ez8=
eJxdjr0OwjAMhM9J+as6M7HTF0AsiKV7F54ACJUKVaiSjOnEi2MbISQGf4rtu3OuMwBSBVfDFQdG
BhzwMAgNMsER1s58+wJ3Hlm4Ai/z33YGE+A1IrNljnBBtiLYT1ZSf2sr6lMt19u+ZPYQkGDJqA0j
ycfap7+lBT/C2bveJ/UkEQ7KqByTGMbPKNQSpojiPMTEzqNKup2aKlnShramopJW5g2ipyUM
eJxdjTEOglAQRB98iMbEKxhLbkBjaLSwsrHWBEUJCRKULTT5VFzc3W9nMS+zk93ZqwNS1UK1VQ17
RQ0CVcQUsTvljO4vWjEmSIRP8A4PXn3MlHKOea4DlxyzWMsOjXUHK/bpVXb1TWy855kF2gN9SPo2
DD9+At8Zdm4YZorNIFXTFTI335aPS1UWtie28QV3xx4p
eJxtjz8LwjAQxV/S1mrRxcnZKat/qyAuOrv0E4ilIJRS2hsUCg7OfmcvubZTIe/97nKPcHkEADpd
WPWPjYCGj0Kj0fjIfHwVqiWIbzxbJ6SHEleQ1yf8ocQHFLSJqgKN+nTYVUUEGndNCiRG8UY3M7F7
abb7TrAS7AVrQSw4CDaCreBo7CfJPvdy/nZeummZuyY3bHBWh2ynmtJncXaRLLaJem6HaqGiVlMV
6Zn+Azn/L1k=
eJwljr0KAkEMhCf3o2hrIb7BlWIhFiKC1jYWViKHe+qKnHob0GKt7sVNcsV8ZDeTSc45gJ5oINqI
wkkQgTvQAvRdgwmO0BK2xxl+uTUTxBwugUtxT8EZIiHKZ4o21dZE7FLRe4yD+nMLixlchvG+0KU7
PxR6EVjhSVDoKazt86MqG6uasr5WrI3SucCNbJPEp685keIy576aqktThVs3r0kf48s8r4c9Ogaj
L3SnIej8MrDz9aqLXJhPzwMNaURT4R/aUC0X
eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWwNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY
m5SSaAdWDFIBALI0C1U=
eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY
m5SSaAdWDFIBALBMC00=
eJw10EtLw0AUBeAzTWLqo74bML8gSyFdiotm40rEZF+kRyVtCGKmqzar/nHvHBDmfty5c+fBrB2A
iUVuUVkMG4MOnIARGIMJeAKm4BQ8Bc9UsfwcvABn/5VL8Aq81tINeAveKb/Hd47R4WDDTp5j7hEm
R4fsoS4yu+7Vh1e8yEYu5V7WciffZCl/5UpW8l162cuF3Mq1fJSUY5uYhTZFRvfZF+EvfOCnU89X
gdATGFLjafBs+2e1fJShY4jDomvcH1q4K9U=
eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcRQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY
m5SSaAdWDFIBALCJC04=
eJxNzTELwjAQBeCXS4r6TzKJP6DUgruLq0s1S7BKIRkqJP/dd3Hp8D4ex3H3NAA6xjEXJo2kAHeH
alAF1aI6FINg8BIsZxTZdM5lM2/95i2PXCNBPBCvzeubLOR4yvp2bX6bS3P+LyppR/qUQ/wMea99
nt6PMA26l/SKxQ/XGxky
eJwlzLsKwkAQheF/L0afw2qr4AOENOnT2NpEgyDGENgtFHbfPTNrcT6G4cw8DHCQeMkgiWchw81T
DMVSHMWTDdnytGTHu+Ea9G4MAkHPkxXaS9L1t/qrbtXlX1TiUehiml9rn046L9PnPk+99qJ+cewN
xxM9
eJwlzLEKwjAQxvF/rhF9jk6Zig8gXdy7uLq0FqFYRUiGFpJ39y4O34/j+O4eDjhovOaqia2S4e4p
jiKUhuLJjiw8hex5Cbdgd0NQCHaeROnOydZbda9+q+u/aMSjcolpXj59Otm8ju9pHnvrRfvS8AMM
qhM6
eJxLZmRgYABhJiB2BuJiPiBRw8CQwsgglsLEkM3EEKzBDBTyy2QFkplAzKABJkCaSkBEjgZcsJgd
SNgUl6Rk5tmVcIDYOYm5SSmJdmDFIBUAVDAM/Q==
eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcQQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY
m5SSaAdWDFIBAK+VC0o=
eJw1jTELwjAUhC9Jq/0VzhldBAfr4u7i6mYpFFSKCXRJp/7x3rsi5L5Avnsvrx0AS8PcmNQSGSg8
DsWjBJQKS42nxwzMQSog09b/gsrs9AGP6LjhHr3tMfSn7TpH+yebfYtJHGXH7eknTpGAkPbEJeVu
+F5V/Bw1Wpl0B7cCYGsZOw==
eJw1zUEKAjEMBdCfdMQreIRuRwU3Mhv3bjzCDAOCitCAm7rqxU1+cZGX0v408wbAvy5e5eQYUAUm
qAnNHdASvsJLhSVUBpryoPG6Km5ZfPaah/hBnXXf29jbsbdDjl0W2Tdd6IN+6JwdkLJ1zsWW+2vi
/HOMRIklkJ38AF2QGOk=
eJxNjj8LAjEMxV96fz+Fk0NHdT5c3F1cD5c7BEHlsAWXdrov7kuKICS/0LyXpFMP4JcnZrgSEUgM
QXJIDVKLtcHokAWZKvsVUm0eGjr1rC3GCplBW/03Xpy2hM5bj4sXnjh7p4cUz30pO6+fiKouxtn6
y8MehcH4MU7GtydgCB0xhDjfX8ey8mAzrYqyka18AW5IIKw=
Nonet
timet
sleep(
./snake_obf.pyt
snake%
marshalt
typesR
FunctionTypet
loadst
decodet
globalst
wrapper(
./snake_obf.pyt
<module>
```

It contains many Base64 encoded strings, and we notice the use of a
`snake_obf.pyt` file, which might suggest that this file has been obfuscated.

## Decompilation

Let's use [pycdc](https://github.com/zrax/pycdc) to decompile `chall.pyc`.

```sh
❯ pycdc "/workspace/rev_snakecode/chall.pyc"
```

```py
import marshal
import types
import time

ll = types.FunctionType(
    marshal.loads(
        "YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\nAIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\nc3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\nAAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\ncwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n".decode(
            "base64"
        )
    ),
    globals(),
)
i0 = ll(
    "eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n"
)
i1 = ll(
    "eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n"
)
f0 = ll(
    "eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n"
)
f1 = ll(
    "eJxLZmRgYIBhZyAu5gISNQwMWQwMzQwMwRogcT8wWcIKJNJTS5IzIFxmIFGemacBpBjARDE7kLAp\nLknJzLMr4QCxcxJzk1IS7cDKQSoAvuUPJw==\n"
)
f2 = ll(
    "eJx1kL1uwkAQhOfOBsxPQZUmL+DOEnWUBghEQQbFIESVglUkY5ECX+lHoMz7Jrt7HCgSOWlGO/rm\n1tbtIwBBY1b9zdYYkEFlcRqiAQoWxaginDJhjcUBijNQy+O24jxgfzsHdTxOFB8DtoqPoK7HPcXn\ngCPFZ1BfcUGsdMA/lpc/fEqeUBq21Mp0L0rv/3grX/f5aELlbryVYzbXZnub7j42K5dcxslym7vu\nJby/zubrK1pMX9apPLOTraReqe9T3SlWd9ieakfl17OTb36OpFE/CDQDE5vHv7K/FKBNmA==\n"
)
f3 = ll(
    "eJxVj00KAjEMhV+b8Q9040IZT9C9WxHEvRvBC1iFUhhk2sUIIwgexLWn1KQzI9qSl/DlhaZHDSDj\nII4tR3ix1IBVyK1GXitImt/0l1JDSSih1rAZfIZyI4x9BRIkeKA8SLeF1Dl9clIHG+c9OakdZ35O\nT/o+yiciZI2Hgvpt702Pt925Nx/HFZwSGbIYqaL87FS5aKSIgi5JbZR/F1WTrkZmk4QByypE64p1\nap6X4g8LaaoZ3zFGfzFVE/UBTuovhA==\n"
)
f4 = ll(
    "eJw1zDsKgEAMBNCJilb2drZ7AEuxsbfxBOIHFFkWNqWdF3eyYJEXkgxZcwB/jazYkkdwUeAVCAcV\nW3F4MjTt7ISZyWVUS7KEsPtN7cW9e2ddLeKTIXk7gkSsSB91O/2g9uToLBELO0otH2W6Ez8=\n"
)
f5 = ll(
    "eJxdjr0OwjAMhM9J+as6M7HTF0AsiKV7F54ACJUKVaiSjOnEi2MbISQGf4rtu3OuMwBSBVfDFQdG\nBhzwMAgNMsER1s58+wJ3Hlm4Ai/z33YGE+A1IrNljnBBtiLYT1ZSf2sr6lMt19u+ZPYQkGDJqA0j\nycfap7+lBT/C2bveJ/UkEQ7KqByTGMbPKNQSpojiPMTEzqNKup2aKlnShramopJW5g2ipyUM\n"
)
f6 = ll(
    "eJxdjTEOglAQRB98iMbEKxhLbkBjaLSwsrHWBEUJCRKULTT5VFzc3W9nMS+zk93ZqwNS1UK1VQ17\nRQ0CVcQUsTvljO4vWjEmSIRP8A4PXn3MlHKOea4DlxyzWMsOjXUHK/bpVXb1TWy855kF2gN9SPo2\nDD9+At8Zdm4YZorNIFXTFTI335aPS1UWtie28QV3xx4p\n"
)
f7 = ll(
    "eJxtjz8LwjAQxV/S1mrRxcnZKat/qyAuOrv0E4ilIJRS2hsUCg7OfmcvubZTIe/97nKPcHkEADpd\nWPWPjYCGj0Kj0fjIfHwVqiWIbzxbJ6SHEleQ1yf8ocQHFLSJqgKN+nTYVUUEGndNCiRG8UY3M7F7\nabb7TrAS7AVrQSw4CDaCreBo7CfJPvdy/nZeummZuyY3bHBWh2ynmtJncXaRLLaJem6HaqGiVlMV\n6Zn+Azn/L1k=\n"
)
f8 = ll(
    "eJwljr0KAkEMhCf3o2hrIb7BlWIhFiKC1jYWViKHe+qKnHob0GKt7sVNcsV8ZDeTSc45gJ5oINqI\nwkkQgTvQAvRdgwmO0BK2xxl+uTUTxBwugUtxT8EZIiHKZ4o21dZE7FLRe4yD+nMLixlchvG+0KU7\nPxR6EVjhSVDoKazt86MqG6uasr5WrI3SucCNbJPEp685keIy576aqktThVs3r0kf48s8r4c9Ogaj\nL3SnIej8MrDz9aqLXJhPzwMNaURT4R/aUC0X\n"
)
a1 = ll(
    "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWwNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALI0C1U=\n"
)
a2 = ll(
    "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALBMC00=\n"
)
a3 = ll(
    "eJw10EtLw0AUBeAzTWLqo74bML8gSyFdiotm40rEZF+kRyVtCGKmqzar/nHvHBDmfty5c+fBrB2A\niUVuUVkMG4MOnIARGIMJeAKm4BQ8Bc9UsfwcvABn/5VL8Aq81tINeAveKb/Hd47R4WDDTp5j7hEm\nR4fsoS4yu+7Vh1e8yEYu5V7WciffZCl/5UpW8l162cuF3Mq1fJSUY5uYhTZFRvfZF+EvfOCnU89X\ngdATGFLjafBs+2e1fJShY4jDomvcH1q4K9U=\n"
)
a4 = ll(
    "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcRQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALCJC04=\n"
)
a5 = ll(
    "eJxNzTELwjAQBeCXS4r6TzKJP6DUgruLq0s1S7BKIRkqJP/dd3Hp8D4ex3H3NAA6xjEXJo2kAHeH\nalAF1aI6FINg8BIsZxTZdM5lM2/95i2PXCNBPBCvzeubLOR4yvp2bX6bS3P+LyppR/qUQ/wMea99\nnt6PMA26l/SKxQ/XGxky\n"
)
a6 = ll(
    "eJwlzLsKwkAQheF/L0afw2qr4AOENOnT2NpEgyDGENgtFHbfPTNrcT6G4cw8DHCQeMkgiWchw81T\nDMVSHMWTDdnytGTHu+Ea9G4MAkHPkxXaS9L1t/qrbtXlX1TiUehiml9rn046L9PnPk+99qJ+cewN\nxxM9\n"
)
a7 = ll(
    "eJwlzLEKwjAQxvF/rhF9jk6Zig8gXdy7uLq0FqFYRUiGFpJ39y4O34/j+O4eDjhovOaqia2S4e4p\njiKUhuLJjiw8hex5Cbdgd0NQCHaeROnOydZbda9+q+u/aMSjcolpXj59Otm8ju9pHnvrRfvS8AMM\nqhM6\n"
)
a8 = ll(
    "eJxLZmRgYABhJiB2BuJiPiBRw8CQwsgglsLEkM3EEKzBDBTyy2QFkplAzKABJkCaSkBEjgZcsJgd\nSNgUl6Rk5tmVcIDYOYm5SSmJdmDFIBUAVDAM/Q==\n"
)
a9 = ll(
    "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcQQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBAK+VC0o=\n"
)
m0 = ll(
    "eJw1jTELwjAUhC9Jq/0VzhldBAfr4u7i6mYpFFSKCXRJp/7x3rsi5L5Avnsvrx0AS8PcmNQSGSg8\nDsWjBJQKS42nxwzMQSog09b/gsrs9AGP6LjhHr3tMfSn7TpH+yebfYtJHGXH7eknTpGAkPbEJeVu\n+F5V/Bw1Wpl0B7cCYGsZOw==\n"
)
m1 = ll(
    "eJw1zUEKAjEMBdCfdMQreIRuRwU3Mhv3bjzCDAOCitCAm7rqxU1+cZGX0v408wbAvy5e5eQYUAUm\nqAnNHdASvsJLhSVUBpryoPG6Km5ZfPaah/hBnXXf29jbsbdDjl0W2Tdd6IN+6JwdkLJ1zsWW+2vi\n/HOMRIklkJ38AF2QGOk=\n"
)
m2 = ll(
    "eJxNjj8LAjEMxV96fz+Fk0NHdT5c3F1cD5c7BEHlsAWXdrov7kuKICS/0LyXpFMP4JcnZrgSEUgM\nQXJIDVKLtcHokAWZKvsVUm0eGjr1rC3GCplBW/03Xpy2hM5bj4sXnjh7p4cUz30pO6+fiKouxtn6\ny8MehcH4MU7GtydgCB0xhDjfX8ey8mAzrYqyka18AW5IIKw=\n"
)


def snake(w):
    r = i0()
    c = i1()
    f0(w)
    d = (0, 1)
    p = [(5, 5)]
    pl = 1
    s = 0
    l = None
    while None:
        (p, d, pl, l, s, w, c, r) = m2(p, d, pl, l, s, w, c, r)


i1().wrapper(snake)
```

This file is indeed obfuscated. The `ll` function is deserialized from a Base64
string, and is later used to initialize all the functions.

### `ll`

Let's run a script to save the deserialized `ll` data into a `ll.pyc` file:

```py
import marshal

# Decode the base64 encoded data
src = marshal.loads(
    (
        "YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\nAIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\nc3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\nAAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\ncwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n"
    ).decode("base64")
)

# Open a 'll.pyc' file to write the modified bytecode
with open("ll.pyc", "wb") as f:
    # Add Python magic bytes obtained from 'chall.pyc'
    MAGIC_BYTES = [0x03, 0xF3, 0x0D, 0x0A, 0xCE, 0xEA, 0xE5, 0x61]
    # Write the magic bytes to the file
    f.write(bytearray(MAGIC_BYTES))
    # Dump the decoded marshal data into the file
    marshal.dump(src, f)
```

Now let's decompile the `ll.pyc` file:

```sh
❯ pycdc "/workspace/rev_snakecode/ll.pyc"
```

```py
return types.FunctionType(
    marshal.loads(__import__("zlib").decompress(s.decode("base64"))), globals()
)
```

Okay, so the `ll` function uses `zlib` to decompress the Base64 decoded data of
the input, and serializes it.

Knowing how `ll` works, we can write a script to deserialize all the other
functions:

```py
import marshal
import zlib
import base64

# Dictionary containing obfuscated functions with names as keys
OBFUSCATED_FUNCTIONS = {
    "i0": "eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n",
    "i1": "eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n",
    "f0": "eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n",
    "f1": "eJxLZmRgYIBhZyAu5gISNQwMWQwMzQwMwRogcT8wWcIKJNJTS5IzIFxmIFGemacBpBjARDE7kLAp\nLknJzLMr4QCxcxJzk1IS7cDKQSoAvuUPJw==\n",
    "f2": "eJx1kL1uwkAQhOfOBsxPQZUmL+DOEnWUBghEQQbFIESVglUkY5ECX+lHoMz7Jrt7HCgSOWlGO/rm\n1tbtIwBBY1b9zdYYkEFlcRqiAQoWxaginDJhjcUBijNQy+O24jxgfzsHdTxOFB8DtoqPoK7HPcXn\ngCPFZ1BfcUGsdMA/lpc/fEqeUBq21Mp0L0rv/3grX/f5aELlbryVYzbXZnub7j42K5dcxslym7vu\nJby/zubrK1pMX9apPLOTraReqe9T3SlWd9ieakfl17OTb36OpFE/CDQDE5vHv7K/FKBNmA==\n",
    "f3": "eJxVj00KAjEMhV+b8Q9040IZT9C9WxHEvRvBC1iFUhhk2sUIIwgexLWn1KQzI9qSl/DlhaZHDSDj\nII4tR3ix1IBVyK1GXitImt/0l1JDSSih1rAZfIZyI4x9BRIkeKA8SLeF1Dl9clIHG+c9OakdZ35O\nT/o+yiciZI2Hgvpt702Pt925Nx/HFZwSGbIYqaL87FS5aKSIgi5JbZR/F1WTrkZmk4QByypE64p1\nap6X4g8LaaoZ3zFGfzFVE/UBTuovhA==\n",
    "f4": "eJw1zDsKgEAMBNCJilb2drZ7AEuxsbfxBOIHFFkWNqWdF3eyYJEXkgxZcwB/jazYkkdwUeAVCAcV\nW3F4MjTt7ISZyWVUS7KEsPtN7cW9e2ddLeKTIXk7gkSsSB91O/2g9uToLBELO0otH2W6Ez8=\n",
    "f5": "eJxdjr0OwjAMhM9J+as6M7HTF0AsiKV7F54ACJUKVaiSjOnEi2MbISQGf4rtu3OuMwBSBVfDFQdG\nBhzwMAgNMsER1s58+wJ3Hlm4Ai/z33YGE+A1IrNljnBBtiLYT1ZSf2sr6lMt19u+ZPYQkGDJqA0j\nycfap7+lBT/C2bveJ/UkEQ7KqByTGMbPKNQSpojiPMTEzqNKup2aKlnShramopJW5g2ipyUM\n",
    "f6": "eJxdjTEOglAQRB98iMbEKxhLbkBjaLSwsrHWBEUJCRKULTT5VFzc3W9nMS+zk93ZqwNS1UK1VQ17\nRQ0CVcQUsTvljO4vWjEmSIRP8A4PXn3MlHKOea4DlxyzWMsOjXUHK/bpVXb1TWy855kF2gN9SPo2\nDD9+At8Zdm4YZorNIFXTFTI335aPS1UWtie28QV3xx4p\n",
    "f7": "eJxtjz8LwjAQxV/S1mrRxcnZKat/qyAuOrv0E4ilIJRS2hsUCg7OfmcvubZTIe/97nKPcHkEADpd\nWPWPjYCGj0Kj0fjIfHwVqiWIbzxbJ6SHEleQ1yf8ocQHFLSJqgKN+nTYVUUEGndNCiRG8UY3M7F7\nabb7TrAS7AVrQSw4CDaCreBo7CfJPvdy/nZeummZuyY3bHBWh2ynmtJncXaRLLaJem6HaqGiVlMV\n6Zn+Azn/L1k=\n",
    "f8": "eJwljr0KAkEMhCf3o2hrIb7BlWIhFiKC1jYWViKHe+qKnHob0GKt7sVNcsV8ZDeTSc45gJ5oINqI\nwkkQgTvQAvRdgwmO0BK2xxl+uTUTxBwugUtxT8EZIiHKZ4o21dZE7FLRe4yD+nMLixlchvG+0KU7\nPxR6EVjhSVDoKazt86MqG6uasr5WrI3SucCNbJPEp685keIy576aqktThVs3r0kf48s8r4c9Ogaj\nL3SnIej8MrDz9aqLXJhPzwMNaURT4R/aUC0X\n",
    "a1": "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWwNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALI0C1U=\n",
    "a2": "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALBMC00=\n",
    "a3": "eJw10EtLw0AUBeAzTWLqo74bML8gSyFdiotm40rEZF+kRyVtCGKmqzar/nHvHBDmfty5c+fBrB2A\niUVuUVkMG4MOnIARGIMJeAKm4BQ8Bc9UsfwcvABn/5VL8Aq81tINeAveKb/Hd47R4WDDTp5j7hEm\nR4fsoS4yu+7Vh1e8yEYu5V7WciffZCl/5UpW8l162cuF3Mq1fJSUY5uYhTZFRvfZF+EvfOCnU89X\ngdATGFLjafBs+2e1fJShY4jDomvcH1q4K9U=\n",
    "a4": "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcRQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALCJC04=\n",
    "a5": "eJxNzTELwjAQBeCXS4r6TzKJP6DUgruLq0s1S7BKIRkqJP/dd3Hp8D4ex3H3NAA6xjEXJo2kAHeH\nalAF1aI6FINg8BIsZxTZdM5lM2/95i2PXCNBPBCvzeubLOR4yvp2bX6bS3P+LyppR/qUQ/wMea99\nnt6PMA26l/SKxQ/XGxky\n",
    "a6": "eJwlzLsKwkAQheF/L0afw2qr4AOENOnT2NpEgyDGENgtFHbfPTNrcT6G4cw8DHCQeMkgiWchw81T\nDMVSHMWTDdnytGTHu+Ea9G4MAkHPkxXaS9L1t/qrbtXlX1TiUehiml9rn046L9PnPk+99qJ+cewN\nxxM9\n",
    "a7": "eJwlzLEKwjAQxvF/rhF9jk6Zig8gXdy7uLq0FqFYRUiGFpJ39y4O34/j+O4eDjhovOaqia2S4e4p\njiKUhuLJjiw8hex5Cbdgd0NQCHaeROnOydZbda9+q+u/aMSjcolpXj59Otm8ju9pHnvrRfvS8AMM\nqhM6\n",
    "a8": "eJxLZmRgYABhJiB2BuJiPiBRw8CQwsgglsLEkM3EEKzBDBTyy2QFkplAzKABJkCaSkBEjgZcsJgd\nSNgUl6Rk5tmVcIDYOYm5SSmJdmDFIBUAVDAM/Q==\n",
    "a9": "eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcQQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBAK+VC0o=\n",
    "m0": "eJw1jTELwjAUhC9Jq/0VzhldBAfr4u7i6mYpFFSKCXRJp/7x3rsi5L5Avnsvrx0AS8PcmNQSGSg8\nDsWjBJQKS42nxwzMQSog09b/gsrs9AGP6LjhHr3tMfSn7TpH+yebfYtJHGXH7eknTpGAkPbEJeVu\n+F5V/Bw1Wpl0B7cCYGsZOw==\n",
    "m1": "eJw1zUEKAjEMBdCfdMQreIRuRwU3Mhv3bjzCDAOCitCAm7rqxU1+cZGX0v408wbAvy5e5eQYUAUm\nqAnNHdASvsJLhSVUBpryoPG6Km5ZfPaah/hBnXXf29jbsbdDjl0W2Tdd6IN+6JwdkLJ1zsWW+2vi\n/HOMRIklkJ38AF2QGOk=\n",
    "m2": "eJxNjj8LAjEMxV96fz+Fk0NHdT5c3F1cD5c7BEHlsAWXdrov7kuKICS/0LyXpFMP4JcnZrgSEUgM\nQXJIDVKLtcHokAWZKvsVUm0eGjr1rC3GCplBW/03Xpy2hM5bj4sXnjh7p4cUz30pO6+fiKouxtn6\ny8MehcH4MU7GtydgCB0xhDjfX8ey8mAzrYqyka18AW5IIKw=\n",
}

# Iterate through each filename and obfuscated data
for filename, obfuscated_data in OBFUSCATED_FUNCTIONS.items():
    # Open file in binary write mode
    with open(filename + ".pyc", "wb") as f:
        # Decode the base64-encoded string, decompress it using zlib, and load the marshalled data
        decoded_data = base64.b64decode(obfuscated_data)
        decompressed_data = zlib.decompress(decoded_data)
        data_to_write = marshal.loads(decompressed_data)
        # Add Python magic bytes obtained from 'chall.pyc'
        MAGIC_BYTES = [0x03, 0xF3, 0x0D, 0x0A, 0xCE, 0xEA, 0xE5, 0x61]
        # Write the magic bytes to the file
        f.write(bytearray(MAGIC_BYTES))
        # Dump the decoded marshal data into the file
        marshal.dump(data_to_write, f)
```

Now, we can reconstruct the whole source code by decompiling each function.

# Putting it all together

Here's the result of the decompilation:

```py
import random
import curses


def import_random_module():
    return random


def import_curses_module():
    return curses


def set_window_timeout(window):
    return window.timeout(0)


def get_keyboard_input(window):
    return window.getch()


def determine_direction(k, direction):
    if k == -1:
        return direction
    if direction != (0, 1) and k == curses.KEY_UP:
        return (0, -1)
    if direction != (0, -1) and k == curses.KEY_DOWN:
        return (0, 1)
    if direction != (-1, 0) and k == curses.KEY_RIGHT:
        return (1, 0)
    if direction != (1, 0) and k == curses.KEY_LEFT:
        return (-1, 0)
    return None


def calculate_next_position(position, direction):
    next_x = position[-1][0] + direction[0]
    next_y = position[-1][1] + direction[1]
    if next_x > 8:
        next_x = 1
    if next_x < 1:
        next_x = 8
    if next_y > 8:
        next_y = 1
    if next_y < 1:
        next_y = 8
    if (next_x, next_y) in position:
        exit(0)
    return (next_x, next_y)


def update_snake_position(new_position, position, length):
    position.append(new_position)
    return position[len(position) - length :]


def generate_new_food(length, score, position):
    new_length = None
    if length == None and score % 10 == 0:
        new_length = (random.randint(1, 8), random.randint(1, 8))
    if new_length in position:
        score += 1
        new_length = None
    return (new_length, score)


def create_game_board(position, score, length):
    return [
        [display_cell(x, y, position, score, length) for x in range(10)]
        for y in range(10)
    ]


def display_cell(x, y, position, score, length):
    if check_food(x, y, position, length):
        return food_icon(score)
    if check_collision(x, y, position, length):
        return obstacle_icon(score)
    if None(x, y, position, length):
        if generate_bonus_food(score):
            return get_flag(score)
        return " "


def draw_game_screen(window, position, score, length):
    window.clear()
    for i in range(10):
        window.addstr(i, 0, "".join(create_game_board(position, score, length)))

    window.refresh()
    return score + 1


def snake_icon():
    return "+"


def obstacle_icon():
    return "#"


def get_flag(score):
    flag = [
        "H",
        "T",
        "B",
        "{",
        "S",
        "u",
        "P",
        "3",
        "r",
        "_",
        "S",
        "3",
        "C",
        "R",
        "t",
        "_",
        "S",
        "n",
        "4",
        "k",
        "3",
        "c",
        "0",
        "d",
        "3",
        "}",
    ]
    return flag[score / 5 % len(flag)]


def food_icon():
    return "$"


def check_end_game_conditions(x, y):
    (x, y) = 0.0
    if not x == 0 and y == 0 and x == 9:
        pass
    return y == 9


def check_collision(x, y, position):
    (x, y, position) = 0.0
    return (x, y) in position


def check_food(x, y, length):
    (x, y, length) = 0.0
    return (x, y) == length


def generate_bonus_food(score):
    return score % 5 == 0


def main_game_logic(position, score, length, window):
    (new_food_position, score) = generate_new_food(length, score, position)
    draw_game_screen(window, position, score, length)
    return (new_food_position, score, draw_game_screen(window, position, score, length))


def handle_keyboard_input(window, direction, position, length):
    new_direction = determine_direction(get_keyboard_input(window), direction)
    return (
        new_direction,
        update_snake_position(
            calculate_next_position(position, new_direction), position, length
        ),
    )


def snake_game_loop(window):
    random_module = import_random_module()
    curses_module = import_curses_module()
    set_window_timeout(window)
    direction = (0, 1)
    position = [(5, 5)]
    score = 1
    length = None
    while True:
        (
            position,
            direction,
            score,
            length,
            score,
            window,
            curses_module,
            random_module,
        ) = main_game_logic(
            position, direction, score, length, window, curses_module, random_module
        )
        (direction, position) = handle_keyboard_input(
            window, direction, position, length
        )


import_curses_module.wrapper(snake_game_loop)
```

This program is actually an implementation of the Snake game in Python using the
`curses` library.

There's one function in the program that should be here though: `get_flag`,
which does nothing for the game logic and shouldn't even be executed at all.

It does contain a very interesting string broken down into several characters...

```sh
❯ python -c "print(''.join(['H', 'T', 'B', '{', 'S', 'u', 'P', '3', 'r', '_', 'S', '3', 'C', 'R', 't', '_', 'S', 'n', '4', 'k', '3', 'c', '0', 'd', '3', '}']))"
```

```
HTB{SuP3r_S3CRt_Sn4k3c0d3}
```

It's actually the flag, `HTB{SuP3r_S3CRt_Sn4k3c0d3}`!

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Easy'. It was tedious to reconstruct the whole source
code from the .PYC file, since it used a function to instantiate others, and it
required many steps. However, it was rather easy to understand and to perform.

Thanks for reading!

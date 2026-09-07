# A JPEG XL file that shows its own SHA-256

`hashquine.jxl` is a lossless JPEG XL image. It shows the first 10 hex digits
(40 bits) of its own SHA-256 hash.

## Check it

```sh
./verify.sh
```

Or by hand:

```sh
sha256sum hashquine.jxl      # read the first 10 characters
djxl hashquine.jxl out.png   # look at the large orange digits
```

The two agree.

## Why 10 digits and not all 64

A file that shows all 64 digits of its own SHA-256 is out of reach today.

To make one, you must find a file `x` whose picture contains `sha256(x)`. Change
one byte of the file and the whole hash changes. So you cannot compute the
answer. You can only search. A full 256-bit target needs about 2^256 tries.
There is not enough energy in the solar system for that.

Hashquines exist for MD5 and for SHA-1. They do not use search. They use
collision attacks, which are cheap for those two functions. SHA-256 has no known
collision attack, so that road is closed.

What is left is honest brute force on a shorter target. This file does 40 bits.
The search took 6.16e11 tries and 51 minutes on 4 cores, at 203 million tries
per second. The expected count was 1.1e12, so this run was lucky.

```
sha256  894eaf6cb44bb5d4eae09913e15f2e31101abc1582b7fe716ba57dde24e6e9cd
nonce   02000023e5acddd5      (the last 8 bytes of the file)
size    13768 bytes
```

| digits | bits | tries      | time on 4 cores at 200M/s |
| -----: | ---: | ---------: | ------------------------- |
|      8 |   32 |    4.3e9   | 22 seconds                |
|     10 |   40 |    1.1e12  | 1.5 hours                 |
|     12 |   48 |    2.8e14  | 16 days                   |
|     16 |   64 |    1.8e19  | 2900 years                |
|     64 |  256 |    1.2e77  | no                        |

## How it works

1. Choose the digits to draw. Any value works. The cost does not change.
2. Draw them into a picture. Encode the picture to JPEG XL with `cjxl -d 0`
   (lossless).
3. Put the codestream in a JXL container: the signature box, an `ftyp` box, a
   `jxlc` box, and one custom box at the end with the type `nonc`.
4. The `nonc` box holds a short note and an 8-byte nonce. A decoder skips a box
   type it does not know. So the nonce changes the bytes of the file, but not
   one pixel of the picture.
5. Pad the note so the file length is 8 more than a multiple of 64. The nonce
   and the SHA-256 padding then fit in the last compression block.
6. Search the nonce until `sha256(file)` starts with the chosen digits.

Step 5 is what makes the search quick. All the blocks before the nonce are
constant, so the program folds them into a SHA-256 midstate one time at the
start. After that, one try costs one compression function call instead of a hash
of the whole 13 kB file. The AVX-512 searcher does 16 tries at a time and gets
about 200 million tries per second on 4 cores.

## Files

| file          | what it does                                              |
| ------------- | --------------------------------------------------------- |
| `hashquine.jxl` | the result                                              |
| `make.sh`     | builds the whole thing from nothing                        |
| `build.py`    | draws the picture and builds the container template        |
| `search16.c`  | nonce search, AVX-512, 16 lanes                            |
| `search.c`    | nonce search, plain C, for machines without AVX-512        |
| `finish.py`   | puts the nonce in the template and checks the result       |
| `verify.sh`   | prints the hash and decodes the picture                    |

## Build it again

```sh
./make.sh                    # same digits as the file here
./make.sh deadbeefca         # your own digits
./make.sh c0ffee 8           # 6 digits, 8 threads -- fast
```

You need `python3`, `pillow`, `gcc`, and `libjxl-tools` (`cjxl` and `djxl`).

A rebuild with the same digits gives a different nonce, because the search
starts at a different place. The picture stays the same.

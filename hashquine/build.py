#!/usr/bin/env python3
"""Build a JPEG XL file that shows the first N hex digits of its own SHA-256.

The file is a JXL container.  A trailing custom box holds a note and an 8-byte
nonce; decoders skip the box, so the picture does not change when the nonce
changes.  The nonce is then searched until the hash starts with the digits that
are already drawn in the picture.
"""
import binascii, hashlib, struct, subprocess, sys, os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
MONO_R = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

BG   = (14, 16, 22)
FG   = (226, 230, 238)
DIM  = (128, 138, 158)
HOT  = (255, 176, 46)
RULE = (44, 50, 64)


def render(digits, nbits, path):
    W, H = 1120, 620
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    f_title = ImageFont.truetype(MONO, 44)
    f_sub   = ImageFont.truetype(MONO_R, 22)
    f_big   = ImageFont.truetype(MONO, 76)
    f_body  = ImageFont.truetype(MONO_R, 21)
    f_small = ImageFont.truetype(MONO_R, 18)

    def ctr(y, text, font, fill):
        w = d.textlength(text, font=font)
        d.text(((W - w) / 2, y), text, font=font, fill=fill)

    d.rectangle([16, 16, W - 17, H - 17], outline=RULE, width=2)

    ctr(56, "SHA-256 HASHQUINE", f_title, FG)
    ctr(112, "a JPEG XL file that shows the start of its own hash", f_sub, DIM)

    d.line([120, 176, W - 120, 176], fill=RULE, width=2)

    ctr(206, "the first %d bits of sha256(this file) are" % nbits, f_body, FG)
    ctr(258, digits, f_big, HOT)

    d.line([120, 372, W - 120, 372], fill=RULE, width=2)

    ctr(400, "check it yourself:", f_body, DIM)
    ctr(436, "sha256sum hashquine.jxl", f_body, FG)

    ctr(500, "The remaining %d digits are not shown." % (64 - len(digits)), f_small, DIM)
    ctr(526, "Printing all 64 would need a preimage attack", f_small, DIM)
    ctr(552, "on SHA-256, which costs about 2^256 work.", f_small, DIM)
    ctr(578, "This one cost about 2^%d." % nbits, f_small, DIM)

    img.save(path)
    return path


def codestream(png, out):
    subprocess.run(["cjxl", png, out, "-d", "0", "-e", "9", "--quiet"],
                   check=True, capture_output=True)
    return open(out, "rb").read()


def box(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


NOTE = (b"  The 8 bytes at the end of this file are a nonce.  A JPEG XL decoder "
        b"skips this box, so the nonce does not change the picture -- but it does "
        b"change the SHA-256 of the file.  It was searched until the hash started "
        b"with the digits drawn in the picture.  ")


def container(cs):
    sig  = struct.pack(">I", 12) + b"JXL " + b"\x0d\x0a\x87\x0a"
    ftyp = box(b"ftyp", b"jxl \x00\x00\x00\x00jxl ")
    jxlc = box(b"jxlc", cs)
    head = sig + ftyp + jxlc
    # pad so the whole file is 8 bytes past a 64-byte boundary: the nonce plus
    # the SHA-256 padding then fit in one final compression block
    pad = (8 - len(head) - 16) % 64 + 128
    note = (NOTE * 4)[:pad]
    nonc = box(b"nonc", note + b"\x00" * 8)
    return head + nonc


if __name__ == "__main__":
    digits = sys.argv[1]
    nbits = len(digits) * 4
    png = os.path.join(HERE, "frame.png")
    cs_path = os.path.join(HERE, "frame.jxl")
    render(digits, nbits, png)
    cs = codestream(png, cs_path)
    data = container(cs)
    assert len(data) % 64 == 8, len(data) % 64
    open(os.path.join(HERE, "template.jxl"), "wb").write(data)
    print("codestream %d bytes, file %d bytes (%d mod 64)" % (len(cs), len(data), len(data) % 64))

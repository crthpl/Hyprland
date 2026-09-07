#!/usr/bin/env python3
"""Put the found nonce into the template and check the result."""
import hashlib, binascii, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))

def main(digits, nonce_hex):
    data = bytearray(open(os.path.join(HERE, "template.jxl"), "rb").read())
    data[-8:] = binascii.unhexlify(nonce_hex.strip())
    digest = hashlib.sha256(data).hexdigest()
    if not digest.startswith(digits):
        print("MISMATCH: hash is %s, picture shows %s" % (digest, digits))
        return 1
    out = os.path.join(HERE, "hashquine.jxl")
    open(out, "wb").write(data)
    print("wrote %s (%d bytes)" % (out, len(data)))
    print("sha256 = %s" % digest)
    print("picture = %s   <- the first %d digits agree" % (digits, len(digits)))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))

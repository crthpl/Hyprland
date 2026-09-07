#!/bin/sh
# Show the hash of the file, then decode the picture so you can compare.
set -e
cd "$(dirname "$0")"
echo "sha256sum says:"
sha256sum hashquine.jxl
echo
echo "the picture says:"
djxl hashquine.jxl hashquine.png 2>/dev/null
echo "  decoded to hashquine.png -- open it and read the large digits"

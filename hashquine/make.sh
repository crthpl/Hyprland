#!/bin/sh
# Build a JPEG XL file that shows the start of its own SHA-256 hash.
#
#   ./make.sh [hex-prefix] [threads]
#
# The prefix is the digit string that goes into the picture.  Any value works.
# Each added digit multiplies the search cost by 16.
set -e
cd "$(dirname "$0")"

PREFIX=${1:-894eaf6cb4}
THREADS=${2:-$(nproc)}
BITS=$(( ${#PREFIX} * 4 ))

echo "== drawing the picture and building the container"
python3 build.py "$PREFIX"

echo "== building the searcher"
if grep -q avx512f /proc/cpuinfo 2>/dev/null; then
    gcc -O3 -mavx512f -pthread -o searcher search16.c -lm      # 16 tries at a time
else
    gcc -O3 -pthread -o searcher search.c                      # portable fallback
fi

echo "== searching for a nonce (about 2^$BITS hashes)"
NONCE=$(./searcher template.jxl "$PREFIX" "$BITS" "$THREADS")

echo "== writing the result"
python3 finish.py "$PREFIX" "$NONCE"

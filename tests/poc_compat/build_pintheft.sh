#!/usr/bin/env bash
# Build the PinTheft PoC against older/divergent distro UAPI headers.
# Usage (from the PoC directory): build_pintheft.sh <compat-dir>
set -euo pipefail

COMPAT=${1:?compat dir}
SRC=poc.c

# Rename any system struct definition out of the way, then provide the ABI the
# PoC actually uses. This works whether the header has the old layout, the new
# layout, or no clone-buffer struct at all.
awk '
  /#include <linux\/io_uring\.h>/ {
    print "#define io_uring_clone_buffers io_uring_clone_buffers_uapi"
    print
    print "#undef io_uring_clone_buffers"
    print "#include \"io_uring_clone.h\""
    next
  }
  { print }
' "$SRC" > poc_compat.c

exec gcc -O2 -I "$COMPAT" -o exp poc_compat.c

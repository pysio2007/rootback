#!/usr/bin/env bash
# Boot a supplied bzImage under QEMU TCG and prove which kernel is running.
# No KVM required, so this works on GitHub-hosted runners.
set -uo pipefail

KERNEL=''
EXPECT=''
QEMU=${QEMU:-qemu-system-x86_64}
BUSYBOX=${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}
[[ -n $BUSYBOX ]] || BUSYBOX=/bin/busybox
TIMEOUT=${TIMEOUT:-90}
MEM=${MEM:-1024}

usage() {
  cat >&2 <<'EOF'
Usage: tests/qemu_probe.sh --kernel PATH --expect VERSION [--timeout SECONDS]
Requires: qemu-system-x86_64, busybox (static), cpio, gzip.
EOF
}

while (($#)); do
  case $1 in
    --kernel) KERNEL=${2:-}; shift 2 ;;
    --expect) EXPECT=${2:-}; shift 2 ;;
    --timeout) TIMEOUT=${2:-}; shift 2 ;;
    --qemu) QEMU=${2:-}; shift 2 ;;
    --busybox) BUSYBOX=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
[[ -r $KERNEL ]] || { printf 'kernel not readable: %s\n' "$KERNEL" >&2; exit 1; }
[[ -n $EXPECT ]] || { printf '--expect is required\n' >&2; exit 1; }
[[ -n $BUSYBOX && -x $BUSYBOX ]] || { printf 'static busybox not found\n' >&2; exit 1; }
have "$QEMU" || { printf 'qemu not found: %s\n' "$QEMU" >&2; exit 1; }
have cpio || { printf 'cpio not found\n' >&2; exit 1; }
have gzip || { printf 'gzip not found\n' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/rootback-qemu.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT
ROOT="$TMP/root"
LOG="$TMP/serial.log"
mkdir -p "$ROOT"/{bin,proc,sys,dev,tmp}
cp "$BUSYBOX" "$ROOT/bin/busybox"
chmod 755 "$ROOT/bin/busybox"

cat >"$ROOT/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sys /sys 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
echo "ROOTBACK_QEMU_OK $(/bin/busybox uname -r)"
/bin/busybox sync
/bin/busybox poweroff -f 2>/dev/null
EOF
chmod 755 "$ROOT/init"

( cd "$ROOT" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 ) >"$TMP/initrd.cpio.gz"

set +e
timeout "$TIMEOUT" "$QEMU" \
  -m "$MEM" -smp 2 -cpu max \
  -kernel "$KERNEL" -initrd "$TMP/initrd.cpio.gz" \
  -append "console=ttyS0 panic=-1" \
  -nographic -no-reboot >"$LOG" 2>&1
rc=$?
set -e

if tr -d '\r' <"$LOG" | grep -qx "ROOTBACK_QEMU_OK $EXPECT"; then
  printf 'ok   QEMU TCG booted %s (qemu rc=%s)\n' "$EXPECT" "$rc"
  exit 0
fi

printf 'FAIL QEMU did not report %s (qemu rc=%s)\n' "$EXPECT" "$rc" >&2
tail -30 "$LOG" >&2 || true
exit 1

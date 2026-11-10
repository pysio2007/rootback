#!/usr/bin/env bash
# Build a deterministic vulnerable kernel for QEMU TCG tests.
# Usage: build_vuln_kernel.sh [VERSION] [WORKDIR]
# Prints the bzImage path on stdout. Build logs go to stderr.
set -euo pipefail

VERSION=${1:-6.12.80}
WORK=${2:-"$PWD/.kernel"}
MAJOR=${VERSION%%.*}
TARBALL="$WORK/linux-$VERSION.tar.xz"
SRC="$WORK/linux-$VERSION"

mkdir -p "$WORK"

if [[ ! -d $SRC ]]; then
  if [[ ! -f $TARBALL ]]; then
    printf 'downloading linux-%s...\n' "$VERSION" >&2
    curl -fsSL -o "$TARBALL" "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${VERSION}.tar.xz"
  fi
  tar -C "$WORK" -xf "$TARBALL"
fi

cd "$SRC"
make defconfig >&2
scripts/config \
  -e USER_NS -e NET_NS -e MULTIUSER \
  -e CRYPTO_USER_API -e CRYPTO_USER_API_AEAD -e CRYPTO_USER_API_SKCIPHER -e CRYPTO_USER_API_HASH \
  -e CRYPTO_AEAD -e CRYPTO_AES -e CRYPTO_GCM -e CRYPTO_ECB -e CRYPTO_CTR -e CRYPTO_GHASH \
  -e XFRM_USER -e XFRM_ESPINTCP -e INET_ESP -e INET6_ESP -e INET_ESPINTCP -e INET6_ESPINTCP \
  -e NET_SCHED -e NET_CLS_ACT -e NET_ACT_PEDIT -e NET_CLS_MATCHALL \
  -e RDS -e RDS_TCP -e IO_URING -e OVERLAY_FS -e NF_TABLES \
  -e TMPFS -e DEVTMPFS -e DEVTMPFS_MOUNT -e BLK_DEV_INITRD -e RD_GZIP \
  -e PROC_FS -e SYSFS -e BINFMT_ELF -e UNIX -e INET -e IPV6 \
  -e SECCOMP -e EPOLL -e FUTEX -e SIGNALFD -e TIMERFD -e EVENTFD \
  -e SHMEM -e AIO \
  -d DEBUG_INFO -d DEBUG_INFO_BTF -d DEBUG_INFO_DWARF5 -d WERROR \
  -d MODULE_SIG -d SECURITY_LOCKDOWN_LSM \
  --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS "" >&2
make olddefconfig >&2

# Fail loudly if a feature the recipes rely on was dropped by dependency resolution.
missing=()
for sym in CONFIG_USER_NS CONFIG_CRYPTO_USER_API_AEAD CONFIG_CRYPTO_USER_API_SKCIPHER \
           CONFIG_INET_ESPINTCP CONFIG_INET6_ESPINTCP CONFIG_NET_ACT_PEDIT \
           CONFIG_RDS CONFIG_RDS_TCP CONFIG_IO_URING CONFIG_NF_TABLES CONFIG_OVERLAY_FS; do
  grep -q "^${sym}=y" .config || missing+=("$sym")
done
if (( ${#missing[@]} )); then
  printf 'missing required config: %s\n' "${missing[*]}" >&2
  exit 1
fi

printf 'building linux-%s with %s jobs...\n' "$VERSION" "$(nproc)" >&2
make -j"$(nproc)" bzImage >&2
printf '%s\n' "$SRC/arch/x86/boot/bzImage"

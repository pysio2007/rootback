#!/usr/bin/env bash
# Per-CVE CI matrix: deterministic detection fixtures + optional build-only.
# This script never executes a proof-of-concept.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CASES="$ROOT/tests/cases.tsv"
ONLY=''
BUILD_ONLY=0
FAIL=0
PASS=0

usage() {
  cat >&2 <<'EOF'
Usage: tests/cve_matrix.sh [--cve CVE-...] [--build-only]
  --cve         test only one CVE (default: all rows in tests/cases.tsv)
  --build-only  after the vulnerable detection check, fetch/build the auto recipe
EOF
}

while (($#)); do
  case $1 in
    --cve|--only) ONLY=${2:-}; shift 2 ;;
    --build-only) BUILD_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
have jq || { printf 'jq is required\n' >&2; exit 1; }
[[ -r $CASES ]] || { printf 'missing %s\n' "$CASES" >&2; exit 1; }

pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }

write_bin() {
  local path=$1 line=$2 mode=${3:-755}
  printf '#!/bin/sh\nprintf "%%s\\n" %s\n' "$(printf '%q' "$line")" >"$path"
  chmod "$mode" "$path"
}

# run_one ID TOOL VKERNEL PKERNEL VTOOL PTOOL ARCH MODULES USERNS PTRACE KVM NESTED CIFS SCENARIO
run_one() {
  local id=$1 tool=$2 vkernel=$3 pkernel=$4 vtool=$5 ptool=$6
  local arch=$7 modules=$8 userns=$9 ptrace=${10} kvm=${11} nested=${12} cifs=${13} scenario=${14}

  local dir kernel active='' sudo_ver pkexec_ver runc_ver podman_ver docker_ver glibc_ver os_id spl
  dir=$(mktemp -d "${TMPDIR:-/tmp}/rootback-ci.XXXXXX") || { fail "$id: mktemp"; return; }
  mkdir -p "$dir/bin" "$dir/tmp" "$dir/state"

  if [[ $scenario == vuln ]]; then kernel=$vkernel; active=$vtool
  else kernel=$pkernel; active=$ptool; fi

  sudo_ver=1.9.17p2
  pkexec_ver=127
  runc_ver=1.3.6
  podman_ver=5.8.4
  docker_ver=29.7.0
  glibc_ver=2.44
  case $tool in
    sudo)   sudo_ver=$active ;;
    pkexec) pkexec_ver=$active ;;
    runc)   runc_ver=$active ;;
    podman) podman_ver=$active ;;
    docker) docker_ver=$active ;;
    glibc)  glibc_ver=$active ;;
  esac

  os_id=ubuntu
  spl=''
  if [[ $tool == android ]]; then
    os_id=android
    spl=$active
  fi

  write_bin "$dir/bin/sudo"   "Sudo version $sudo_ver" 4755
  write_bin "$dir/bin/pkexec" "pkexec version $pkexec_ver" 4755
  write_bin "$dir/bin/runc"   "runc version $runc_ver"
  write_bin "$dir/bin/podman" "podman version $podman_ver"
  write_bin "$dir/bin/docker" "Docker version $docker_ver, build ci"
  write_bin "$dir/bin/ldd"    "ldd (GNU libc) $glibc_ver"
  write_bin "$dir/bin/su"     "su" 4755
  [[ $cifs == yes ]] && write_bin "$dir/bin/cifs.upcall" "cifs.upcall"

  cat >"$dir/config" <<'EOF'
CONFIG_CRYPTO_USER_API_AEAD=m
CONFIG_INET_ESP=m
CONFIG_INET6_ESP=m
CONFIG_NET_ACT_PEDIT=m
CONFIG_RDS=m
CONFIG_IO_URING=m
CONFIG_CIFS=m
CONFIG_NF_TABLES=m
CONFIG_OVERLAY_FS=m
EOF

  local out="$dir/out.json"
  if ! env \
      ROOTBACK_KERNEL="$kernel" \
      ROOTBACK_ARCH="$arch" \
      ROOTBACK_OS_ID="$os_id" \
      ROOTBACK_ANDROID_SPL="$spl" \
      ROOTBACK_CONFIG="$dir/config" \
      ROOTBACK_MODULES="$modules" \
      ROOTBACK_USERNS="$userns" \
      ROOTBACK_PTRACE_SCOPE="$ptrace" \
      ROOTBACK_KVM="$kvm" \
      ROOTBACK_NESTED="$nested" \
      ROOTBACK_CONTAINER=no \
      ROOTBACK_VM=no \
      ROOTBACK_MODULES_MISSING= \
      PATH="$dir/bin:$PATH" \
      XDG_STATE_HOME="$dir/state" \
      TMPDIR="$dir/tmp" \
      "$ROOT/rootback.sh" scan --json >"$out" 2>"$dir/err"; then
    fail "$id/$scenario: scan failed"; sed -n '1,5p' "$dir/err" >&2
    rm -rf "$dir"; return
  fi

  local state reach conf detail
  state=$(jq -r --arg id "$id" '.[]|select(.id==$id)|.state' "$out")
  reach=$(jq -r --arg id "$id" '.[]|select(.id==$id)|.reachable' "$out")
  conf=$(jq -r --arg id "$id" '.[]|select(.id==$id)|.confidence' "$out")
  detail=$(jq -r --arg id "$id" '.[]|select(.id==$id)|.detail' "$out")

  if [[ $scenario == vuln ]]; then
    if [[ $state == VULNERABLE && $reach != no && ( $conf == high || $conf == medium ) ]]; then
      pass "$id vulnerable fixture ($reach/$conf)"
    else
      fail "$id vulnerable fixture: state=$state reach=$reach conf=$conf detail=$detail"
    fi
  else
    if [[ $state == PATCHED || $state == NOT_AFFECTED ]]; then
      pass "$id patched fixture ($state)"
    else
      fail "$id patched fixture: state=$state detail=$detail"
    fi
  fi

  if [[ $BUILD_ONLY == 1 && $scenario == vuln ]]; then
    local mode
    mode=$(awk -F'|' -v id="$id" '$1==id{print $9}' "$ROOT/catalog/cves.tsv")
    if [[ $mode != auto ]]; then
      fail "$id: --build-only requested for a manual CVE"
    else
      if env \
          ROOTBACK_KERNEL="$kernel" \
          ROOTBACK_ARCH="$arch" \
          ROOTBACK_OS_ID="$os_id" \
          ROOTBACK_ANDROID_SPL="$spl" \
          ROOTBACK_CONFIG="$dir/config" \
          ROOTBACK_MODULES="$modules" \
          ROOTBACK_USERNS="$userns" \
          ROOTBACK_PTRACE_SCOPE="$ptrace" \
          ROOTBACK_KVM="$kvm" \
          ROOTBACK_NESTED="$nested" \
          ROOTBACK_CONTAINER=no \
          ROOTBACK_VM=no \
          PATH="$dir/bin:$PATH" \
          XDG_STATE_HOME="$dir/state" \
          TMPDIR="$dir/tmp" \
          "$ROOT/rootback.sh" exploit "$id" --authorized --yes --include-medium --build-only \
            >"$dir/build.log" 2>&1; then
        pass "$id build-only"
      else
        fail "$id build-only"
        tail -15 "$dir/build.log" >&2 || true
      fi
    fi
  fi

  rm -rf "$dir"
}

while IFS='|' read -r id tool vkernel pkernel vtool ptool arch modules userns ptrace kvm nested cifs; do
  [[ -z $id || $id == \#* ]] && continue
  if [[ -n $ONLY && $id != "$ONLY" ]]; then continue; fi
  run_one "$id" "$tool" "$vkernel" "$pkernel" "$vtool" "$ptool" \
          "$arch" "$modules" "$userns" "$ptrace" "$kvm" "$nested" "$cifs" vuln
  if [[ $BUILD_ONLY == 0 ]]; then
    run_one "$id" "$tool" "$vkernel" "$pkernel" "$vtool" "$ptool" \
            "$arch" "$modules" "$userns" "$ptrace" "$kvm" "$nested" "$cifs" patched
  fi
done <"$CASES"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))

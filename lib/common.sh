#!/usr/bin/env bash
# Shared primitives: logging, version math, kernel/distro introspection.
# This file is sourced; it must not exit the caller.

RB_VERSION="0.1.0"

if [[ -z ${RB_ROOT:-} ]]; then
  RB_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fi
RB_CATALOG="${RB_CATALOG:-$RB_ROOT/catalog/cves.tsv}"

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''
  C_BLUE=''; C_MAGENTA=''; C_CYAN=''
fi

rb_msg()  { printf '%s\n' "$*" >&2; }
rb_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
rb_ok()   { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
rb_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
rb_err()  { printf '%s[-]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
rb_die()  { rb_err "$*"; exit 1; }

rb_have() { command -v "$1" >/dev/null 2>&1; }

rb_find_bin() {
  local name=$1 path
  path=$(type -P "$name" 2>/dev/null || true)
  [[ -n $path ]] || path=$(command -v "$name" 2>/dev/null || true)
  if [[ $path == /* ]]; then printf '%s' "$path"; return 0; fi
  for path in "/run/current-system/sw/bin/$name" "/run/wrappers/bin/$name" \
              "/usr/sbin/$name" "/sbin/$name" "/usr/bin/$name" "/bin/$name"; do
    [[ -x $path ]] && { printf '%s' "$path"; return 0; }
  done
  return 1
}

rb_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# Single-quote a string for POSIX sh.
rb_shquote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

rb_json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g' -e 's/\r//g'
}

# ---------------------------------------------------------------------------
# Version math. Supports 1.2.3, 1.2.3p1, 1.4.0-rc.2, 6.12.90+deb13.1.
# Key format: MMMMM.mmmmm.ppppp.release.extra (fixed width, sortable as text).
# ---------------------------------------------------------------------------
rb_ver_key() {
  local v=${1#v} maj=0 min=0 pat=0 rel=1 extra=0 suffix=''
  if [[ $v =~ ^([0-9]+)(\.([0-9]+))?(\.([0-9]+))?(.*)$ ]]; then
    maj=${BASH_REMATCH[1]}
    min=${BASH_REMATCH[3]:-0}
    pat=${BASH_REMATCH[5]:-0}
    suffix=${BASH_REMATCH[6]}
  else
    printf '00000.00000.00000.1.00000'
    return 0
  fi
  if [[ $suffix =~ ^-rc\.?([0-9]+) ]]; then
    rel=0; extra=${BASH_REMATCH[1]}
  elif [[ $suffix =~ ^p([0-9]+) ]]; then
    rel=1; extra=${BASH_REMATCH[1]}
  fi
  printf '%05d.%05d.%05d.%d.%05d' "$maj" "$min" "$pat" "$rel" "$extra"
}

rb_ver_lt() { [[ $(rb_ver_key "$1") < $(rb_ver_key "$2") ]]; }
rb_ver_le() { ! rb_ver_lt "$2" "$1"; }
rb_ver_gt() { rb_ver_lt "$2" "$1"; }
rb_ver_ge() { ! rb_ver_lt "$1" "$2"; }

# Kernel version: uname -r, or ROOTBACK_KERNEL for tests.
rb_kernel_version() {
  if [[ -n ${ROOTBACK_KERNEL:-} ]]; then
    printf '%s' "$ROOTBACK_KERNEL"
  else
    uname -r
  fi
}

rb_kver_parse() {
  local v=$1
  if [[ $v =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    RB_KMAJ=${BASH_REMATCH[1]}
    RB_KMIN=${BASH_REMATCH[2]}
    RB_KPAT=${BASH_REMATCH[3]}
    return 0
  fi
  return 1
}

# rb_kernel_status KFROM KFIX
# Echoes: VULNERABLE | PATCHED | NOT_AFFECTED | UNKNOWN
# KFIX is a space-separated list; a trailing '+' token is a floor.
rb_kernel_status() {
  local kfrom=$1 kfix=$2 v token fmaj fmin fpat
  v=$(rb_kernel_version)
  rb_kver_parse "$v" || { printf 'UNKNOWN'; return 0; }

  for token in $kfix; do
    [[ $token == *+ ]] || continue
    if rb_ver_ge "$v" "${token%+}"; then
      printf 'PATCHED'; return 0
    fi
  done

  for token in $kfix; do
    [[ $token == *+ ]] && continue
    IFS=. read -r fmaj fmin fpat <<<"$token"
    if [[ $RB_KMAJ == "$fmaj" && $RB_KMIN == "$fmin" ]]; then
      if (( RB_KPAT >= fpat )); then printf 'PATCHED'; else printf 'VULNERABLE'; fi
      return 0
    fi
  done

  if [[ -n $kfrom ]] && rb_ver_lt "$v" "$kfrom"; then
    printf 'NOT_AFFECTED'; return 0
  fi
  printf 'UNKNOWN'
}

# ---------------------------------------------------------------------------
# Local system introspection.
# ---------------------------------------------------------------------------
rb_os_id() {
  if [[ -n ${ROOTBACK_OS_ID:-} ]]; then printf '%s' "$ROOTBACK_OS_ID"; return 0; fi
  local id=''
  if [[ -r /etc/os-release ]]; then
    id=$(sed -n 's/^ID=//p' /etc/os-release | head -1 | tr -d '"')
  fi
  printf '%s' "${id:-unknown}"
}

rb_arch() {
  if [[ -n ${ROOTBACK_ARCH:-} ]]; then printf '%s' "$ROOTBACK_ARCH"; return 0; fi
  uname -m 2>/dev/null || printf 'unknown'
}

rb_config_file() {
  if [[ -n ${ROOTBACK_CONFIG:-} && -r $ROOTBACK_CONFIG ]]; then
    printf '%s' "$ROOTBACK_CONFIG"; return 0
  fi
  if [[ -r /proc/config.gz ]]; then
    printf '/proc/config.gz'; return 0
  fi
  if [[ -r "/boot/config-$(rb_kernel_version)" ]]; then
    printf '/boot/config-%s' "$(rb_kernel_version)"; return 0
  fi
  return 1
}

rb_config_get() {
  local sym=$1 file
  file=$(rb_config_file) || return 1
  case $file in
    *.gz) zgrep -m1 "^${sym}=" "$file" 2>/dev/null | cut -d= -f2- ;;
    *)    grep -m1 "^${sym}=" "$file" 2>/dev/null | cut -d= -f2- ;;
  esac
}

rb_module_symbol() {
  case $1 in
    algif_aead) printf 'CONFIG_CRYPTO_USER_API_AEAD' ;;
    esp4)       printf 'CONFIG_INET_ESP' ;;
    esp6)       printf 'CONFIG_INET6_ESP' ;;
    act_pedit)  printf 'CONFIG_NET_ACT_PEDIT' ;;
    nf_tables)  printf 'CONFIG_NF_TABLES' ;;
    rds)        printf 'CONFIG_RDS' ;;
    cifs)       printf 'CONFIG_CIFS' ;;
    overlay)    printf 'CONFIG_OVERLAY_FS' ;;
    kvm)        printf 'CONFIG_KVM' ;;
    *)          printf '' ;;
  esac
}

# Echoes yes | no | unknown for one module.
rb_module_state() {
  local name=$1 sym cfg line
  if [[ -n ${ROOTBACK_MODULES+x} ]]; then
    local list=",$ROOTBACK_MODULES,"
    if [[ $list == *",$name,"* ]]; then printf 'yes'; else printf 'no'; fi
    return 0
  fi
  sym=$(rb_module_symbol "$name")
  if [[ -n $sym ]]; then
    cfg=$(rb_config_get "$sym" 2>/dev/null || true)
    case $cfg in
      y|m) printf 'yes'; return 0 ;;
      n)   printf 'no';  return 0 ;;
    esac
  fi
  while read -r line; do
    [[ ${line%% *} == "$name" ]] && { printf 'yes'; return 0; }
  done < <(lsmod 2>/dev/null || true)
  if modinfo -F name "$name" >/dev/null 2>&1; then
    printf 'yes'; return 0
  fi
  printf 'unknown'
}

# Spec: "a,b" = all required; "a+b" = any required.
rb_modules_state() {
  local spec=$1 group sub state all_ok=yes any_ok=no seen=0
  local -a groups=() subs=()
  IFS=',' read -r -a groups <<<"$spec"
  for group in "${groups[@]}"; do
    [[ -n $group ]] || continue
    if [[ $group == *+* ]]; then
      IFS='+' read -r -a subs <<<"$group"
      any_ok=no
      for sub in "${subs[@]}"; do
        seen=1
        state=$(rb_module_state "$sub")
        [[ $state == yes ]] && any_ok=yes
        [[ $state == unknown && $any_ok != yes ]] && any_ok=unknown
      done
      if [[ $any_ok != yes ]]; then
        if [[ $any_ok == unknown ]]; then all_ok=unknown; else all_ok=no; fi
      fi
    else
      seen=1
      state=$(rb_module_state "$group")
      case $state in
        no) all_ok=no ;;
        unknown) [[ $all_ok == yes ]] && all_ok=unknown ;;
      esac
    fi
  done
  (( seen )) || { printf 'yes'; return 0; }
  printf '%s' "$all_ok"
}

rb_config_all_state() {
  local spec=$1 sym val result=yes
  local -a syms=()
  IFS=',' read -r -a syms <<<"$spec"
  for sym in "${syms[@]}"; do
    [[ -n $sym ]] || continue
    val=$(rb_config_get "$sym" 2>/dev/null || true)
    case $val in
      y|m) ;;
      n) printf 'no'; return 0 ;;
      *) result=unknown ;;
    esac
  done
  printf '%s' "$result"
}

rb_userns_state() {
  if [[ -n ${ROOTBACK_USERNS:-} ]]; then printf '%s' "$ROOTBACK_USERNS"; return 0; fi
  local max clone restricted unconfined
  max=$(sysctl -n user.max_user_namespaces 2>/dev/null || true)
  clone=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || true)
  restricted=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true)
  unconfined=$(sysctl -n kernel.apparmor_restrict_unprivileged_unconfined 2>/dev/null || true)

  [[ $clone == 0 ]] && { printf 'no'; return 0; }
  [[ $max == 0 ]] && { printf 'no'; return 0; }
  if [[ $restricted == 1 ]]; then
    if [[ $unconfined == 1 ]]; then printf 'no'; else printf 'restricted'; fi
    return 0
  fi
  if [[ -n $max || -n $clone ]]; then printf 'yes'; return 0; fi
  printf 'unknown'
}

rb_container_state() {
  if [[ -n ${ROOTBACK_CONTAINER:-} ]]; then printf '%s' "$ROOTBACK_CONTAINER"; return 0; fi
  [[ -e /.dockerenv || -e /run/.containerenv ]] && { printf 'yes'; return 0; }
  if [[ -r /proc/1/cgroup ]] && grep -qaE '(docker|kubepods|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
    printf 'yes'; return 0
  fi
  printf 'no'
}

rb_vm_state() {
  if [[ -n ${ROOTBACK_VM:-} ]]; then printf '%s' "$ROOTBACK_VM"; return 0; fi
  local v=''
  if rb_have systemd-detect-virt; then
    v=$(systemd-detect-virt 2>/dev/null || true)
    [[ -n $v && $v != none ]] && { printf 'yes'; return 0; }
  fi
  if [[ -r /sys/class/dmi/id/product_name ]]; then
    v=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
    case $v in *KVM*|*VMware*|*VirtualBox*|*QEMU*|*Hyper-V*) printf 'yes'; return 0 ;; esac
  fi
  if grep -qa hypervisor /proc/cpuinfo 2>/dev/null; then printf 'yes'; return 0; fi
  printf 'no'
}

rb_kvm_state() {
  if [[ -n ${ROOTBACK_KVM:-} ]]; then printf '%s' "$ROOTBACK_KVM"; return 0; fi
  [[ -e /dev/kvm ]] && { printf 'yes'; return 0; }
  printf 'no'
}

rb_cmd_version() {
  local cmd=$1 out
  rb_have "$cmd" || { printf ''; return 0; }
  out=$("$cmd" --version 2>/dev/null | head -1 || true)
  # Locale-independent: take the first X.Y.Z token on the first line.
  printf '%s\n' "$out" | grep -oE '[0-9]+(\.[0-9]+){0,2}[0-9A-Za-z.+-]*' | head -1 || true
}

rb_glibc_version() {
  local line v
  line=$(ldd --version 2>/dev/null | head -1 || true)
  v=$(printf '%s\n' "$line" | sed -n 's/.*[^0-9]\([0-9][0-9]*\.[0-9][0-9]*\)$/\1/p')
  [[ -z $v ]] && v=$(printf '%s\n' "$line" | grep -oE '[0-9]+\.[0-9]+$' | head -1 || true)
  printf '%s' "$v"
}

rb_ptrace_scope() {
  if [[ -n ${ROOTBACK_PTRACE_SCOPE:-} ]]; then printf '%s' "$ROOTBACK_PTRACE_SCOPE"; return 0; fi
  sysctl -n kernel.yama.ptrace_scope 2>/dev/null || printf ''
}

rb_audit() {
  local msg=$1 dir
  dir="${XDG_STATE_HOME:-$HOME/.local/state}/rootback"
  mkdir -p "$dir" 2>/dev/null || return 0
  printf '%s\tuid=%s\t%s\n' "$(date -u +%FT%TZ)" "$(id -u)" "$msg" >> "$dir/audit.log" 2>/dev/null || true
  chmod 600 "$dir/audit.log" 2>/dev/null || true
}

rb_preflight_tools() {
  local missing=()
  local tool
  for tool in "$@"; do
    rb_have "$tool" || missing+=("$tool")
  done
  if (( ${#missing[@]} )); then
    rb_die "missing required tool(s): ${missing[*]}"
  fi
}

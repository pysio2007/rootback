#!/usr/bin/env bash
# rootback — local-only root recovery research tool.
# No remote target option exists by design.

set -uo pipefail
umask 077

RB_SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RB_ROOT="$RB_SELF_DIR"

# shellcheck source=lib/common.sh
source "$RB_ROOT/lib/common.sh"
# shellcheck source=lib/catalog.sh
source "$RB_ROOT/lib/catalog.sh"
# shellcheck source=lib/detect.sh
source "$RB_ROOT/lib/detect.sh"
# shellcheck source=lib/reset.sh
source "$RB_ROOT/lib/reset.sh"
# shellcheck source=lib/exploit.sh
source "$RB_ROOT/lib/exploit.sh"

CMD='scan'
RB_AUTHORIZED=0
RB_ALLOW_SSH=0
RB_YES=0
RB_DRY_RUN=0
RB_JSON=0
RB_KEEP=0
RB_NO_FETCH=0
RB_INCLUDE_MEDIUM=0
RB_FORCE=0
RB_BUILD_ONLY=0
RB_FAIL_ON_VULN=0
RB_MARKDOWN=0
RB_HTML=0
RB_CLASS=''
RB_WORK=''
RB_SUCCESS=0
declare -a RB_ARGS=()

usage() {
  cat <<'EOF'
rootback — find a public root path on the machine you own, then reset your password.

Usage:
  ./rootback.sh scan                 detect (default)
  ./rootback.sh list                 show the CVE catalog
  ./rootback.sh exploit [CVE|auto]   run a public recipe (authorization required)
  ./rootback.sh reset                reset a password as root (authorization required)
  ./rootback.sh deps                 show local detection/tooling status

Options:
  --authorized            acknowledge that you own/are authorized on this machine
  --allow-ssh             allow a mutating command over SSH
  --yes                   skip the typed consent phrase (still needs --authorized)
  --dry-run               show the plan; never fetch, build, or execute
  --json                  machine-readable scan output
  --user NAME             account to reset (default: root)
  --password PW           new password (visible in process listings)
  --password-file FILE    read the new password from FILE
  --save-password FILE    write the generated password to FILE (mode 600)
  --poc-dir DIR           use local, audited PoCs instead of fetching
  --no-fetch              refuse network fetches
  --include-medium        allow auto-selection of medium-confidence candidates
  --force                 allow an explicit UNKNOWN/low-confidence candidate
  --build-only            fetch and build the recipe, then stop before execution
  --keep                  keep the temporary workdir after success
  --class CLASS           filter list/scan output (kernel, kvm, container, ...)
  --fail-on-vuln          scan exits 1 if an applicable CVE is found
  --kernel-version VER    test detection against a different kernel string
  --android-spl DATE      override the Android security patch level (YYYY-MM-DD)
  --markdown | --html     render the catalog in that format
  -h, --help              this text
  --version               version

Local-only by construction: there is no host/target argument. The tool reads
uname(1), /proc, installed tool versions, and then — only after explicit consent —
runs public proof-of-concept code against THIS kernel.
EOF
}

banner() {
  cat >&2 <<'EOF'
  ┌──────────────────────────────────────────────────────────────┐
  │  ROOTBACK                                                    │
  │  local kernel triage + public-PoC root recovery              │
  │                                                              │
  │  Authorized machines only. No remote targets. No persistence.│
  │  No credential harvesting. No warranty.                     │
  └──────────────────────────────────────────────────────────────┘
EOF
}

rb_gate() {
  if [[ $RB_AUTHORIZED != 1 ]]; then
    rb_err "authorization not acknowledged"
    rb_msg "Pass --authorized only if you own this machine or have written permission."
    exit 2
  fi
  if [[ -n ${SSH_CONNECTION:-}${SSH_TTY:-} && $RB_ALLOW_SSH != 1 ]]; then
    rb_err "SSH session detected; refusing to change a remote machine by accident"
    rb_msg "Pass --allow-ssh if this is your own host."
    exit 2
  fi
  [[ $RB_DRY_RUN == 1 ]] && return 0
  if [[ $RB_YES != 1 ]]; then
    [[ -t 0 ]] || { rb_err "no TTY for consent; use --yes together with --authorized"; exit 2; }
    printf "Type exactly 'I OWN THIS MACHINE' to continue: " >&2
    local ans=''
    read -r ans || exit 2
    [[ $ans == 'I OWN THIS MACHINE' ]] || { rb_err "consent phrase mismatch"; exit 2; }
  fi
}

rb_workdir() {
  [[ -n $RB_WORK ]] && return 0
  RB_WORK=$(mktemp -d "${TMPDIR:-/tmp}/rootback.XXXXXX") || rb_die "cannot create workdir"
  chmod 700 "$RB_WORK"
}

rb_cleanup_payload() {
  [[ -n ${RB_PAYLOAD:-} ]] && rm -f "$RB_PAYLOAD" 2>/dev/null || true
}
trap rb_cleanup_payload EXIT

rb_scan_cmd() {
  local tmp
  RB_SCAN_FILTER=1
  tmp=$(mktemp "${TMPDIR:-/tmp}/rootback-scan.XXXXXX") || rb_die "mktemp failed"
  rb_scan_collect "$tmp"
  if [[ $RB_JSON == 1 ]]; then
    rb_scan_json "$tmp"
  else
    rb_scan_render "$tmp"
  fi
  if [[ $RB_FAIL_ON_VULN == 1 ]] && awk -F'\t' '$2=="VULNERABLE" && $3!="no"{f=1} END{exit !f}' "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  return 0
}

rb_list_cmd() {
  if [[ $RB_MARKDOWN == 1 ]]; then
    rb_catalog_markdown "$RB_CLASS"
  elif [[ $RB_HTML == 1 ]]; then
    rb_catalog_html "$RB_CLASS"
  else
    rb_catalog_print "$RB_CLASS"
  fi
}

rb_assert_candidate() {
  local id=$1 tmp state reach conf
  tmp=$(mktemp "${TMPDIR:-/tmp}/rootback-cand.XXXXXX") || rb_die "mktemp failed"
  rb_scan_collect "$tmp"
  read -r state reach conf < <(awk -F'\t' -v id="$id" '$1==id{print $2"\t"$3"\t"$4}' "$tmp")
  rm -f "$tmp"
  [[ -n $state ]] || rb_die "unknown CVE: $id"
  if [[ $state != VULNERABLE ]]; then
    rb_die "$id is $state on this host; refusing to run"
  fi
  if [[ $reach == no ]]; then
    rb_die "$id is not reachable on this host; refusing to run"
  fi
  case $conf in
    high) ;;
    medium)
      [[ $RB_INCLUDE_MEDIUM == 1 || $RB_DRY_RUN == 1 ]] && return 0
      rb_warn "$id has medium confidence (vendor backport may be present)"
      if [[ $RB_YES == 1 ]]; then
        rb_die "pass --include-medium to run it non-interactively"
      fi
      rb_confirm "Attempt $id anyway?" || exit 2
      ;;
    *)
      [[ $RB_FORCE == 1 || $RB_DRY_RUN == 1 ]] || rb_die "$id has low confidence; pass --force to override"
      ;;
  esac
}

rb_exploit_cmd() {
  local id=${RB_ARGS[0]:-auto}
  banner
  rb_gate
  rb_workdir
  if [[ $id == auto ]]; then
    rb_exploit_auto
    return $?
  fi
  rb_assert_candidate "$id"
  rb_exploit_id "$id"
}

rb_reset_cmd() {
  banner
  rb_gate
  [[ $(id -u) == 0 ]] || rb_die "reset requires root; use './rootback.sh exploit auto' to get there first"
  rb_workdir
  rb_prepare_payload
  printf '  target : user %s\n' "$RB_USER" >&2
  printf '  payload: %s\n' "$RB_PAYLOAD" >&2
  if [[ $RB_DRY_RUN == 1 ]]; then
    rb_info "dry-run: payload prepared but not executed"
    rm -f "$RB_PAYLOAD"
    [[ $RB_KEEP != 1 ]] && rm -rf "$RB_WORK"
    return 0
  fi
  rb_run_payload
  local rc=$?
  rm -f "$RB_PAYLOAD"
  if (( rc == 0 )); then
    rb_audit "reset success user=$RB_USER kernel=$RB_KERNEL"
    [[ $RB_KEEP != 1 ]] && rm -rf "$RB_WORK"
  else
    rb_audit "reset failed user=$RB_USER kernel=$RB_KERNEL"
    rb_info "workdir kept: $RB_WORK"
  fi
  return $rc
}

rb_deps_cmd() {
  printf 'rootback %s\n' "$RB_VERSION"
  printf 'kernel      : %s\n' "$(rb_kernel_version)"
  printf 'os          : %s\n' "$(rb_os_id)"
  printf 'android     : %s\n' "$(rb_is_android && printf yes || printf no)"
  printf 'android spl : %s\n' "$(rb_android_spl)"
  printf 'arch        : %s\n' "$(rb_arch)"
  printf 'container   : %s\n' "$(rb_container_state)"
  printf 'vm          : %s\n' "$(rb_vm_state)"
  printf 'kvm         : %s\n' "$(rb_kvm_state)"
  printf 'userns      : %s\n' "$(rb_userns_state)"
  printf 'ptrace_scope: %s\n' "$(rb_ptrace_scope)"
  printf 'glibc       : %s\n' "$(rb_glibc_version)"
  printf 'sudo        : %s\n' "$(rb_cmd_version sudo)"
  printf 'pkexec      : %s\n' "$(rb_cmd_version pkexec)"
  printf 'runc        : %s\n' "$(rb_cmd_version runc)"
  printf 'podman      : %s\n' "$(rb_cmd_version podman)"
  local t missing=''
  for t in git gcc make python3 chpasswd base64 openssl getent; do
    if rb_have "$t"; then printf 'tool %-8s: yes\n' "$t"; else printf 'tool %-8s: no\n' "$t"; missing+=" $t"; fi
  done
  [[ -n $missing ]] && printf 'missing     :%s\n' "$missing"
  return 0
}

while (($#)); do
  case $1 in
    scan|exploit|reset|list|deps|version|help) CMD=$1; shift ;;
    --authorized) RB_AUTHORIZED=1; shift ;;
    --allow-ssh) RB_ALLOW_SSH=1; shift ;;
    --yes) RB_YES=1; shift ;;
    --dry-run) RB_DRY_RUN=1; shift ;;
    --json) RB_JSON=1; shift ;;
    --build-only) RB_BUILD_ONLY=1; shift ;;
    --keep) RB_KEEP=1; shift ;;
    --no-fetch) RB_NO_FETCH=1; shift ;;
    --include-medium) RB_INCLUDE_MEDIUM=1; shift ;;
    --force) RB_FORCE=1; shift ;;
    --fail-on-vuln) RB_FAIL_ON_VULN=1; shift ;;
    --markdown) RB_MARKDOWN=1; shift ;;
    --html) RB_HTML=1; shift ;;
    --class) RB_CLASS=${2:-}; shift 2 ;;
    --class=*) RB_CLASS=${1#*=}; shift ;;
    --user) RB_USER=${2:-}; shift 2 ;;
    --user=*) RB_USER=${1#*=}; shift ;;
    --password) RB_PASSWORD=${2:-}; shift 2 ;;
    --password=*) RB_PASSWORD=${1#*=}; shift ;;
    --password-file) RB_PASSWORD_FILE=${2:-}; shift 2 ;;
    --password-file=*) RB_PASSWORD_FILE=${1#*=}; shift ;;
    --save-password) RB_SAVE_PASSWORD=${2:-}; shift 2 ;;
    --save-password=*) RB_SAVE_PASSWORD=${1#*=}; shift ;;
    --poc-dir) RB_POC_DIR_OVERRIDE=${2:-}; shift 2 ;;
    --poc-dir=*) RB_POC_DIR_OVERRIDE=${1#*=}; shift ;;
    --kernel-version) ROOTBACK_KERNEL=${2:-}; shift 2 ;;
    --kernel-version=*) ROOTBACK_KERNEL=${1#*=}; shift ;;
    --android-spl) ROOTBACK_ANDROID_SPL=${2:-}; shift 2 ;;
    --android-spl=*) ROOTBACK_ANDROID_SPL=${1#*=}; shift ;;
    --quiet) RB_QUIET=1; shift ;;
    --no-color) C_RESET=''; C_DIM=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''; shift ;;
    -h|--help) CMD=help; shift ;;
    --version) CMD=version; shift ;;
    -*) rb_die "unknown option: $1" ;;
    *) RB_ARGS+=("$1"); shift ;;
  esac
done

RB_KERNEL=$(rb_kernel_version)

case $CMD in
  scan)    rb_scan_cmd; exit $? ;;
  list)    rb_catalog_load; rb_list_cmd; exit 0 ;;
  exploit) rb_exploit_cmd; exit $? ;;
  reset)   rb_reset_cmd; exit $? ;;
  deps)    rb_deps_cmd; exit 0 ;;
  version) printf 'rootback %s\n' "$RB_VERSION"; exit 0 ;;
  help)    usage; exit 0 ;;
  *)       usage; exit 1 ;;
esac

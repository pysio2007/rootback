#!/usr/bin/env bash
# Password reset payload construction and execution.

RB_USER=${RB_USER:-root}
RB_PASSWORD=${RB_PASSWORD:-}
RB_PASSWORD_FILE=${RB_PASSWORD_FILE:-}
RB_SAVE_PASSWORD=${RB_SAVE_PASSWORD:-}
RB_QUIET=${RB_QUIET:-0}
RB_PW=''
RB_PW_GENERATED=0
RB_NONCE=''
RB_PAYLOAD=''

rb_validate_user() {
  local user=$1
  [[ $user =~ ^[A-Za-z0-9._-]+$ ]] || rb_die "invalid user name: $user"
  getent passwd "$user" >/dev/null 2>&1 || rb_die "no such local user: $user"
}

rb_generate_password() {
  if rb_have openssl; then
    openssl rand -hex 12
  else
    od -An -N12 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

rb_resolve_password() {
  local pw=''
  if [[ -n $RB_PASSWORD ]]; then
    pw=$RB_PASSWORD
    rb_warn "--password is visible in process listings; prefer --password-file or the prompt"
  elif [[ -n $RB_PASSWORD_FILE ]]; then
    [[ -r $RB_PASSWORD_FILE ]] || rb_die "cannot read password file: $RB_PASSWORD_FILE"
    IFS= read -r pw <"$RB_PASSWORD_FILE" || true
    pw=${pw%$'\r'}
  elif [[ -n ${ROOTBACK_PASSWORD:-} ]]; then
    pw=$ROOTBACK_PASSWORD
  else
    pw=$(rb_generate_password)
    RB_PW_GENERATED=1
  fi
  [[ -n $pw ]] || rb_die "empty password"
  [[ $pw != *$'\n'* ]] || rb_die "password must not contain a newline"
  RB_PW=$pw
}

rb_b64() {
  local b
  b=$(rb_find_bin base64) || rb_die "base64 not found"
  printf '%s' "$1" | "$b" | tr -d '\n'
}

rb_prepare_payload() {
  rb_is_android && rb_die "Android: no /etc/shadow or chpasswd; rootback cannot reset a lockscreen credential"
  rb_validate_user "$RB_USER"
  rb_resolve_password
  local chpasswd base64 passwd
  chpasswd=$(rb_find_bin chpasswd) || rb_die "chpasswd not found; install shadow/passwd utilities"
  base64=$(rb_find_bin base64) || rb_die "base64 not found"
  passwd=$(rb_find_bin passwd 2>/dev/null || true)
  mkdir -p "$RB_WORK" || rb_die "cannot create workdir: $RB_WORK"

  local cred b64 work user_q nonce
  cred="$RB_USER:$RB_PW"
  b64=$(rb_b64 "$cred")
  work=$(rb_shquote "$RB_WORK")
  user_q=$(rb_shquote "$RB_USER")
  RB_NONCE=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  nonce=$(rb_shquote "$RB_NONCE")
  RB_PAYLOAD="$RB_WORK/payload.sh"

  {
    printf '%s\n' '#!/bin/sh'
    printf '%s\n' 'set -eu'
    printf '%s\n' '[ "$(id -u)" -eq 0 ] || { echo "rootback: payload is not root" >&2; exit 1; }'
    printf 'printf %%s %s | %s -d | %s\n' \
      "$(rb_shquote "$b64")" "$(rb_shquote "$base64")" "$(rb_shquote "$chpasswd")"
    if [[ -n $passwd ]]; then
      printf '%s -u %s >/dev/null 2>&1 || true\n' "$(rb_shquote "$passwd")" "$user_q"
    fi
    printf 'if command -v getent >/dev/null 2>&1; then h=$(getent shadow %s | cut -d: -f2); else h=$(grep "^%s:" /etc/shadow | cut -d: -f2); fi\n' "$user_q" "$RB_USER"
    printf '%s\n' 'case "$h" in \$*) ;; *) echo "rootback: shadow update failed" >&2; exit 1 ;; esac'
    printf 'printf %%s %s > %s\n' "$(rb_shquote "$RB_NONCE")" "$(rb_shquote "$RB_WORK/root-ok")"
    printf 'chmod 600 %s\n' "$(rb_shquote "$RB_WORK/root-ok")"
    printf 'printf "rootback: password updated for %%s\\n" %s\n' "$user_q"
    printf '%s\n' 'sync'
    printf '%s\n' 'echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true'
  } >"$RB_PAYLOAD"
  chmod 700 "$RB_PAYLOAD"
}

rb_verify_root_marker() {
  local f="$RB_WORK/root-ok" owner value
  [[ -f $f ]] || return 1
  value=$(cat "$f" 2>/dev/null || true)
  [[ $value == "$RB_NONCE" ]] || return 1
  owner=$(stat -c %u "$f" 2>/dev/null || printf 'x')
  [[ $owner == 0 ]] || return 1
  return 0
}

rb_print_password() {
  (( RB_QUIET )) && return 0
  if (( RB_PW_GENERATED )); then
    rb_ok "new password for ${RB_USER}: ${RB_PW}"
  else
    rb_ok "password updated for ${RB_USER}"
  fi
  if [[ -n $RB_SAVE_PASSWORD ]]; then
    umask 077
    printf '%s\n' "$RB_PW" >"$RB_SAVE_PASSWORD" || rb_warn "could not write $RB_SAVE_PASSWORD"
    chmod 600 "$RB_SAVE_PASSWORD" 2>/dev/null || true
    rb_info "password saved to $RB_SAVE_PASSWORD (mode 600)"
  fi
}

rb_run_payload() {
  [[ -f $RB_PAYLOAD ]] || rb_die "payload not prepared"
  sh "$RB_PAYLOAD"
  local rc=$?
  if rb_verify_root_marker; then
    rb_ok "root marker verified (uid=0, nonce match)"
    rb_print_password
    return 0
  fi
  rb_err "payload did not produce a verified root marker"
  return 1
}

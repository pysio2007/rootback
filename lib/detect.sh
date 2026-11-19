#!/usr/bin/env bash
# Detection. Read-only: never loads a module, never writes outside the workdir.

RB_KERNEL=''
RB_STATE='UNKNOWN'
RB_REACH='unknown'
RB_CONF='low'
RB_DETAIL=''

rb_any_suid() {
  local bin
  for bin in /usr/bin/su /bin/su /usr/bin/passwd /bin/passwd /usr/bin/pkexec /usr/bin/sudo /run/wrappers/bin/sudo; do
    [[ -u $bin ]] && return 0
  done
  bin=$(command -v su 2>/dev/null || true)
  [[ -n $bin && -u $bin ]] && return 0
  return 1
}

rb_kernel_max_fix() {
  local kfix=$1 token max=''
  for token in $kfix; do
    [[ $token == *+ ]] && token=${token%+}
    [[ -z $max ]] && { max=$token; continue; }
    rb_ver_gt "$token" "$max" && max=$token
  done
  printf '%s' "$max"
}

rb_check_kernel_generic() {
  local vendor=0 android=0
  rb_is_android && android=1
  if (( android )) && [[ -n ${RB_CUR_ASPL:-} ]]; then
    rb_check_android
    return 0
  fi
  RB_STATE=$(rb_kernel_status "$RB_CUR_KFROM" "$RB_CUR_KFIX")
  RB_REACH='unknown'
  RB_CONF='medium'
  RB_DETAIL="kernel $RB_KERNEL; fix: ${RB_CUR_KFIX:-unknown}"

  case $RB_STATE in
    PATCHED|NOT_AFFECTED)
      RB_REACH='no'
      RB_CONF='high'
      return 0
      ;;
    UNKNOWN)
      # Vendor kernels keep their base version (e.g. Ubuntu 6.8.0-xxx) and
      # backport fixes; they never appear in the upstream stable matrix.
      # Treat a kernel older than the newest known fix as a medium-confidence
      # candidate instead of silently missing it. Newer/EOL lines stay unknown.
      local maxfix
      maxfix=$(rb_kernel_max_fix "$RB_CUR_KFIX")
      if [[ -n $maxfix ]] && rb_ver_lt "$RB_KERNEL" "$maxfix"; then
        RB_STATE='VULNERABLE'; vendor=1
        RB_CONF='medium'
        RB_REACH='unknown'
        RB_DETAIL="kernel $RB_KERNEL is off the upstream stable matrix (newest fix $maxfix); vendor backport unknown"
      else
        RB_REACH='unknown'
        RB_CONF='low'
        RB_DETAIL="kernel $RB_KERNEL is on an unlisted/EOL line; verify the vendor advisory"
        return 0
      fi
      ;;
  esac

  RB_REACH='yes'
  if (( vendor )); then RB_CONF='medium'; else RB_CONF='high'; fi

  if [[ -n $RB_CUR_MODS ]]; then
    local ms
    ms=$(rb_modules_state "$RB_CUR_MODS")
    case $ms in
      no)      RB_REACH='no'; RB_DETAIL+="; required module unavailable (${RB_CUR_MODS})" ;;
      unknown) RB_CONF='medium'; RB_DETAIL+="; module presence unknown (${RB_CUR_MODS})" ;;
    esac
  fi

  if [[ -n $RB_CUR_CONFIG ]]; then
    local cs
    cs=$(rb_config_all_state "$RB_CUR_CONFIG")
    case $cs in
      no)      RB_REACH='no'; RB_DETAIL+="; kernel config disabled (${RB_CUR_CONFIG})" ;;
      unknown) RB_CONF='medium'; RB_DETAIL+="; kernel config unreadable (${RB_CUR_CONFIG})" ;;
    esac
  fi

  if [[ $RB_CUR_USERNS == 1 ]]; then
    if (( android )); then
      RB_REACH='no'
      RB_DETAIL+="; Android app sandbox: unprivileged user namespaces unavailable"
    else
      local us
      us=$(rb_userns_state)
      case $us in
        no)         RB_REACH='no'; RB_DETAIL+="; unprivileged user namespaces disabled" ;;
        restricted) RB_CONF='medium'; RB_DETAIL+="; unprivileged userns restricted (AppArmor)" ;;
        unknown)    RB_CONF='medium'; RB_DETAIL+="; userns state unknown" ;;
      esac
    fi
  fi

  if (( android )) && [[ $RB_STATE == VULNERABLE ]]; then
    RB_CONF='medium'
    RB_DETAIL+="; GKI base version is not a patch level: check ro.build.version.security_patch"
  fi
}

rb_check_kvm() {
  rb_check_kernel_generic
  [[ $RB_STATE == VULNERABLE ]] || return 0

  local arch nested='' n
  arch=$(rb_arch)
  case $RB_ID in
    CVE-2026-89775|CVE-2026-46316)
      [[ $arch == aarch64 || $arch == arm64 ]] || { RB_REACH='no'; RB_DETAIL+="; arm64-only"; return 0; } ;;
    CVE-2026-53359|CVE-2026-64561|CVE-2025-40026|CVE-2026-99312)
      [[ $arch == x86_64 || $arch == amd64 ]] || { RB_REACH='no'; RB_DETAIL+="; x86_64-only"; return 0; } ;;
  esac

  if [[ $(rb_kvm_state) != yes ]]; then
    RB_REACH='no'; RB_DETAIL+="; /dev/kvm not present"; return 0
  fi

  if [[ -n ${ROOTBACK_NESTED:-} ]]; then
    nested=$ROOTBACK_NESTED
  else
    for n in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
      if [[ -r $n ]]; then nested=$(cat "$n" 2>/dev/null || true); break; fi
    done
  fi
  case $nested in
    0|N|n|no)     RB_REACH='no'; RB_DETAIL+="; nested virtualization disabled" ;;
    yes|1|Y|y)    RB_DETAIL+="; /dev/kvm + nested virtualization" ;;
    *)            RB_CONF='medium'; RB_DETAIL+="; nested virtualization state unknown" ;;
  esac

  if [[ $RB_ID == CVE-2026-99312 ]]; then
    local vendor=${ROOTBACK_KVM_VENDOR:-}
    if [[ -z $vendor ]]; then
      if [[ -d /sys/module/kvm_amd ]]; then vendor=amd
      elif [[ -d /sys/module/kvm_intel ]]; then vendor=intel
      else vendor=unknown; fi
    fi
    case $vendor in
      amd) ;;
      intel) RB_REACH='no'; RB_DETAIL+="; kvm_amd not present" ;;
      *)     RB_CONF='medium'; RB_DETAIL+="; KVM vendor unknown (AMD-only bug)" ;;
    esac
  fi
}

rb_check_android() {
  RB_REACH='unknown'
  RB_CONF='medium'
  if ! rb_is_android; then
    RB_STATE='NOT_AFFECTED'
    RB_REACH='no'
    RB_CONF='high'
    RB_DETAIL='not an Android device'
    return 0
  fi
  local spl
  spl=$(rb_android_spl)
  if [[ -z $spl ]]; then
    RB_STATE='UNKNOWN'
    RB_DETAIL='Android device, but ro.build.version.security_patch is unavailable'
    return 0
  fi
  if ! rb_spl_valid "$spl"; then
    RB_STATE='UNKNOWN'
    RB_DETAIL="unparseable Android security patch level: $spl"
    return 0
  fi
  RB_DETAIL="android SPL $spl; fixed at ${RB_CUR_ASPL:-unknown}"
  if [[ -n ${RB_CUR_ASPL:-} && $spl < $RB_CUR_ASPL ]]; then
    RB_STATE='VULNERABLE'
    RB_CONF='high'
    RB_DETAIL+="; ${RB_CUR_PRE:-device-specific path}"
    if [[ ${RB_CUR_USERNS:-0} == 1 ]]; then
      RB_REACH='no'
      RB_DETAIL+='; Android app sandbox: unprivileged userns unavailable'
    fi
  else
    RB_STATE='PATCHED'
    RB_CONF='high'
    RB_REACH='no'
    RB_DETAIL+="; no reachable path"
    return 0
  fi
  if [[ $(getenforce 2>/dev/null || true) == Enforcing ]]; then
    RB_DETAIL+='; SELinux enforcing'
  fi
}

rb_check_cifs() {
  rb_check_kernel_generic
  [[ $RB_STATE == VULNERABLE ]] || return 0
  if rb_find_bin cifs.upcall >/dev/null 2>&1 || [[ -x /usr/sbin/cifs.upcall || -x /sbin/cifs.upcall ]]; then
    RB_DETAIL+="; cifs.upcall present"
  else
    RB_REACH='no'; RB_DETAIL+="; cifs.upcall not installed"
  fi
}

rb_check_ptrace() {
  rb_check_kernel_generic
  [[ $RB_STATE == VULNERABLE ]] || return 0
  local scope
  scope=$(rb_ptrace_scope)
  if [[ -z $scope ]]; then
    RB_REACH='unknown'; RB_CONF='medium'; RB_DETAIL+="; ptrace_scope unavailable"
  elif (( scope < 2 )); then
    RB_DETAIL+="; ptrace_scope=$scope"
  else
    RB_REACH='no'; RB_DETAIL+="; ptrace_scope=$scope blocks the known path"
  fi
}

rb_check_sudo() {
  RB_REACH='no'; RB_CONF='medium'
  local ver bin
  bin=$(rb_find_bin sudo 2>/dev/null || true)
  if [[ -z $bin ]]; then
    RB_STATE='NOT_AFFECTED'; RB_DETAIL='sudo not installed'; return 0
  fi
  ver=$(rb_cmd_version "$bin")
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse sudo version'; return 0
  fi
  RB_DETAIL="sudo $ver"

  if rb_ver_lt "$ver" '1.9.14'; then
    RB_STATE='NOT_AFFECTED'; return 0
  fi
  if rb_ver_lt "$ver" '1.9.17p1'; then
    RB_STATE='VULNERABLE'; RB_CONF='high'
    if [[ -u $bin ]]; then RB_REACH='yes'; else RB_DETAIL+='; sudo is not setuid'; fi
    return 0
  fi
  RB_STATE='PATCHED'; RB_CONF='high'
}

rb_check_pkexec() {
  RB_REACH='no'; RB_CONF='medium'
  local ver bin
  bin=$(rb_find_bin pkexec 2>/dev/null || true)
  if [[ -z $bin ]]; then
    RB_STATE='NOT_AFFECTED'; RB_DETAIL='pkexec not installed'; return 0
  fi
  ver=$(rb_cmd_version "$bin")
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse pkexec version'; return 0
  fi
  RB_DETAIL="pkexec $ver"
  if rb_ver_lt "$ver" '0.121'; then
    RB_STATE='VULNERABLE'
    RB_CONF='medium'
    if [[ -u $bin ]]; then RB_REACH='yes'; else RB_DETAIL+='; pkexec is not setuid'; fi
  else
    RB_STATE='PATCHED'; RB_CONF='high'
  fi
}

rb_check_nginx() {
  RB_REACH='unknown'; RB_CONF='medium'
  local ver bin vout
  bin=$(rb_find_bin nginx 2>/dev/null || true)
  ver=${ROOTBACK_NGINX_VERSION:-}
  if [[ -z $ver ]]; then
    if [[ -z $bin ]]; then
      RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL='nginx not installed'; return 0
    fi
    ver=$(rb_nginx_version "$bin")
  fi
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse nginx version'; return 0
  fi
  RB_DETAIL="nginx $ver; version check only, config not evaluated"

  local first
  case $RB_ID in
    CVE-2026-123007) first='1.9.5' ;;
    CVE-2026-123634) first='1.13.4' ;;
    CVE-2026-123633) first='1.19.7' ;;
    CVE-2026-121810) first='1.25.0' ;;
    CVE-2026-113425) first='0.5.15' ;;
    *)               first='' ;;
  esac
  if [[ -n $first ]] && rb_ver_lt "$ver" "$first"; then
    RB_STATE='NOT_AFFECTED'; RB_CONF='high'; return 0
  fi

  if rb_ver_lt "$ver" '1.30.7' ||
     { rb_ver_ge "$ver" '1.31.0' && rb_ver_lt "$ver" '1.31.9'; }; then
    RB_STATE='VULNERABLE'; RB_CONF='high'
  else
    RB_STATE='PATCHED'; RB_CONF='high'; return 0
  fi

  if [[ $RB_ID == CVE-2026-123007 || $RB_ID == CVE-2026-123633 ]] && [[ -n $bin ]] && [[ -z ${ROOTBACK_NGINX_VERSION:-} ]]; then
    vout=$("$bin" -V 2>&1 || true)
    if [[ -n $vout ]]; then
      if [[ $vout == *--with-http_v2_module* ]]; then
        RB_DETAIL+='; HTTP/2 module present'
      else
        RB_REACH='no'; RB_DETAIL+='; HTTP/2 module absent'
      fi
    else
      RB_CONF='medium'; RB_DETAIL+='; cannot read nginx build flags'
    fi
  fi
}

rb_check_java() {
  RB_REACH='unknown'; RB_CONF='high'
  local ver bin major base patched arch flags f
  bin=$(rb_find_bin java 2>/dev/null || true)
  ver=${ROOTBACK_JAVA_VERSION:-}
  if [[ -z $ver ]]; then
    if [[ -z $bin ]]; then
      RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL='java not installed'; return 0
    fi
    ver=$(rb_java_version "$bin")
  fi
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse java version'; return 0
  fi
  RB_DETAIL="java $ver"
  major=${ver%%.*}
  case $major in
    17|21|25|27) ;;
    *) RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL+='; release line not listed as affected'; return 0 ;;
  esac
  if [[ $major == 17 ]] && rb_ver_lt "$ver" '17.0.6'; then
    RB_STATE='NOT_AFFECTED'; RB_REACH='no'; return 0
  fi
  case $major in
    17) base='17.0.21'; patched='17.0.21.1' ;;
    21) base='21.0.13'; patched='21.0.13.1' ;;
    25) base='25.0.5';  patched='25.0.5.1' ;;
    27) base='27.0.1';  patched='27.0.1.1' ;;
  esac
  if rb_java_ver_ge "$ver" "$patched"; then
    RB_STATE='PATCHED'; return 0
  fi
  if [[ $ver == "$base" || $ver == "$base"+* ]]; then
    RB_STATE='UNKNOWN'; RB_CONF='medium'
    RB_DETAIL+="; vendor build may or may not include the .1 fix"
    return 0
  fi
  RB_STATE='VULNERABLE'

  arch=$(rb_arch)
  if [[ $arch != x86_64 && $arch != amd64 ]]; then
    RB_REACH='no'; RB_DETAIL+="; $arch is not affected (AVX-512 VBMI required)"; return 0
  fi
  if [[ -n ${ROOTBACK_JAVA_CPU_OK:-} ]]; then
    [[ $ROOTBACK_JAVA_CPU_OK == yes ]] || { RB_REACH='no'; RB_DETAIL+='; CPU lacks AVX-512 VBMI'; }
    return 0
  fi
  flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)
  if [[ -z $flags ]]; then
    RB_CONF='medium'; RB_DETAIL+='; CPU flags unavailable'; return 0
  fi
  for f in avx512f avx512bw avx512vbmi bmi2; do
    if [[ $flags != *" $f "* ]]; then
      RB_REACH='no'; RB_DETAIL+="; CPU lacks $f"; return 0
    fi
  done
  RB_DETAIL+='; CPU supports AVX-512 VBMI'
}

rb_check_php() {
  RB_REACH='unknown'; RB_CONF='high'
  local ver bin major minor fixed=''
  bin=$(rb_find_bin php 2>/dev/null || true)
  ver=${ROOTBACK_PHP_VERSION:-}
  if [[ -z $ver ]]; then
    if [[ -z $bin ]]; then
      RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL='php not installed'; return 0
    fi
    ver=$(rb_php_version "$bin")
  fi
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse php version'; return 0
  fi
  RB_DETAIL="php $ver"
  if rb_ver_lt "$ver" '5.4'; then
    RB_STATE='NOT_AFFECTED'; RB_REACH='no'; return 0
  fi
  IFS=. read -r major minor _ <<<"$ver"
  case "$major.$minor" in
    8.2) fixed='8.2.35' ;;
    8.3) fixed='8.3.36' ;;
    8.4) fixed='8.4.27' ;;
    8.5) fixed='8.5.12' ;;
  esac
  if [[ -n $fixed ]]; then
    if rb_ver_ge "$ver" "$fixed"; then
      RB_STATE='PATCHED'; return 0
    fi
    RB_STATE='VULNERABLE'
  elif (( major > 8 || (major == 8 && minor >= 6) )); then
    RB_STATE='UNKNOWN'; RB_CONF='medium'
    RB_DETAIL+='; release line not in the vendor matrix'
  else
    RB_STATE='VULNERABLE'
    RB_DETAIL+='; EOL branch has no official patch'
  fi
}

rb_check_node() {
  RB_REACH='unknown'; RB_CONF='high'
  local ver bin major minor fixed=''
  bin=$(rb_find_bin node 2>/dev/null || true)
  ver=${ROOTBACK_NODE_VERSION:-}
  if [[ -z $ver ]]; then
    if [[ -z $bin ]]; then
      RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL='node not installed'; return 0
    fi
    ver=$(rb_node_version "$bin")
  fi
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot parse node version'; return 0
  fi
  RB_DETAIL="node $ver"
  IFS=. read -r major minor _ <<<"$ver"
  case $major in
    22) fixed='22.23.4' ;;
    24) fixed='24.22.1' ;;
    26) fixed='26.12.1' ;;
  esac
  if [[ -z $fixed ]]; then
    RB_STATE='UNKNOWN'; RB_CONF='medium'
    RB_DETAIL+='; release line not in the vendor matrix'
    return 0
  fi
  if rb_ver_ge "$ver" "$fixed"; then
    RB_STATE='PATCHED'; return 0
  fi
  RB_STATE='VULNERABLE'
  RB_DETAIL+='; bundled Brotli decoder; app must decode untrusted data'
}

rb_check_glibc() {
  RB_REACH='no'; RB_CONF='medium'
  local ver
  ver=$(rb_glibc_version)
  if [[ -z $ver ]]; then
    RB_STATE='UNKNOWN'; RB_DETAIL='cannot determine glibc version'; return 0
  fi
  RB_DETAIL="glibc $ver"
  if rb_ver_ge "$ver" '2.34' && rb_ver_lt "$ver" '2.39'; then
    RB_STATE='VULNERABLE'
    if rb_any_suid; then RB_REACH='yes'; else RB_DETAIL+='; no SUID binary found'; fi
  else
    RB_STATE='NOT_AFFECTED'; RB_CONF='high'
  fi
}

rb_check_runc() {
  RB_REACH='no'; RB_CONF='medium'
  local ver
  ver=$(rb_cmd_version "$(rb_find_bin runc 2>/dev/null || true)")
  if [[ -z $ver ]]; then
    RB_STATE='NOT_AFFECTED'; RB_DETAIL='runc not installed'; return 0
  fi
  RB_DETAIL="runc $ver"
  RB_REACH='unknown'

  local vuln=0
  case $RB_ID in
    CVE-2025-31133)
      if rb_ver_lt "$ver" '1.2.8' ||
         { rb_ver_ge "$ver" '1.3.0-rc.1' && rb_ver_lt "$ver" '1.3.2'; } ||
         { rb_ver_ge "$ver" '1.4.0-rc.1' && rb_ver_lt "$ver" '1.4.0-rc.3'; }; then vuln=1; fi ;;
    CVE-2025-52565)
      if { rb_ver_ge "$ver" '1.0.0-rc3' && rb_ver_lt "$ver" '1.2.8'; } ||
         { rb_ver_ge "$ver" '1.3.0-rc.1' && rb_ver_lt "$ver" '1.3.3'; } ||
         { rb_ver_ge "$ver" '1.4.0-rc.1' && rb_ver_lt "$ver" '1.4.0-rc.3'; }; then vuln=1; fi ;;
    CVE-2025-52881)
      if rb_ver_lt "$ver" '1.2.8' ||
         { rb_ver_ge "$ver" '1.3.0' && rb_ver_lt "$ver" '1.3.3'; } ||
         { rb_ver_ge "$ver" '1.4.0-rc.1' && rb_ver_lt "$ver" '1.4.0-rc.3'; }; then vuln=1; fi ;;
    CVE-2026-41579)
      if rb_ver_lt "$ver" '1.3.6' ||
         { rb_ver_ge "$ver" '1.4.0-rc.1' && rb_ver_lt "$ver" '1.4.3'; } ||
         { rb_ver_ge "$ver" '1.5.0-rc.1' && rb_ver_lt "$ver" '1.5.0-rc.3'; }; then vuln=1; fi ;;
    CVE-2024-21626)
      if rb_ver_lt "$ver" '1.1.12'; then vuln=1; fi ;;
  esac

  if (( vuln )); then
    RB_STATE='VULNERABLE'
    RB_DETAIL+='; requires control over container creation'
  else
    RB_STATE='PATCHED'; RB_CONF='high'
  fi
}

rb_check_podman() {
  RB_REACH='no'; RB_CONF='medium'
  local ver
  ver=$(rb_cmd_version "$(rb_find_bin podman 2>/dev/null || true)")
  if [[ -z $ver ]]; then
    RB_STATE='NOT_AFFECTED'; RB_DETAIL='podman not installed'; return 0
  fi
  RB_DETAIL="podman $ver"
  if rb_ver_ge "$ver" '1.8.1' && rb_ver_lt "$ver" '5.8.4'; then
    RB_STATE='VULNERABLE'; RB_REACH='unknown'
    RB_DETAIL+='; requires a malicious image'
  else
    RB_STATE='PATCHED'; RB_CONF='high'
  fi
}

rb_check_docker() {
  RB_REACH='unknown'; RB_CONF='medium'
  local ver
  ver=$(rb_cmd_version "$(rb_find_bin docker 2>/dev/null || true)")
  if [[ -z $ver ]]; then
    RB_STATE='NOT_AFFECTED'; RB_REACH='no'; RB_DETAIL='docker not installed'; return 0
  fi
  RB_DETAIL="docker $ver"
  if rb_ver_lt "$ver" '29.7.0'; then
    RB_STATE='VULNERABLE'
    RB_DETAIL+='; requires a malicious archive via docker cp'
  else
    RB_STATE='PATCHED'; RB_CONF='high'
  fi
}

rb_run_one_check() {
  RB_STATE='UNKNOWN'; RB_REACH='unknown'; RB_CONF='low'; RB_DETAIL=''
  case $RB_CUR_KIND in
    kernel) rb_check_kernel_generic ;;
    android) rb_check_android ;;
    kvm)    rb_check_kvm ;;
    cifs)   rb_check_cifs ;;
    ptrace) rb_check_ptrace ;;
    sudo)   rb_check_sudo ;;
    pkexec) rb_check_pkexec ;;
    nginx)  rb_check_nginx ;;
    java)   rb_check_java ;;
    php)    rb_check_php ;;
    node)   rb_check_node ;;
    glibc)  rb_check_glibc ;;
    runc)   rb_check_runc ;;
    podman) rb_check_podman ;;
    docker) rb_check_docker ;;
    *)      RB_DETAIL='no detector implemented' ;;
  esac
}

# Writes a TSV: id, state, reachable, confidence, order, detail
rb_scan_collect() {
  local out=$1 id
  : >"$out"
  RB_KERNEL=$(rb_kernel_version)
  rb_catalog_load
  for id in "${RB_IDS[@]}"; do
    rb_catalog_get "$id"
    if [[ ${RB_SCAN_FILTER:-0} == 1 && -n ${RB_CLASS:-} && $RB_CUR_CLASS != "$RB_CLASS" ]]; then
      continue
    fi
    rb_run_one_check
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$RB_ID" "$RB_STATE" "$RB_REACH" "$RB_CONF" "$RB_CUR_ORDER" "$RB_DETAIL" >>"$out"
  done
}

rb_state_color() {
  case $1 in
    VULNERABLE) printf '%s' "$C_RED" ;;
    PATCHED)    printf '%s' "$C_GREEN" ;;
    UNKNOWN)    printf '%s' "$C_YELLOW" ;;
    *)          printf '%s' "$C_DIM" ;;
  esac
}

rb_scan_render() {
  local file=$1 id state reach conf order detail
  printf '%-17s %-9s %-12s %-6s %-7s %s\n' "CVE" "CLASS" "STATE" "REACH" "CONF" "DETAIL"
  local vuln=0
  while IFS=$'\t' read -r id state reach conf order detail; do
    rb_catalog_get "$id"
    [[ $state == VULNERABLE && $reach != no ]] && vuln=$((vuln + 1))
    printf '%-17s %-9s %s%-12s%s %-6s %-7s %s\n' \
      "$id" "$RB_CUR_CLASS" "$(rb_state_color "$state")" "$state" "$C_RESET" \
      "$reach" "$conf" "$detail"
  done <"$file"
  printf '\n'
  if (( vuln )); then
    rb_warn "$vuln CVE(s) look applicable; this is a local heuristic (version or Android SPL), not a vendor patch attestation."
  else
    rb_ok "No applicable CVE detected by this snapshot."
  fi
}

rb_scan_json() {
  local file=$1 id state reach conf order detail first=1
  printf '[\n'
  while IFS=$'\t' read -r id state reach conf order detail; do
    rb_catalog_get "$id"
    (( first )) || printf ',\n'
    first=0
    printf '  {"id":"%s","name":"%s","class":"%s","severity":"%s","state":"%s","reachable":"%s","confidence":"%s","order":%s,"detail":"%s","affected":"%s","fixed":"%s","poc":"%s","mode":"%s"}' \
      "$id" \
      "$(rb_json_escape "$RB_CUR_NAME")" \
      "$RB_CUR_CLASS" "$RB_CUR_SEV" "$state" "$reach" "$conf" "${order:-0}" \
      "$(rb_json_escape "$detail")" \
      "$(rb_json_escape "$RB_CUR_AFFECTED")" \
      "$(rb_json_escape "$RB_CUR_FIXED")" \
      "$(rb_json_escape "$RB_CUR_POC")" \
      "$RB_CUR_MODE"
  done <"$file"
  printf '\n]\n'
}

# Emits: order, rank, id, confidence, detail
rb_auto_candidates() {
  local file=$1 id state reach conf order detail rank
  rb_is_android && return 0
  while IFS=$'\t' read -r id state reach conf order detail; do
    [[ $state == VULNERABLE && $reach != no ]] || continue
    rb_catalog_get "$id"
    [[ $RB_CUR_MODE == auto ]] || continue
    case $conf in
      high) rank=1 ;;
      medium) rank=2 ;;
      *) continue ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\n' "${order:-999}" "$rank" "$id" "$conf" "$detail"
  done <"$file" | sort -t$'\t' -k2,2n -k1,1n
}

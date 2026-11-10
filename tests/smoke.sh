#!/usr/bin/env bash
# Smoke tests: no exploit is ever executed. Safe to run on a patched host.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rootback-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FAIL=0

ok()   { printf 'ok   %s\n' "$*"; }
bad()  { printf 'FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }
check(){ if eval "$1"; then ok "$2"; else bad "$2"; fi; }

cd "$ROOT"

check 'bash -n rootback.sh lib/*.sh tests/*.sh tests/kernel/*.sh' 'shell syntax'
check 'awk -F"|" '"'"'/^[^#]/ && NF!=18 {exit 1}'"'"' catalog/cves.tsv' 'catalog has 18 fields per row'
check '[ "$(grep -vc "^#" catalog/cves.tsv)" -eq 27 ]' 'catalog has 27 entries'
check '[ "$(grep -vc "^#" tests/cases.tsv)" -eq 27 ]' 'case matrix covers 27 CVEs'
check 'awk -F"|" '"'"'/^[^#]/ && NF!=13 {exit 1}'"'"' tests/cases.tsv' 'case matrix has 13 fields per row'

source lib/common.sh
source lib/reset.sh

check 'rb_ver_lt 1.9.17 1.9.17p1' 'version: sudo p-revision ordering'
check 'rb_ver_lt 1.4.0-rc.2 1.4.0' 'version: rc ordering'
check 'rb_ver_ge 6.12.90 6.12.90' 'version: equality'
check 'rb_ver_lt 6.12.90+deb13.1 6.12.94' 'version: distro suffix ignored'
check '[ "$(rb_ver_key 1.2.3)" = "00001.00002.00003.1.00000" ]' 'version: fixed-width key'

check 'ROOTBACK_KERNEL=6.12.80 ./rootback.sh scan --json | jq -e '"'"'any(.[]; .id=="CVE-2026-31431" and .state=="VULNERABLE")'"'"' >/dev/null' 'scan: fake vulnerable kernel'
check 'ROOTBACK_KERNEL=7.3.3 ./rootback.sh scan --json | jq -e '"'"'[.[] | select((.class=="kernel" or .class=="kvm") and .state=="VULNERABLE")] | length == 0'"'"' >/dev/null' 'scan: patched kernel has no kernel CVE'
check 'ROOTBACK_KERNEL=6.12.80 ./rootback.sh scan --json | jq -e '"'"'length == 27'"'"' >/dev/null' 'scan: JSON has 27 records'

out=$(ROOTBACK_KERNEL=6.12.80 ROOTBACK_MODULES=algif_aead ./rootback.sh exploit auto --dry-run --authorized 2>&1)
check 'grep -q "auto-selected CVE-" <<<"$out"' 'auto: selects a candidate'
check 'grep -q "recipe" <<<"$out"' 'auto: prints recipe'

out=$(ROOTBACK_KERNEL=6.12.80 ROOTBACK_MODULES=algif_aead ./rootback.sh exploit CVE-2026-31431 --dry-run --authorized 2>&1)
check 'grep -q "python3 copy_fail_exp.py" <<<"$out"' 'explicit: prints recipe'

./rootback.sh exploit CVE-2026-31431 --dry-run >/dev/null 2>&1
check '[ $? -eq 2 ]' 'gate: refuses without --authorized'

./rootback.sh --host 127.0.0.1 >/dev/null 2>&1
check '[ $? -eq 1 ]' 'gate: no remote target option'

RB_WORK="$TMP/payload"
mkdir -p "$RB_WORK"
RB_USER=root
RB_PASSWORD='test-pass'
rb_prepare_payload >/dev/null 2>&1
check 'sh -n "$RB_PAYLOAD"' 'payload: valid shell'
sh "$RB_PAYLOAD" >/dev/null 2>&1
check '[ $? -eq 1 ]' 'payload: non-root guard exits 1'
check 'grep -q "not root" <(sh "$RB_PAYLOAD" 2>&1)' 'payload: non-root guard message'
rm -rf "$RB_WORK"
RB_WORK='' RB_PAYLOAD=''

check '[ "$(grep -c "<tr><td><code>CVE-" index.html)" -eq 27 ]' 'site: 27 catalog rows'
check '! grep -qi "<script" index.html' 'site: no JavaScript'
check '[ "$(grep -c "^| CVE-" README.md)" -ge 27 ]' 'README: catalog tables present'
check 'grep -q "I OWN THIS MACHINE" README.md index.html' 'docs: consent phrase documented'

printf '\n'
if (( FAIL )); then
  printf '%d test(s) failed\n' "$FAIL"
  exit 1
fi
printf 'all tests passed\n'

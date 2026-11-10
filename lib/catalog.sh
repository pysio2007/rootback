#!/usr/bin/env bash
# Catalog loader and renderers. One TSV is the single source of truth.

RB_IDS=()
declare -A RB_C_NAME=() RB_C_CLASS=() RB_C_SEV=() RB_C_AFFECTED=()
declare -A RB_C_FIXED=() RB_C_PRE=() RB_C_POC=() RB_C_MODE=()
declare -A RB_C_ORDER=() RB_C_KIND=() RB_C_KFROM=() RB_C_KFIX=()
declare -A RB_C_MODS=() RB_C_CONFIG=() RB_C_USERNS=() RB_C_RECIPE=()
declare -A RB_C_NOTES=()

rb_catalog_load() {
  [[ -r $RB_CATALOG ]] || rb_die "catalog not found: $RB_CATALOG"
  RB_IDS=()
  RB_C_NAME=(); RB_C_CLASS=(); RB_C_SEV=(); RB_C_AFFECTED=()
  RB_C_FIXED=(); RB_C_PRE=(); RB_C_POC=(); RB_C_MODE=()
  RB_C_ORDER=(); RB_C_KIND=(); RB_C_KFROM=(); RB_C_KFIX=()
  RB_C_MODS=(); RB_C_CONFIG=(); RB_C_USERNS=(); RB_C_RECIPE=()
  RB_C_NOTES=()
  local id name class sev affected fixed pre poc mode order kind kfrom kfix mods config userns recipe notes
  while IFS='|' read -r id name class sev affected fixed pre poc mode order kind kfrom kfix mods config userns recipe notes; do
    [[ -z $id || $id == \#* ]] && continue
    RB_IDS+=("$id")
    RB_C_NAME[$id]=$name
    RB_C_CLASS[$id]=$class
    RB_C_SEV[$id]=$sev
    RB_C_AFFECTED[$id]=$affected
    RB_C_FIXED[$id]=$fixed
    RB_C_PRE[$id]=$pre
    RB_C_POC[$id]=$poc
    RB_C_MODE[$id]=$mode
    RB_C_ORDER[$id]=$order
    RB_C_KIND[$id]=$kind
    RB_C_KFROM[$id]=$kfrom
    RB_C_KFIX[$id]=$kfix
    RB_C_MODS[$id]=$mods
    RB_C_CONFIG[$id]=$config
    RB_C_USERNS[$id]=$userns
    RB_C_RECIPE[$id]=$recipe
    RB_C_NOTES[$id]=$notes
  done <"$RB_CATALOG"
}

rb_catalog_get() {
  local id=$1
  [[ -n ${RB_C_NAME[$id]+x} ]] || return 1
  RB_ID=$id
  RB_CUR_NAME=${RB_C_NAME[$id]}
  RB_CUR_CLASS=${RB_C_CLASS[$id]}
  RB_CUR_SEV=${RB_C_SEV[$id]}
  RB_CUR_AFFECTED=${RB_C_AFFECTED[$id]}
  RB_CUR_FIXED=${RB_C_FIXED[$id]}
  RB_CUR_PRE=${RB_C_PRE[$id]}
  RB_CUR_POC=${RB_C_POC[$id]}
  RB_CUR_MODE=${RB_C_MODE[$id]}
  RB_CUR_ORDER=${RB_C_ORDER[$id]}
  RB_CUR_KIND=${RB_C_KIND[$id]}
  RB_CUR_KFROM=${RB_C_KFROM[$id]}
  RB_CUR_KFIX=${RB_C_KFIX[$id]}
  RB_CUR_MODS=${RB_C_MODS[$id]}
  RB_CUR_CONFIG=${RB_C_CONFIG[$id]}
  RB_CUR_USERNS=${RB_C_USERNS[$id]}
  RB_CUR_RECIPE=${RB_C_RECIPE[$id]}
  RB_CUR_NOTES=${RB_C_NOTES[$id]}
}

rb_catalog_ids() { printf '%s\n' "${RB_IDS[@]}"; }

rb_html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

rb_catalog_print() {
  local filter=${1:-}
  printf '%-17s %-9s %-8s %-8s %s\n' "CVE" "CLASS" "SEVERITY" "MODE" "NAME"
  local id
  for id in "${RB_IDS[@]}"; do
    [[ -n $filter && ${RB_C_CLASS[$id]} != "$filter" ]] && continue
    printf '%-17s %-9s %-8s %-8s %s\n' \
      "$id" "${RB_C_CLASS[$id]}" "${RB_C_SEV[$id]}" "${RB_C_MODE[$id]}" "${RB_C_NAME[$id]}"
  done
}

rb_catalog_markdown() {
  local filter=${1:-} id
  printf '| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |\n'
  printf '|---|---|---|---|---|---|\n'
  for id in "${RB_IDS[@]}"; do
    [[ -n $filter && ${RB_C_CLASS[$id]} != "$filter" ]] && continue
    printf '| %s | %s | %s | %s | %s | %s |\n' \
      "$id" "${RB_C_NAME[$id]}" "${RB_C_CLASS[$id]}" \
      "${RB_C_AFFECTED[$id]}" "${RB_C_FIXED[$id]}" "${RB_C_MODE[$id]}"
  done
}

rb_catalog_html() {
  local filter=${1:-} id poc
  for id in "${RB_IDS[@]}"; do
    [[ -n $filter && ${RB_C_CLASS[$id]} != "$filter" ]] && continue
    poc=${RB_C_POC[$id]}
    printf '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>' \
      "$id" "$(rb_html_escape "${RB_C_NAME[$id]}")" "$(rb_html_escape "${RB_C_CLASS[$id]}")" \
      "$(rb_html_escape "${RB_C_AFFECTED[$id]}")" "$(rb_html_escape "${RB_C_FIXED[$id]}")" \
      "${RB_C_MODE[$id]}"
    if [[ $poc == http* ]]; then
      printf '<a href="%s">research</a>' "$(rb_html_escape "$poc")"
    else
      printf '%s' "$(rb_html_escape "$poc")"
    fi
    printf '</td></tr>\n'
  done
}

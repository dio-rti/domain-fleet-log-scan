#!/usr/bin/env bash
# fleet-log-scan remote payload scan-v1. Read-only: prints a small TSV on stdout, writes nothing.
# Records: H (header), F (file state), G (group counts). Runs under bash 3.2+ and POSIX awk.
set -u
PV=scan-v1
ROOT=/var/www/domain-0/runtime/logs
ROLE=service
SINCE=0
MAX=52428800
CKS=""
for a in "$@"; do
  case "$a" in
    root=*) ROOT=${a#root=} ;;
    role=*) ROLE=${a#role=} ;;
    since=*) SINCE=${a#since=} ;;
    max=*) MAX=${a#max=} ;;
    ck=*) CKS="$CKS ${a#ck=}" ;;
    *) printf 'H\t%s\tERR\tbad-arg\n' "$PV"; exit 2 ;;
  esac
done
case "$SINCE$MAX" in *[!0-9]*) printf 'H\t%s\tERR\tbad-num\n' "$PV"; exit 2 ;; esac
case "$ROLE" in service|admin|db) ;; *) printf 'H\t%s\tERR\tbad-role\n' "$PV"; exit 2 ;; esac

fst() {
  stat -c '%i %s %Y' -- "$1" 2</dev/null || stat -f '%i %z %m' -- "$1" 2</dev/null
}
gz_usize() { # uncompressed size of a gzip member, or empty
  gzip -l -- "$1" 2</dev/null | awk 'NR==2 && $2 ~ /^[0-9]+$/ { print $2; exit }'
}
tsstr() {
  date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2</dev/null || date -r "$1" '+%Y-%m-%d %H:%M:%S' 2</dev/null
}

AWKPROG=$(cat <<'AWKEOF'
function rpt(c, n,   o, i) { o = ""; for (i = 0; i < n; i++) o = o c; return o }
function rep(s, re, ph,   l, out) {
  out = ""; l = tolower(s)
  while (match(l, re)) {
    if (RLENGTH <= 0) break
    out = out substr(s, 1, RSTART - 1) ph
    s = substr(s, RSTART + RLENGTH); l = substr(l, RSTART + RLENGTH)
  }
  return out s
}
function ip6(s,   out, l, t, n, x, pc, lead) {
  out = ""; l = tolower(s)
  while (match(l, "[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*")) {
    t = substr(l, RSTART, RLENGTH); n = split(t, x, ":") - 1
    pc = RSTART == 1 ? "" : substr(l, RSTART - 1, 1)
    lead = t ~ /^::[0-9a-f]/ && pc !~ /[a-z0-9_]/
    if (!lead && (length(t) < 6 || (n < 3 && (index(t, "::") == 0 || substr(t, 1, 1) == ":")))) {
      out = out substr(s, 1, RSTART + RLENGTH - 1)
    } else {
      out = out substr(s, 1, RSTART - 1) "{ip}"
    }
    s = substr(s, RSTART + RLENGTH); l = substr(l, RSTART + RLENGTH)
  }
  return out s
}
function b64(s,   out, l, t) {
  out = ""; l = tolower(s)
  while (match(l, B64RE)) {
    t = substr(l, RSTART, RLENGTH)
    if (t ~ /[0-9]/ || t ~ /[+=]/) out = out substr(s, 1, RSTART - 1) "{b64}"
    else out = out substr(s, 1, RSTART + RLENGTH - 1)
    s = substr(s, RSTART + RLENGTH); l = substr(l, RSTART + RLENGTH)
  }
  return out s
}
function host(s,   out, l, t, tld, nx) {
  out = ""; l = tolower(s)
  while (match(l, "[a-z0-9-]+(\\.[a-z0-9-]+)*\\.[a-z][a-z]+")) {
    t = substr(l, RSTART, RLENGTH); tld = t; while (index(tld, ".")) tld = substr(tld, index(tld, ".") + 1)
    nx = substr(l, RSTART + RLENGTH, 1)
    if (nx ~ /[a-z0-9_]/ || index(" " EXTS " ", " " tld " ")) out = out substr(s, 1, RSTART + RLENGTH - 1)
    else out = out substr(s, 1, RSTART - 1) "{host}"
    s = substr(s, RSTART + RLENGTH); l = substr(l, RSTART + RLENGTH)
  }
  return out s
}
function phppath(s,   out, t, k, re) {
  out = ""
  re = "(/[A-Za-z0-9_.@-]+)+\\." phpext
  while (match(s, re)) {
    t = substr(s, RSTART, RLENGTH); k = t
    while (index(k, "/")) k = substr(k, index(k, "/") + 1)
    out = out substr(s, 1, RSTART - 1) k
    s = substr(s, RSTART + RLENGTH)
  }
  return out s
}
function nums(s,   out, pre, d, c) {
  out = ""
  while (match(s, "[0-9]+")) {
    pre = substr(s, 1, RSTART - 1); d = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
    c = substr(pre, length(pre), 1)
    if ((c ~ /[A-Za-z_]/ && length(d) <= 2) || substr(pre, length(pre) - 4) == dotphp || (length(d) == 3 && d ~ /^[45]/ && substr(s, 1, 1) !~ /[0-9.]/ && tolower(substr(pre, length(pre) - 13)) ~ /(http|status|code|exception)[^a-z0-9]*$/)) out = out pre d
    else out = out pre "{n}"
  }
  return out s
}
function norm(s) {
  gsub(/\t/, " ", s)
  s = rep(s, "(set-)?cookie[\"' ]*(=\076|=|:).*", "cookie={secret}")
  s = rep(s, "(proxy-)?authorization[\"' ]*(=\076|=|:).*", "authorization={secret}")
  s = rep(s, "(bearer|basic) +(\"[^\"]*\"|'[^']*'|[^],;&\"')]+)", "bearer {token}")
  s = rep(s, "(password|passwd|pwd|secret|token|api_?key|access_?key|_csrf|csrf[a-z_]*|phpsessid|sessid|session_?id|auth|key)[\"' ]*(=\076|=|:) *(\"[^\"]*\"|'[^']*'|[^],;&\"')]+)", "{secret}")
  s = rep(s, JWTRE, "{jwt}")
  s = rep(s, "[a-z][a-z0-9+.-]*://[^] \"'<\076]+", "{url}")
  s = rep(s, "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z][a-z]+", "{email}")
  s = rep(s, UUIDRE, "{uuid}")
  s = ip6(s)
  s = rep(s, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", "{ip}")
  s = host(s)
  s = phppath(s)
  s = rep(s, HEXRE, "{hex}")
  s = b64(s)
  s = nums(s)
  gsub(/[ ]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s)
  if (length(s) <= 200) return s
  return substr(s, 1, 200) "..."
}
function flush(   h, i, f, p, lvl, cat, msg, k) {
  if (!have) return
  have = 0
  if (!(cur_ts <= lastts) || lastts == "") lastts = cur_ts
  nent++
  if (cur_ts < bound) return
  h = cur_head
  for (i = 1; i <= 5; i++) {
    sub(/^ +/, "", h)
    if (substr(h, 1, 1) != "[") return
    p = index(h, "]"); if (p == 0) return
    f[i] = substr(h, 2, p - 2); h = substr(h, p + 1)
  }
  lvl = tolower(f[4]); if (lvl != "error" && lvl != "warning") return
  cat = norm(f[5]); msg = norm(h)
  k = lvl SUBSEP cat SUBSEP msg
  if (!(k in cnt)) { first[k] = cur_ts; cnt[k] = 0 }
  cnt[k]++; last[k] = cur_ts
}
function addtext(t, nl) {
  if (!have) return
  if (nl || nlines == 0) { nlines++; if (nlines == 1) cur_head = t; return }
  if (nlines == 1) cur_head = cur_head t
}
BEGIN {
  TSRE = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] \\["
  HX = "[0-9a-f]"; B = "[a-z0-9+/=_-]"; J = "[a-z0-9_-]"
  UUIDRE = rpt(HX, 8) "-" rpt(HX, 4) "-" rpt(HX, 4) "-" rpt(HX, 4) "-" rpt(HX, 12)
  HEXRE = rpt(HX, 16) HX "*"
  B64RE = rpt(B, 32) B "*"
  JWTRE = "ey" rpt(J, 8) J "*\\." rpt(J, 8) J "*\\." J "*"
  phpext = "p" "hp"
  dotphp = "." phpext ":"
  EXTS = "phtml log js json css html htm txt gz sh xml yml yaml ini conf png jpg jpeg gif svg sql csv md lock tmp bak zip tar twig tpl env pem crt key map vue ts " phpext
  have = 0; nent = 0; lastts = ""
}
{
  s = $0; nl = 1
  while (1) {
    if (match(s, TSRE)) {
      rs = RSTART
      if (rs != 1) addtext(substr(s, 1, rs - 1), nl)
      flush(); have = 1; nlines = 0; cur_head = ""
      cur_ts = substr(s, rs, 19); s = substr(s, rs + 19); nl = 0
    } else { if (s != "" || nl) addtext(s, nl); break }
  }
}
END {
  flush()
  for (k in cnt) {
    split(k, kk, SUBSEP)
    printf "G\t-\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", kk[1], kk[2], kk[3], cnt[k], first[k], last[k], label
  }
  if (lastts == "") lastts = "-"
  printf "F\t%s\ty\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", label, inode, size, size, mtime, lastts, flags, bytes, nent, pl, ps
}
AWKEOF
)

printf 'H\t%s\t%s\t%s\t%s\n' "$PV" "$(date +%s)" "$(date +%z)" "$ROLE"

SINCE_S=$(tsstr "$SINCE")

primaries() {
  local f
  for f in "$ROOT"/app.log "$ROOT"/cron/* "$ROOT"/payment/*; do printf '%s\n' "$f"; done
  if [ "$ROLE" = db ]; then
    for f in "$ROOT"/casino-callback/* "$ROOT"/casino-worker-*.log; do printf '%s\n' "$f"; done
  fi
  if [ "$ROLE" = admin ]; then
    for f in "$ROOT"/admin-sound/*; do printf '%s\n' "$f"; done
  fi
}

ck_for() { # label: prints "inode offset lastts pfxlen pfxsum" or nothing
  local c r
  for c in $CKS; do
    if [ "${c%%:*}" = "$1" ]; then
      r=${c#*:}
      printf '%s\n' "$r" | tr ':' ' '
      return 0
    fi
  done
  return 1
}

pfx() { # file bytes: prints the cksum of the first N bytes
  local r
  r=$(head -c "$2" -- "$1" 2</dev/null | cksum) || return 1
  printf '%s\n' "${r%% *}"
}

SP=(); SS=(); SL=(); SG=()
addseg() { SP[${#SP[@]}]=$1; SS[${#SS[@]}]=$2; SL[${#SL[@]}]=$3; SG[${#SG[@]}]=$4; }
addfile() { # path mode(full|since): adds a whole plain or gz file; returns 1 if absent
  local st uz
  [ -f "$1" ] && [ -r "$1" ] || return 1
  st=$(fst "$1") || return 1
  set -- "$1" "$2" $st
  if [ "$2" = since ] && [ "$5" -lt "$SINCE" ]; then return 0; fi
  case "$1" in
    *.gz)
      uz=$(gz_usize "$1")
      case "$uz" in ''|*[!0-9]*) uz=$((MAX + 1)) ;; esac
      addseg "$1" 0 "$uz" 1
      ;;
    *) addseg "$1" 0 "$4" 0 ;;
  esac
}

scan_one() {
  local f=$1 label=${1#"$ROOT"/} st ino sz mt ck cino coff clast cpl cps flags="" i k bound="$SINCE_S" total keep j skipped=0 bytes=0 sst npl nps
  case "$label" in *[!A-Za-z0-9._/-]*) return ;; esac
  if [ ! -e "$f" ]; then
    [ "$label" = app.log ] && printf 'F\t%s\tn\t-\t-\t-\t-\t-\tmissing\t0\t0\t0\t-\n' "$label"
    return
  fi
  if [ ! -r "$f" ] || [ -d "$f" ]; then
    [ -d "$f" ] || printf 'F\t%s\tn\t-\t-\t-\t-\t-\tunreadable\t0\t0\t0\t-\n' "$label"
    return
  fi
  st=$(fst "$f") || { printf 'F\t%s\tn\t-\t-\t-\t-\t-\tunreadable\t0\t0\t0\t-\n' "$label"; return; }
  set -- $st; ino=$1; sz=$2; mt=$3
  SP=(); SS=(); SL=(); SG=()
  if ck=$(ck_for "$label"); then
    set -- $ck; cino=${1:-0}; coff=${2:-0}; clast=${3:-0}; cpl=${4:-0}; cps=${5:--}
    case "$cino$coff$clast$cpl" in *[!0-9]*) cino=0; coff=0; clast=0; cpl=0 ;; esac
    bound=""
    if [ "$cino" = "$ino" ]; then
      if [ "$sz" -lt "$coff" ]; then flags=truncated; addseg "$f" 0 "$sz" 0
      elif [ "$cpl" -gt 0 ] && [ "$sz" -ge "$cpl" ] && [ "$(pfx "$f" "$cpl")" != "$cps" ]; then flags=truncated; addseg "$f" 0 "$sz" 0
      else addseg "$f" "$coff" $((sz - coff)) 0; fi
    else
      k=0
      for i in 1 2 3 4 5 6 7 8 9; do
        [ -f "$f.$i" ] || continue
        sst=$(fst "$f.$i") || continue
        set -- $sst
        if [ "$1" = "$cino" ]; then k=$i; break; fi
      done
      if [ "$k" -gt 0 ]; then
        flags=rotated
        sst=$(fst "$f.$k")
        set -- $sst
        if [ "$2" -ge "$coff" ]; then addseg "$f.$k" "$coff" $(($2 - coff)) 0
        else flags=rotated,truncated; addseg "$f.$k" 0 "$2" 0; fi
        i=$((k - 1))
        while [ "$i" -ge 1 ]; do
          addfile "$f.$i" full || addfile "$f.$i.gz" full || flags="$flags,hole"
          i=$((i - 1))
        done
        addseg "$f" 0 "$sz" 0
      else
        flags=gap; bound="$SINCE_S"
        if [ "$clast" -gt "$SINCE" ]; then bound=$(tsstr $((clast + 1))); fi
        for i in 9 8 7 6 5 4 3 2 1; do
          addfile "$f.$i.gz" since || true
          addfile "$f.$i" since || true
        done
        addseg "$f" 0 "$sz" 0
      fi
    fi
  else
    flags=first
    for i in 9 8 7 6 5 4 3 2 1; do
      addfile "$f.$i.gz" since || true
      addfile "$f.$i" since || true
    done
    addseg "$f" 0 "$sz" 0
  fi
  total=0; for j in "${SL[@]}"; do total=$((total + j)); done
  if [ "$total" -gt "$MAX" ]; then
    keep=$MAX; j=$((${#SP[@]} - 1))
    while [ "$j" -ge 0 ]; do
      if [ "$keep" -le 0 ]; then skipped=$((skipped + SL[j])); SL[j]=0
      elif [ "${SL[j]}" -gt "$keep" ]; then
        skipped=$((skipped + SL[j] - keep))
        if [ "${SG[j]}" != 1 ]; then SS[j]=$((SS[j] + SL[j] - keep)); fi
        SL[j]=$keep
        keep=0
      else keep=$((keep - SL[j])); fi
      j=$((j - 1))
    done
    flags="${flags:+$flags,}capped:$skipped"
  fi
  for j in "${SL[@]}"; do bytes=$((bytes + j)); done
  [ -n "$flags" ] || flags=-
  npl=256; [ "$sz" -lt 256 ] && npl=$sz
  nps=-; [ "$npl" -gt 0 ] && nps=$(pfx "$f" "$npl")
  {
    j=0
    while [ "$j" -lt "${#SP[@]}" ]; do
      if [ "${SL[j]}" -gt 0 ]; then
        if [ "${SG[j]}" = 1 ]; then gzip -dc -- "${SP[j]}" 2</dev/null | head -c "${SL[j]}"
        else tail -c +$((SS[j] + 1)) -- "${SP[j]}" 2</dev/null | head -c "${SL[j]}"; fi
        printf '\n'
      fi
      j=$((j + 1))
    done
  } | awk -v label="$label" -v inode="$ino" -v size="$sz" -v mtime="$mt" -v flags="$flags" -v bytes="$bytes" -v bound="$bound" -v pl="$npl" -v ps="$nps" "$AWKPROG"
}

while IFS= read -r f; do
  case "$f" in *.[0-9]|*.[0-9][0-9]|*.gz|*'*') continue ;; esac
  scan_one "$f"
done < <(primaries)
printf 'E\t%s\tok\n' "$PV"

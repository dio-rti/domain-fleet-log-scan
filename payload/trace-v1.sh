#!/usr/bin/env bash
# fleet-log-scan remote payload trace-v1. Read-only request-id search; writes nothing.
# Records: H (header), R (file earliest entry ts), M (matching entry, whitelisted keys only), E (end).
set -u
PV=trace-v1
ROOT=/var/www/domain-0/runtime/logs
RID=""
FROM=0
TO=0
for a in "$@"; do
  case "$a" in
    root=*) ROOT=${a#root=} ;;
    id=*) RID=${a#id=} ;;
    from=*) FROM=${a#from=} ;;
    to=*) TO=${a#to=} ;;
    *) printf 'H\t%s\tERR\tbad-arg\n' "$PV"; exit 2 ;;
  esac
done
case "$FROM$TO" in *[!0-9]*) printf 'H\t%s\tERR\tbad-num\n' "$PV"; exit 2 ;; esac
case "$RID" in ????????-????-????-????-????????????) ;; *) printf 'H\t%s\tERR\tbad-id\n' "$PV"; exit 2 ;; esac
case "$RID" in *[!0-9a-fA-F-]*) printf 'H\t%s\tERR\tbad-id\n' "$PV"; exit 2 ;; esac

fst() {
  stat -c '%i %s %Y' -- "$1" 2</dev/null || stat -f '%i %z %m' -- "$1" 2</dev/null
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
    if (!lead && (length(t) < 6 || (n < 3 && (index(t, "::") == 0 || substr(t, 1, 1) == ":")))) out = out substr(s, 1, RSTART + RLENGTH - 1)
    else out = out substr(s, 1, RSTART - 1) "{ip}"
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
  gsub(/[\t;]/, " ", s)
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
function kv(t, key,   p, r, q) {
  p = index(t, "'" key "' =\076 "); if (p == 0) return ""
  r = substr(t, p + length(key) + 6)
  if (substr(r, 1, 1) == "'") { r = substr(r, 2); q = index(r, "'"); if (q) r = substr(r, 1, q - 1); return r }
  if (match(r, "[],\n]")) r = substr(r, 1, RSTART - 1)
  return r
}
function flush(   h, i, f, p, lvl, cat, out, keys, nk, v, j) {
  if (!have) return
  have = 0
  if (firstts == "") firstts = cur_ts
  if (index(cur_text, rid) == 0) return
  if (cur_ts < from_s || to_s < cur_ts) return
  nh++
  if (nm == 20) return
  h = cur_head
  for (i = 1; i <= 5; i++) {
    sub(/^ +/, "", h)
    if (substr(h, 1, 1) != "[") return
    p = index(h, "]"); if (p == 0) return
    f[i] = substr(h, 2, p - 2); h = substr(h, p + 1)
  }
  lvl = tolower(f[4]); cat = norm(f[5]); sub(/^ +/, "", h)
  if (substr(h, 1, 1) == "[" || tolower(substr(h, 1, 5)) == "array" || substr(h, 1, 2) == "$_") h = ""
  out = ""
  nk = split("message route exception http_status classification suppressed_repeats", keys, " ")
  for (j = 1; j <= nk; j++) {
    v = kv(cur_text, keys[j]); if (v == "") continue
    if (keys[j] == "http_status" || keys[j] == "suppressed_repeats") { if (v ~ /^[0-9]+$/ && length(v) <= 6) out = out keys[j] "=" v ";" }
    else out = out keys[j] "=" norm(v) ";"
  }
  v = kv(cur_text, "request_id"); if (v == rid) out = out "request_id=" rid ";"
  v = kv(cur_text, "REQUEST_METHOD"); if (v ~ /^[A-Z]+$/) out = out "method=" v ";"
  v = kv(cur_text, "REQUEST_URI"); if (v != "") { sub(/\?.*/, "", v); out = out "path=" norm(v) ";" }
  if (index(cur_text, "HTTP_X_REQUEST_ID")) out = out "via=x-request-id-header;"
  nm++
  printf "M\t%s\t%s\t%s\t%s\t%s\t%s\n", label, cur_ts, lvl, cat, norm(h), out
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
  have = 0; nm = 0; nh = 0; firstts = ""
}
{
  s = $0; nl = 1
  while (1) {
    if (match(s, TSRE)) {
      rs = RSTART
      if (rs != 1 && have) { if (nl) cur_text = cur_text "\n"; cur_text = cur_text substr(s, 1, rs - 1); if (nlines == 0) cur_head = cur_head substr(s, 1, rs - 1) }
      flush(); have = 1; nlines = 0; cur_head = ""; cur_text = ""
      cur_ts = substr(s, rs, 19); s = substr(s, rs + 19); nl = 0
    } else {
      if (have) {
        if (nl) { nlines++; if (length(cur_text) < 65536) cur_text = cur_text "\n" s }
        else { cur_text = cur_text s; if (nlines == 0) cur_head = cur_head s }
      }
      break
    }
  }
}
END {
  flush()
  if (firstts == "") firstts = "-"
  printf "R\t%s\t%s\t%d\n", label, firstts, nh
}
AWKEOF
)

printf 'H\t%s\t%s\t%s\n' "$PV" "$(date +%s)" "$(date +%z)"
FROM_S=$(tsstr "$FROM")
TO_S=$(tsstr "$TO")

files() {
  local f
  for f in "$ROOT"/app.log* "$ROOT"/cron/* "$ROOT"/payment/* "$ROOT"/casino-callback/* "$ROOT"/admin-sound/* "$ROOT"/casino-worker-*.log*; do
    printf '%s\n' "$f"
  done
}

files | while IFS= read -r f; do
  case "$f" in *'*') continue ;; esac
  label=${f#"$ROOT"/}
  case "$label" in *[!A-Za-z0-9._/-]*) continue ;; esac
  [ -f "$f" ] && [ -r "$f" ] || continue
  st=$(fst "$f") || continue
  set -- $st
  [ "$3" -lt "$FROM" ] && continue
  case "$f" in
    *.gz) gzip -dc -- "$f" 2</dev/null ;;
    *) cat -- "$f" ;;
  esac | awk -v label="$label" -v rid="$RID" -v from_s="$FROM_S" -v to_s="$TO_S" "$AWKPROG"
done
printf 'E\t%s\tok\n' "$PV"

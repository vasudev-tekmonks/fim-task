#!/usr/bin/env bash
# fim_detect.sh - detector. Independent of fim_restore.sh; the two only share <state-dir>.
#
#   sudo ./fim_detect.sh <file-or-dir> <state-dir> <authorized-users>
#
#   <file-or-dir>       regular file or directory to monitor (recursive)
#   <state-dir>         where this script keeps:
#                         original/            copy of the original contents
#                         original.manifest    SHA-256 + mode/uid/gid/type manifest
#                         state.meta           key=value: type, last_ts (+ restorer_runs, written by fim_restore.sh)
#                         writer.stat          PIDs of UNAUTHORIZED writers (read by fim_restore.sh)
#   <authorized-users>  comma/space separated login names or uids, OR a path to a
#                       root-owned file with one user per line ('#' comments).
#                       Changes by these users are KEPT (they become the new baseline).
#
# One-shot: meant to be called repeatedly (e.g. every 30 s) by a scheduler; it does
# one check and exits. When the manifest no longer matches the baseline it asks the
# audit log who wrote. Unauthorized writers are appended to writer.stat (this script
# never kills or restores anything). If every writer is authorized, the current
# contents become the new baseline. The audit rule is installed once and left in place.
#
# SEQUENTIAL EXECUTION IS REQUIRED: run  fim_detect.sh  and then  fim_restore.sh,
# one after the other, never concurrently and never overlapping with themselves.
# There are no lock files; a run that finds the state-dir busy exits 1 with an error
# (enforced with flock on the state directory itself, released when the process exits).
#
# Exit status: 0 = target intact, or only authorized changes (adopted as new baseline);
#              1 = unauthorized or unresolved modification detected, or an error.
# Identity is fail-closed: a write whose login user (audit auid) is unset/invalid is
# treated as unauthorized; the process uid is never used as a fallback. A write with no
# usable PID is reported as UNRESOLVED on stderr and nothing is killed for it.
# Writes made by fim_restore.sh are skipped by PROCESS IDENTITY: its PID and its
# descendants, recorded in state.meta. Writes by any other process are still detected.
# Optional environment: FIM_AUDIT_WAIT=3  FIM_EVENT_WINDOW=120 (seconds; must exceed the call interval)
#
# writer.stat line format (fields separated by ASCII 0x1d):
#   ts_ms pid ppid uid user exe comm path
set -uo pipefail
umask 077
RS=$'\035'

usage() {
  echo "Usage: sudo $0 <file-or-dir> <state-dir> <authorized-users>" >&2
  exit 1
}
[[ $# -eq 3 ]] || usage
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
for c in auditctl ausearch awk sha256sum find sort xargs cmp diff flock realpath mktemp tr; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing dependency: $c" >&2; exit 1; }
done

# Resolve the directory part only: a target that is later deleted or swapped for a
# symlink must still be found (and reported/restored), not abort the script.
resolve_target() {
  local d b
  case ${1##*/} in ''|.|..) realpath -m -- "$1"; return;; esac
  d=$(realpath -m -- "$(dirname -- "$1")"); b=$(basename -- "$1")
  if [[ $d == / ]]; then printf '/%s\n' "$b"; else printf '%s/%s\n' "$d" "$b"; fi
}
TARGET=$(resolve_target "$1")
[[ $TARGET != / ]] || { echo 'Target must not be /.' >&2; exit 1; }
STATE=$(realpath -m -- "$2")
USERS_ARG=$3

# The state dir must not be inside the target (and vice versa): our own writes would look like tampering.
overlaps() { case "$1/" in "$2"/*) return 0;; esac; case "$2/" in "$1"/*) return 0;; esac; return 1; }
if overlaps "$TARGET" "$STATE"; then echo 'Target and state-dir must not overlap.' >&2; exit 1; fi

install -d -m 700 -- "$STATE" || exit 1
# The state dir drives kills and restores: it must not be writable by anyone but root.
[[ $(stat -c %u -- "$STATE") == 0 ]] && (( (0$(stat -c %a -- "$STATE") & 022) == 0 )) \
  || { echo "ERROR state-dir $STATE must be owned by root and not group/world-writable" >&2; exit 1; }
BASELINE=$STATE/original; MANIFEST=$STATE/original.manifest
META=$STATE/state.meta;   PENDING=$STATE/writer.stat

AUDIT_WAIT=${FIM_AUDIT_WAIT:-3}
EVENT_WINDOW_MS=$(( ${FIM_EVENT_WINDOW:-120} * 1000 ))

# Messages go to stdout; problems (ERROR/CRITICAL/UNRESOLVED/WARN) go to stderr. No log files.
log() {
  local line; line=$(printf '[%s] %s' "$(date --iso-8601=seconds)" "$*")
  case $* in ERROR*|CRITICAL*|UNRESOLVED*|WARN*) printf '%s\n' "$line" >&2;; *) printf '%s\n' "$line";; esac
}

# Every run ends with one summary line on stdout:  RESULT exit=<code> status=<text>
STATUS='ERROR - see the messages above'
trap 'rc=$?; log "RESULT exit=$rc status=$STATUS"' EXIT

# Enforce strictly sequential execution without a lock file: flock the state directory.
exec {SLFD}<"$STATE" && flock -n "$SLFD" || { echo 'ERROR state-dir is busy: fim_detect.sh and fim_restore.sh must run strictly one after another' >&2; exit 1; }

# ---------------------------------------------------------------- state.meta (key=value)
meta_get() {   # prints the value of key $1; fails if absent
  local line; [[ -r $META ]] || return 1
  while IFS= read -r line; do
    [[ $line == "$1="* ]] && { printf '%s' "${line#*=}"; return 0; }
  done <"$META"
  return 1
}
meta_set() {   # key value: keep every other line, replace/add this one, swap in with an atomic mv
  local k=$1 v=$2 tmp line found=0
  tmp=$(mktemp "$STATE/state.meta.XXXXXX") || return 1
  if [[ -r $META ]]; then
    while IFS= read -r line; do
      if [[ $line == "$k="* ]]; then printf '%s=%s\n' "$k" "$v"; found=1; else printf '%s\n' "$line"; fi
    done <"$META" >"$tmp"
  fi
  (( found )) || printf '%s=%s\n' "$k" "$v" >>"$tmp"
  mv -f -- "$tmp" "$META"
}

# ---------------------------------------------------------------- manifest / baseline
# One NUL-terminated record per object: type, mode, uid, gid, relative path, link target;
# then SHA-256 of every regular file. mtime is deliberately not compared.
manifest() {
  local t=$1
  if [[ -d $t && ! -L $t ]]; then
    ( cd -- "$t" 2>/dev/null || exit 0
      find . -printf '%y\t%m\t%U\t%G\t%P\t%l\0' | LC_ALL=C sort -z
      find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum -z -- 2>/dev/null
      true )
  else
    find "$t" -maxdepth 0 -printf '%y\t%m\t%U\t%G\t.\t%l\0' 2>/dev/null
    [[ -f $t && ! -L $t ]] && sha256sum -z <"$t" 2>/dev/null
    return 0
  fi
}
copy_tree() {   # copy the CONTENTS of directory $1 into directory $2
  if command -v rsync >/dev/null 2>&1; then rsync -aHAX --numeric-ids -- "$1/" "$2/"; else cp -a -- "$1/." "$2/"; fi
}
take_copy() {   # copy the current target into directory $1
  if [[ $TYPE == file ]]; then cp -a -- "$TARGET" "$1/item"; else copy_tree "$TARGET" "$1"; fi
}
manifest_of_copy() { if [[ $TYPE == file ]]; then manifest "$1/item"; else manifest "$1"; fi; }

ensure_baseline() {
  local mt tmp mtgt
  # Upgrade from the older layout (separate type/last_ts files, restore.window, lock files)
  # without silently re-trusting the current contents.
  if [[ -z $(meta_get type) && -f $STATE/type ]]; then
    meta_set type "$(<"$STATE/type")"
    [[ -r $STATE/last_ts ]] && meta_set last_ts "$(<"$STATE/last_ts")"
  fi
  rm -f -- "$STATE/type" "$STATE/last_ts" "$STATE/restore.window" "$STATE/state.lock" "$STATE/detector.lock" "$STATE/restorer.lock"

  mt=$(meta_get type) || mt=''
  if [[ -d $BASELINE && -f $MANIFEST && -n $mt ]]; then
    TYPE=$mt          # existing baseline decides; the target itself may have been deleted or replaced
  else
    [[ ! -L $TARGET && ( -f $TARGET || -d $TARGET ) ]] || { echo 'ERROR cannot create a baseline: target must be an existing regular file or directory (not a symlink).' >&2; exit 1; }
    TYPE=file; [[ -d $TARGET ]] && TYPE=directory
    tmp=$STATE/original.new
    rm -rf -- "$tmp"; mkdir -m 700 -- "$tmp"
    take_copy "$tmp" || { log 'ERROR could not create baseline copy'; exit 1; }
    manifest_of_copy "$tmp" >"$MANIFEST.tmp"
    rm -rf -- "$BASELINE"; mv -- "$tmp" "$BASELINE"; mv -f -- "$MANIFEST.tmp" "$MANIFEST"
    meta_set type "$TYPE" || { log 'ERROR could not write state.meta'; exit 1; }
    mt=$TYPE
    log "BASELINE_CREATED target=$TARGET"
  fi
  # a state-dir belongs to ONE target: restoring another target from it would wreck that target
  mtgt=$(meta_get target) || mtgt=''
  if [[ -z $mtgt ]]; then meta_set target "$TARGET"; elif [[ $mtgt != "$TARGET" ]]; then
    echo "ERROR state-dir belongs to $mtgt, not $TARGET; use a different state-dir." >&2; exit 1
  fi
  [[ -e $PENDING ]] || : >"$PENDING"
}

# ---------------------------------------------------------------- authorization
declare -A AUTH=()
load_authorized() {
  AUTH=(); local raw toks tok uid
  if [[ -f $USERS_ARG ]]; then
    if [[ $(stat -c %u -- "$USERS_ARG") != 0 ]] || (( 0$(stat -c %a -- "$USERS_ARG") & 022 )); then
      log "WARN $USERS_ARG must be root-owned and not group/world-writable; ignoring it"; raw=''
    else raw=$(sed 's/#.*//' -- "$USERS_ARG"); fi
  else raw=$USERS_ARG; fi
  raw=${raw//,/ }
  read -ra toks <<<"$raw"
  for tok in ${toks[@]+"${toks[@]}"}; do
    if [[ $tok =~ ^[0-9]+$ ]]; then AUTH[$tok]=1
    elif uid=$(id -u -- "$tok" 2>/dev/null); then AUTH[$uid]=1
    else log "WARN authorized user '$tok' does not exist"; fi
  done
}

# ---------------------------------------------------------------- audit parsing
unhex() {   # values arrive tagged q: (was quoted, literal) or x: (unquoted: hex-encoded if all hex digits)
  local v
  case $1 in
    q:*) printf '%s' "${1#q:}";;
    x:*) v=${1#x:}
         if [[ $v =~ ^([0-9A-Fa-f]{2})+$ ]]; then printf '%b' "$(sed 's/../\\x&/g' <<<"$v")"; else printf '%s' "$v"; fi;;
    *)   printf '%s' "$1";;
  esac
}
# One line per audit event: ts_ms serial success pid ppid auid uid exe comm cwd paths(0x1f-joined)
# The kernel logs only ONE key per event. When audit rules overlap (a leftover rule from
# another target, a parent directory, a second monitor), a write to our target can carry
# somebody else's fim_ key. So read events under EVERY fim_ key; find_writers then keeps
# only the events whose paths are inside our target.
audit_keys() { { printf '%s\n' "$KEY"; auditctl -l 2>/dev/null | grep -o 'fim_[0-9a-f]\{16\}'; } | sort -u; }
audit_events() {
  { local k
    for k in $(audit_keys); do
      ausearch --input-logs -k "$k" -ts recent --raw </dev/null 2>/dev/null
    done
  } | awk -v sep="$RS" '
    function getf(line, name,   s, i, v, j) {
      s = " " line; i = index(s, " " name "="); if (i == 0) return ""
      v = substr(s, i + length(name) + 2)
      if (substr(v, 1, 1) == "\"") { v = substr(v, 2); j = index(v, "\""); return substr(v, 1, j - 1) }
      j = index(v, " "); if (j) v = substr(v, 1, j - 1)
      return v
    }
    function getp(line, name,   s, i, v, j) {   # like getf, but tags the value q: (quoted) or x: (raw)
      s = " " line; i = index(s, " " name "="); if (i == 0) return ""
      v = substr(s, i + length(name) + 2)
      if (substr(v, 1, 1) == "\"") { v = substr(v, 2); j = index(v, "\""); return "q:" substr(v, 1, j - 1) }
      j = index(v, " "); if (j) v = substr(v, 1, j - 1)
      return "x:" v
    }
    {
      p = index($0, "msg=audit("); if (!p) next
      s = substr($0, p + 10); q = index(s, ")"); id = substr(s, 1, q - 1)
      if ($1 == "type=SYSCALL") {
        seen[id] = 1; ok[id] = getf($0, "success"); pid[id] = getf($0, "pid"); ppid[id] = getf($0, "ppid")
        auid[id] = getf($0, "auid"); uid[id] = getf($0, "uid"); exe[id] = getp($0, "exe"); comm[id] = getf($0, "comm")
      } else if ($1 == "type=CWD") { cwd[id] = getp($0, "cwd") }
      else if ($1 == "type=PATH") {
        v = getp($0, "name")
        if (v != "" && v != "x:(null)") paths[id] = paths[id] (paths[id] == "" ? "" : "\037") v
      }
    }
    END {
      for (id in seen) {
        split(id, a, ":")
        printf "%.0f%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n", a[1] * 1000, sep, a[2], sep, ok[id], sep, pid[id], sep, ppid[id], sep, auid[id], sep, uid[id], sep, exe[id], sep, comm[id], sep, cwd[id], sep, paths[id]
      }
    }'
}

# ---------------------------------------------------------------- recognising the restorer's own writes
# fim_restore.sh records every run as  pid:start_ms:end_ms  (end 0 = still running or
# crashed) in state.meta (key restorer_runs). Its restore commands are direct children of
# that PID. An event is the restorer's if it was made by that PID, or by a direct child of
# it, while that run was in progress; descendants of such a process (e.g. a helper it
# forks) are followed through the parent pids in the audit events. Anything else, even
# during a restore, is treated like any other write.
declare -a RUNS=()
load_runs() { local v; v=$(meta_get restorer_runs) || v=''; RUNS=(); IFS=, read -ra RUNS <<<"$v"; }
in_run_time() {   # ts [pid ppid]: within a recorded run; with pid/ppid also requires pid or parent == the restorer
  local r rp rs re
  for r in ${RUNS[@]+"${RUNS[@]}"}; do
    IFS=: read -r rp rs re <<<"$r"
    [[ $rp =~ ^[0-9]+$ && $rs =~ ^[0-9]+$ && $re =~ ^[0-9]+$ ]] || continue
    (( $1 >= rs && ( re == 0 || $1 <= re ) )) || continue
    [[ $# -lt 3 ]] && return 0
    [[ $2 == "$rp" || $3 == "$rp" ]] && return 0
  done
  return 1
}

declare -A W_TS=() W_REC=() W_AUTH=()
LAST_TS_MS=0; MAX_EV_MS=0; N_UNAUTH=0; UNRES=0
find_writers() {
  W_TS=(); W_REC=(); W_AUTH=(); UNRES=0
  local now ts_ms serial ok pid ppid auid uid exe comm cwd paths n full matched actor name i ch
  local -a arr E_ts=() E_pid=() E_ppid=() E_auid=() E_exe=() E_comm=() E_path=()
  local -A TR=()
  now=$(date +%s%3N); load_runs
  # pass 1: collect writes to the target that we have not handled yet
  while IFS=$RS read -r ts_ms serial ok pid ppid auid uid exe comm cwd paths; do
    [[ $ok == yes && $ts_ms =~ ^[0-9]+$ ]] || continue
    (( ts_ms > LAST_TS_MS && now - ts_ms <= EVENT_WINDOW_MS )) || continue
    cwd=$(unhex "$cwd"); exe=$(unhex "$exe"); matched=''; arr=()
    IFS=$'\037' read -ra arr <<<"$paths"
    for n in ${arr[@]+"${arr[@]}"}; do
      n=$(unhex "$n"); [[ $n == /* ]] || n="$cwd/$n"
      full=$(realpath -m -- "$n" 2>/dev/null) || continue
      if [[ $full == "$TARGET" || ( $TYPE == directory && $full == "$TARGET"/* ) ]]; then matched=$full; break; fi
    done
    [[ -n $matched ]] || continue
    E_ts+=("$ts_ms"); E_pid+=("$pid"); E_ppid+=("$ppid"); E_auid+=("$auid"); E_exe+=("$exe"); E_comm+=("$comm"); E_path+=("$matched")
  done < <(audit_events)

  # trusted = the restorer, its direct children during a run, and their descendants
  ch=1
  while (( ch )); do
    ch=0
    for i in "${!E_pid[@]}"; do
      pid=${E_pid[i]}; ppid=${E_ppid[i]}
      [[ $pid =~ ^[0-9]+$ && $ppid =~ ^[0-9]+$ ]] || continue
      [[ -n ${TR[$pid]:-} ]] && continue
      if in_run_time "${E_ts[i]}" "$pid" "$ppid" || { [[ -n ${TR[$ppid]:-} ]] && in_run_time "${E_ts[i]}"; }; then
        TR[$pid]=1; ch=1
      fi
    done
  done

  # pass 2: classify everything else
  for i in "${!E_pid[@]}"; do
    ts_ms=${E_ts[i]}; pid=${E_pid[i]}; ppid=${E_ppid[i]}; auid=${E_auid[i]}
    (( ts_ms > MAX_EV_MS )) && MAX_EV_MS=$ts_ms
    [[ $pid =~ ^[0-9]+$ && -n ${TR[$pid]:-} ]] && continue     # the restorer's own write
    [[ $pid == "$$" ]] && continue
    # a write to the target with no usable PID cannot be attributed or killed: report it
    if ! [[ $pid =~ ^[0-9]+$ ]] || (( pid <= 1 )); then UNRES=$((UNRES+1)); continue; fi
    # Attribute to the LOGIN user (auid survives sudo/su). An unset/invalid auid means the
    # identity is unknown: fail closed, never fall back to the process uid.
    actor=unknown; name=unknown
    if [[ $auid =~ ^[0-9]+$ && $auid != 4294967295 ]]; then actor=$auid; name=$(id -nu -- "$auid" 2>/dev/null) || name=$auid; fi
    if [[ -z ${W_TS[$pid]:-} ]] || (( ts_ms > W_TS[$pid] )); then
      W_TS[$pid]=$ts_ms; W_AUTH[$pid]=0; [[ $actor =~ ^[0-9]+$ && -n ${AUTH[$actor]:-} ]] && W_AUTH[$pid]=1
      W_REC[$pid]="$ts_ms$RS$pid$RS$ppid$RS$actor$RS$name$RS${E_exe[i]}$RS${E_comm[i]}$RS${E_path[i]}"
    fi
  done
}
count_unauth() { local p; N_UNAUTH=0; for p in "${!W_TS[@]}"; do [[ ${W_AUTH[$p]} == 0 ]] && N_UNAUTH=$((N_UNAUTH+1)); done; }
wait_for_writers() {
  local deadline=$((SECONDS + AUDIT_WAIT))
  while :; do
    find_writers
    (( ${#W_TS[@]} || UNRES )) && return 0
    (( SECONDS >= deadline )) && return 1
    sleep 0.3
  done
}

register_unauth() {
  local p ts pid2 ppid uid user exe comm path
  for p in "${!W_TS[@]}"; do
    [[ ${W_AUTH[$p]} == 0 ]] || continue
    printf '%s\n' "${W_REC[$p]}" >>"$PENDING"
    IFS=$RS read -r ts pid2 ppid uid user exe comm path <<<"${W_REC[$p]}"
    log "UNAUTHORIZED_WRITER user=$user pid=$pid2 ppid=$ppid exe=$exe path=$path -> registered in writer.stat"
  done
}

# Keep an authorized change: adopt the current contents as the new baseline.
# Order: snapshot first, then classify writers AGAIN, so the snapshot only holds
# changes whose audit events were already attributed.
adopt_authorized() {
  local snap=$STATE/original.new mf=$STATE/original.manifest.new rc=0
  # never adopt a deleted target or one replaced by a different kind of object
  if [[ $TYPE == file ]]; then [[ -f $TARGET && ! -L $TARGET ]]; else [[ -d $TARGET && ! -L $TARGET ]]; fi \
    || { log 'WARN target is missing or was replaced by another object type; not adopting (the restorer will revert it)'; return 1; }
  rm -rf -- "$snap" "$mf"; mkdir -m 700 -- "$snap"
  if take_copy "$snap"; then
    manifest_of_copy "$snap" >"$mf"
    find_writers; count_unauth
    if (( N_UNAUTH == 0 && UNRES == 0 )); then
      rm -rf -- "$BASELINE"; mv -- "$snap" "$BASELINE"; mv -f -- "$mf" "$MANIFEST"
      log "BASELINE_UPDATED target=$TARGET (authorized change kept)"
    else
      rm -rf -- "$snap" "$mf"; register_unauth; rc=1
      (( UNRES > 0 )) && log "UNRESOLVED $UNRES write event(s) without a usable PID; not adopting"
    fi
  else
    rm -rf -- "$snap" "$mf"; log 'WARN could not snapshot authorized change; leaving it for the restorer'; rc=1
  fi
  return $rc
}

# One pass. Returns 0 = intact / authorized change adopted, 1 = unauthorized or unresolved change.
run_once() {
  local cur p user rc=0 changed=1
  cur=$(mktemp "$STATE/.cur.XXXXXX")
  manifest "$TARGET" >"$cur" 2>/dev/null
  cmp -s -- "$cur" "$MANIFEST" && changed=0
  if (( changed )); then
    log 'ALERT integrity mismatch'
    diff --old-line-format='-%L' --new-line-format='+%L' --unchanged-line-format='' \
         <(tr '\0' '\n' <"$MANIFEST") <(tr '\0' '\n' <"$cur") | head -n 20 |
      while IFS= read -r p; do log "CHANGE ${p//$'\t'/ }"; done
  fi
  rm -f -- "$cur"

  load_authorized
  # Even when the content already matches (the restorer may have reverted it before
  # we ran), unseen unauthorized writes are still registered so the process gets killed.
  if (( changed )); then wait_for_writers || find_writers; else find_writers; fi
  count_unauth
  if (( changed && N_UNAUTH == 0 && UNRES == 0 && ${#W_TS[@]} )); then
    sleep 0.3; find_writers; count_unauth       # let a concurrent unauthorized writer's event arrive
  fi

  if (( N_UNAUTH > 0 )); then
    register_unauth; rc=1
  fi
  if (( UNRES > 0 )); then
    # Not killable and not attributable: the restorer reverts the content; a human should look.
    log "UNRESOLVED path=$TARGET $UNRES write event(s) without a usable PID; nothing will be killed for them (target is restored from the baseline)"
    rc=1
  elif (( N_UNAUTH == 0 && changed )); then
    if (( ${#W_TS[@]} )); then
      for p in "${!W_TS[@]}"; do IFS=$RS read -r _ _ _ _ user _ <<<"${W_REC[$p]}"; done
      log "CHANGE_AUTHORIZED last_user=$user"
      adopt_authorized || rc=1
    else
      log "UNRESOLVED path=$TARGET changed but no write event was found in the audit log (target is restored from the baseline)"; rc=1
    fi
  fi
  if (( MAX_EV_MS > LAST_TS_MS )); then LAST_TS_MS=$MAX_EV_MS; meta_set last_ts "$LAST_TS_MS"; fi
  if (( rc == 0 )); then
    if (( changed )); then STATUS='OK - authorized change adopted as the new baseline'; else STATUS='OK - target intact'; fi
  elif (( N_UNAUTH > 0 )); then STATUS="ALERT - unauthorized change: $N_UNAUTH writer(s) registered in writer.stat (run fim_restore.sh)"
  elif (( UNRES > 0 )) || (( ${#W_TS[@]} == 0 )); then STATUS='ALERT - target changed but the writer could not be identified (UNRESOLVED); nothing to kill, restorer will revert'
  else STATUS='ERROR - authorized change could not be adopted (restorer will revert it)'; fi
  return $rc
}

# ---------------------------------------------------------------- start
ensure_baseline
LAST_TS_MS=$(meta_get last_ts) || LAST_TS_MS=0
[[ $LAST_TS_MS =~ ^[0-9]+$ ]] || LAST_TS_MS=0

# The audit rule must outlive this process: events between two invocations would
# otherwise be lost. Stable key per target; installed only if missing, never removed.
KEY="fim_$(printf '%s' "$TARGET" | sha256sum | cut -c1-16)"
# auditctl -l prints watch rules as "-k KEY" but syscall/dir rules as "-F key=KEY",
# so match both forms (and the arch for dir rules).
RULES_NOW=$(auditctl -l 2>/dev/null)
have_rule() {   # $1 = optional arch pattern (b64/b32) to require on the rule line
  grep -E -- "${1:+arch=$1 .*}(-k |key=)$KEY( |\$)" <<<"$RULES_NOW" >/dev/null 2>&1
}
add_rule() {    # args to auditctl; "Rule exists" is success, anything else is fatal
  local out; out=$(auditctl "$@" 2>&1) && return 0
  [[ $out == *'Rule exists'* ]] && return 0
  log "ERROR auditctl $*: $out"; return 1
}
if [[ $TYPE == file ]]; then
  have_rule || add_rule -w "$TARGET" -p wa -k "$KEY" || exit 1
else
  have_rule b64 || add_rule -a always,exit -F arch=b64 -F dir="$TARGET" -F perm=wa -k "$KEY" || exit 1
  if [[ $(uname -m) == x86_64 ]]; then
    have_rule b32 || add_rule -a always,exit -F arch=b32 -F dir="$TARGET" -F perm=wa -k "$KEY" || log 'WARN 32-bit audit rule unavailable'
  fi
fi
grep -qsx auditd /proc/[0-9]*/comm || log 'WARN auditd does not appear to be running; writer PID cannot be resolved'
auditctl -s 2>/dev/null | grep -Eq '^enabled (1|2)' || log 'WARN kernel auditing appears disabled (try: auditctl -e 1)'

run_once
exit $?
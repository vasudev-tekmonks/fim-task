#!/usr/bin/env bash
# fim_restore.sh - killer + restorer. Independent of fim_detect.sh; the two only share <state-dir>.
#
#   sudo ./fim_restore.sh <file-or-dir> <state-dir> <authorized-users>
#
# Same arguments as fim_detect.sh (see there). This script:
#   1. reads writer.stat (PIDs of unauthorized writers registered by the detector)
#      and terminates those processes after safety checks;
#   2. when the target no longer matches the baseline (original/ + original.manifest),
#      restores the target from original/ and verifies it against the manifest.
#
# NOTE: authorized changes are kept because the *detector* adopts them as the new
# baseline. Run on its own, this script reverts every change.
#
# One-shot: meant to be called repeatedly (e.g. every 30 s) by a scheduler, AFTER
# fim_detect.sh in each cycle; it does one pass and exits.
# SEQUENTIAL EXECUTION IS REQUIRED: never run it concurrently with fim_detect.sh or
# with itself. There are no lock files; a run that finds the state-dir busy exits 1
# (enforced with flock on the state directory itself, released when the process exits).
#
# Exit status: 0 = success (nothing to restore, or restored and verified);
#              1 = restore failed or error.
#
# So the detector can tell this script's own writes from tampering, every restore is
# recorded in state.meta (key restorer_runs = pid:start_ms:end_ms,...). All changes to
# the target are made by direct children of this script (cp, rm, mv, chmod, chown, mkdir,
# find): no rsync, because its forked helpers could not be attributed from audit logs.
#
# Optional environment:
#   FIM_KILL_PARENT=1       if the writer already exited, try its parent (e.g. a loop script)
#   FIM_KILL_INTERACTIVE=1  also terminate a writer that is an interactive shell (closes that terminal)
#   FIM_DRY_RUN=1           log what would be killed, send no signal
set -uo pipefail
umask 077
RS=$'\035'

usage() {
  echo "Usage: sudo $0 <file-or-dir> <state-dir> <authorized-users>" >&2
  exit 1
}
[[ $# -eq 3 ]] || usage
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
for c in sha256sum find sort xargs cmp flock realpath mktemp getconf diff tr cp rm mv chmod chown; do
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
[[ -d $STATE ]] || { echo "State dir $STATE does not exist; start fim_detect.sh first (it creates the baseline)." >&2; exit 1; }
overlaps() { case "$1/" in "$2"/*) return 0;; esac; case "$2/" in "$1"/*) return 0;; esac; return 1; }
if overlaps "$TARGET" "$STATE"; then echo 'Target and state-dir must not overlap.' >&2; exit 1; fi
# The state dir drives kills and restores: it must not be writable by anyone but root.
[[ $(stat -c %u -- "$STATE") == 0 ]] && (( (0$(stat -c %a -- "$STATE") & 022) == 0 )) \
  || { echo "ERROR state-dir $STATE must be owned by root and not group/world-writable" >&2; exit 1; }

BASELINE=$STATE/original; MANIFEST=$STATE/original.manifest
META=$STATE/state.meta;   PENDING=$STATE/writer.stat

# Messages go to stdout; problems (ERROR/CRITICAL/UNRESOLVED/WARN) go to stderr. No log files.
log() {
  local line; line=$(printf '[%s] %s' "$(date --iso-8601=seconds)" "$*")
  case $* in ERROR*|CRITICAL*|UNRESOLVED*|WARN*) printf '%s\n' "$line" >&2;; *) printf '%s\n' "$line";; esac
}
now_ms() { date +%s%3N; }

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

TYPE=$(meta_get type) || TYPE=''
[[ -d $BASELINE && -f $MANIFEST && ( $TYPE == file || $TYPE == directory ) ]] || { echo 'No baseline in state-dir; run fim_detect.sh first.' >&2; exit 1; }
MTGT=$(meta_get target) || MTGT=''
[[ -z $MTGT || $MTGT == "$TARGET" ]] || { echo "ERROR state-dir belongs to $MTGT, not $TARGET." >&2; exit 1; }

# ---------------------------------------------------------------- manifest (same format as the detector's)
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
integrity_ok() { manifest "$TARGET" 2>/dev/null | cmp -s -- "$MANIFEST" -; }

# ---------------------------------------------------------------- run record (read by fim_detect.sh)
RUN_OPEN=0
begin_run() {   # record pid:start:0 BEFORE the first modification; close runs a crash left open
  local v now r new='' n=0; local -a a=() keep=()
  now=$(now_ms); v=$(meta_get restorer_runs) || v=''
  IFS=, read -ra a <<<"$v"
  for r in ${a[@]+"${a[@]}"}; do
    [[ $r =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || continue
    [[ $r == *:0 ]] && r="${r%:0}:$now"
    keep+=("$r")
  done
  keep+=("$$:$((now - 2000)):0")
  (( ${#keep[@]} > 20 )) && keep=("${keep[@]: -20}")
  for r in "${keep[@]}"; do new+="${new:+,}$r"; done
  meta_set restorer_runs "$new" && RUN_OPEN=1
}
end_run() {     # close this run (EXIT trap)
  (( RUN_OPEN )) || return 0
  RUN_OPEN=0
  local v now r new='' n; local -a a=()
  now=$(now_ms); v=$(meta_get restorer_runs) || return 0
  IFS=, read -ra a <<<"$v"
  for r in ${a[@]+"${a[@]}"}; do
    [[ $r == "$$":*:0 ]] && r="${r%:0}:$now"
    new+="${new:+,}$r"
  done
  meta_set restorer_runs "$new"
}
# Every run ends with one summary line on stdout:  RESULT exit=<code> status=<text>
STATUS='ERROR - see the messages above'
KILLED=0
on_exit() { local rc=$?; end_run; log "RESULT exit=$rc status=$STATUS"; }
trap on_exit EXIT
trap 'exit 130' INT; trap 'exit 143' TERM

# ---------------------------------------------------------------- authorization (double check of the detector's verdict)
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

# ---------------------------------------------------------------- /proc helpers
CLK_TCK=$(getconf CLK_TCK); BTIME=0
while read -r k v; do [[ $k == btime ]] && BTIME=$v; done </proc/stat
P_STATE=''; P_PPID=0; P_START=0
read_proc() {   # sets P_STATE P_PPID P_START for pid $1; fails if it does not exist
  local s; local -a f
  { s=$(<"/proc/$1/stat"); } 2>/dev/null || return 1
  s=${s##*) }; f=($s)
  P_STATE=${f[0]}; P_PPID=${f[1]}; P_START=${f[19]}
}
declare -A PROT=()          # never terminated: this script and all its ancestors
PROT[$$]=1; p=$PPID
while (( p > 1 )) && [[ -z ${PROT[$p]:-} ]]; do PROT[$p]=1; read_proc "$p" || break; p=$P_PPID; done
PROTECTED_EXES=" systemd init auditd systemd-journald kthreadd "
SHELLS=" bash sh dash zsh fish ksh mksh ash tcsh csh "

is_interactive() {   # pid exe: a shell a person is sitting in (not -c / script / piped)
  [[ $SHELLS == *" ${2##*/} "* ]] || return 1
  local -a argv=(); local a i
  mapfile -d '' -t argv <"/proc/$1/cmdline" 2>/dev/null
  for ((i=1; i<${#argv[@]}; i++)); do
    a=${argv[i]}
    case $a in
      --)            (( i+1 < ${#argv[@]} )) && return 1; break;;
      --*)           ;;
      -o|+o|-O|+O)   i=$((i+1));;
      -*c*)          return 1;;
      [-+]*)         ;;
      *)             return 1;;
    esac
  done
  [[ ${argv[0]:-} == -* ]] && return 0
  local t; t=$(readlink "/proc/$1/fd/0" 2>/dev/null) || return 1
  [[ $t == /dev/pts/* || $t == /dev/tty* || $t == /dev/console ]]
}

wait_exit() {   # pid start seconds -> 0 if gone
  local i n=$(( $3 * 10 ))
  for ((i=0; i<=n; i++)); do
    read_proc "$1" && [[ $P_START == "$2" && $P_STATE != Z && $P_STATE != X ]] || return 0
    (( i < n )) && sleep 0.1
  done
  return 1
}
R=''
terminate() {   # pid start sig:timeout...   -> sets R
  local pid=$1 start=$2 step sig t; shift 2
  for step in "$@"; do
    sig=${step%%:*}; t=${step##*:}
    if ! kill -"$sig" "$pid" 2>/dev/null; then log "PID_EXITED pid=$pid"; R=gone; return; fi
    if wait_exit "$pid" "$start" "$t"; then log "PID_TERMINATED signal=$sig pid=$pid"; R=killed; return; fi
  done
  log "PID_KILL_FAILED pid=$pid still-running"; R=failed
}
respond() {   # pid expected_exe event_ts_ms role  -> sets R (killed|gone|refused|failed)
  local pid=$1 want=$2 ts=$3 role=$4 tag="pid=$1 role=$4" cur start start_ms
  local -a seq=("TERM:2" "KILL:2")
  R=refused
  if ! read_proc "$pid" || [[ $P_STATE == Z || $P_STATE == X ]]; then log "PID_GONE $tag"; R=gone; return; fi
  start=$P_START
  cur=$(readlink "/proc/$pid/exe" 2>/dev/null) || { log "PID_REFUSED no_exe $tag"; return; }
  if [[ -n $want && $cur != "$want" ]]; then log "PID_REFUSED identity_mismatch $tag"; return; fi
  start_ms=$(( BTIME * 1000 + start * 1000 / CLK_TCK ))
  if (( start_ms > ts + 2000 )); then log "PID_REFUSED pid_reused $tag"; return; fi   # started after the write: recycled PID
  if [[ -n ${PROT[$pid]:-} || $PROTECTED_EXES == *" ${cur##*/} "* ]]; then log "PID_REFUSED protected_process $tag exe=$cur"; return; fi
  if is_interactive "$pid" "$cur"; then
    [[ $KILL_INTERACTIVE == 1 ]] || { log "PID_REFUSED interactive_shell $tag exe=$cur (set FIM_KILL_INTERACTIVE=1 to allow)"; return; }
    seq=("HUP:1" "KILL:2")     # interactive shells ignore SIGTERM
  fi
  if ! read_proc "$pid" || [[ $P_START != "$start" || $(readlink "/proc/$pid/exe" 2>/dev/null) != "$cur" ]]; then
    log "PID_REFUSED identity_changed $tag"; return
  fi
  log "PID_MATCH $tag exe=$cur"
  if [[ $DRY_RUN == 1 ]]; then log "PID_DRY_RUN $tag"; return; fi
  terminate "$pid" "$start" "${seq[@]}"
}
KILL_PARENT=${FIM_KILL_PARENT:-0}; KILL_INTERACTIVE=${FIM_KILL_INTERACTIVE:-0}; DRY_RUN=${FIM_DRY_RUN:-0}

process_pending() {
  local recs='' ts pid ppid uid user exe comm path
  if [[ -s $PENDING ]]; then recs=$(<"$PENDING"); : >"$PENDING"; fi
  [[ -n $recs ]] || return 0
  load_authorized
  while IFS=$RS read -r ts pid ppid uid user exe comm path; do
    [[ $pid =~ ^[0-9]+$ && $ts =~ ^[0-9]+$ ]] || continue
    if [[ $uid =~ ^[0-9]+$ && -n ${AUTH[$uid]:-} ]]; then log "SKIP pid=$pid user=$user is authorized here"; continue; fi
    log "KILL_REQUEST pid=$pid user=$user exe=$exe path=$path"
    respond "$pid" "$exe" "$ts" writer
    [[ $R == killed ]] && KILLED=$((KILLED+1))
    if [[ $R == gone && $KILL_PARENT == 1 && $ppid =~ ^[0-9]+$ ]] && (( ppid > 1 )); then
      respond "$ppid" '' "$ts" parent
      [[ $R == killed ]] && KILLED=$((KILLED+1))
    fi
  done <<<"$recs"
}

# ---------------------------------------------------------------- restore
# Every command below that touches the target is run directly by this script (no pipes
# into writers, no rsync, no command substitution around a writer), so the audit log
# shows it as a child of this PID.
restore_dir_full() {   # fallback: empty the target and copy everything back
  find "$TARGET" -mindepth 1 -delete &&
  cp -aT -- "$BASELINE" "$TARGET" &&
  chown --reference="$BASELINE" -- "$TARGET" && chmod --reference="$BASELINE" -- "$TARGET"
}
restore_dir() {   # incremental: remove extras, re-copy only what differs from the manifest
  local p rel b src dst cur line
  local -A CH=()
  # 1. delete anything the baseline does not have, or has as a different kind of object
  while IFS= read -r -d '' p; do
    rel=${p#"$TARGET"/}; b=$BASELINE/$rel
    if [[ ! -e $b && ! -L $b ]]; then rm -rf -- "$p"
    elif { [[ -L $p ]] && [[ ! -L $b ]]; } || { [[ ! -L $p ]] && [[ -L $b ]]; } \
         || { [[ -d $p && ! -L $p ]] && ! [[ -d $b && ! -L $b ]]; } \
         || { ! [[ -d $p && ! -L $p ]] && [[ -d $b && ! -L $b ]]; }; then rm -rf -- "$p"
    fi
  done < <(find "$TARGET" -depth -mindepth 1 -print0)
  # 2. paths whose manifest records differ
  cur=$(mktemp "$STATE/.restore.XXXXXX") || return 1
  manifest "$TARGET" >"$cur" 2>/dev/null
  while IFS= read -r line; do
    if [[ $line =~ ^[0-9a-f]{64}\ \ \./(.*)$ ]]; then rel=${BASH_REMATCH[1]}
    else line=${line#*$'\t'}; line=${line#*$'\t'}; line=${line#*$'\t'}; line=${line#*$'\t'}; rel=${line%%$'\t'*}; fi
    CH["/$rel"]=1       # leading '/' so the root directory (empty rel) is a valid key
  done < <(diff --old-line-format='%L' --new-line-format='%L' --unchanged-line-format='' \
                <(tr '\0' '\n' <"$MANIFEST") <(tr '\0' '\n' <"$cur"))
  rm -f -- "$cur"
  # 3. copy them back, parents before children
  while IFS= read -r -d '' rel; do
    rel=${rel#/}
    if [[ -z $rel ]]; then chown --reference="$BASELINE" -- "$TARGET"; chmod --reference="$BASELINE" -- "$TARGET"; continue; fi
    src=$BASELINE/$rel; dst=$TARGET/$rel
    [[ -e $src || -L $src ]] || continue
    if [[ -d $src && ! -L $src ]]; then
      if [[ -d $dst && ! -L $dst ]]; then chown --reference="$src" -- "$dst"; chmod --reference="$src" -- "$dst"
      else rm -rf -- "$dst"; cp -aT -- "$src" "$dst" || return 1; fi
    else
      cp -aT --remove-destination -- "$src" "$dst" || return 1
    fi
  done < <(printf '%s\0' "${!CH[@]}" | LC_ALL=C sort -z)
  return 0
}
restore() {
  local rc=0 tmp parent
  begin_run || log 'WARN could not record this run in state.meta; the detector may report these writes'
  if [[ $TYPE == file ]]; then
    parent=$(dirname -- "$TARGET"); mkdir -p -- "$parent"
    [[ -d $TARGET && ! -L $TARGET ]] && rm -rf -- "$TARGET"
    tmp=$(mktemp -u "$parent/.fim-restore.XXXXXX")
    cp -a -- "$BASELINE/item" "$tmp" && mv -fT -- "$tmp" "$TARGET" || { rm -f -- "$tmp"; rc=1; }
  else
    [[ -d $TARGET && ! -L $TARGET ]] || rm -rf -- "$TARGET"
    mkdir -p -- "$TARGET" || rc=1
    if (( rc == 0 )); then
      restore_dir || rc=1
      if (( rc )) || ! integrity_ok; then
        log 'WARN incremental restore did not verify; doing a full restore'
        restore_dir_full || rc=1
      fi
    fi
  fi
  if (( rc == 0 )) && integrity_ok; then log "RESTORE_VERIFIED target=$TARGET"
  else log "CRITICAL restore failed or did not verify; manual intervention required target=$TARGET"; rc=1; fi
  return $rc
}

# One pass. Returns 0 = success (nothing to restore, or restored and verified), 1 = failed.
run_once() {
  [[ -s $PENDING ]] && process_pending          # kill registered writers first
  if integrity_ok; then STATUS="OK - target intact, nothing to restore (processes killed: $KILLED)"; return 0; fi
  log 'ALERT integrity mismatch'
  if restore; then STATUS="OK - target restored from baseline and verified (processes killed: $KILLED)"; return 0; fi
  STATUS="FAILED - restore did not verify; manual intervention required (processes killed: $KILLED)"
  return 1
}

run_once
exit $?
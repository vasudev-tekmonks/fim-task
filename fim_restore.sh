#!/usr/bin/env bash
# fim_restore.sh - killer + restorer. Independent of fim_detect.sh; the two only share <state-dir>.
#
#   sudo ./fim_restore.sh <file-or-dir> <state-dir> <authorized-users>
#
# Same arguments as fim_detect.sh (see there). This script:
#   1. reads writer.stat (PIDs of unauthorized writers registered by the detector)
#      and terminates those processes after safety checks;
#   2. when the target no longer matches the baseline (original/ + original.manifest),
#      waits briefly for the detector's verdict, then restores the target from
#      original/ and verifies it against the manifest.
#
# NOTE: authorized changes are kept because the *detector* adopts them as the new
# baseline. Run on its own, this script reverts every change.
#
# One-shot: meant to be called repeatedly (e.g. every 30 s) by a scheduler, AFTER
# fim_detect.sh in each cycle; it does one pass and exits.
# Exit status: 0 nothing to restore, 3 target restored and verified, 1 restore failed.
# Optional environment:
#   FIM_PID_WAIT=0          seconds to wait for the detector's verdict before restoring
#                           (only useful if the two scripts run concurrently)
#   FIM_KILL_PARENT=1       if the writer already exited, try its parent (e.g. a loop script)
#   FIM_KILL_INTERACTIVE=1  also terminate a writer that is an interactive shell (closes that terminal)
#   FIM_DRY_RUN=1           log what would be killed, send no signal
set -uo pipefail
umask 077
RS=$'\035'

usage() {
  echo "Usage: sudo $0 <file-or-dir> <state-dir> <authorized-users>" >&2
  exit 2
}
[[ $# -eq 3 ]] || usage
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
for c in sha256sum find sort xargs cmp flock realpath mktemp getconf; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing dependency: $c" >&2; exit 1; }
done

TARGET=$(realpath -e -- "$1" 2>/dev/null) || TARGET=''
if [[ -z $TARGET ]]; then
  # A deleted target is a legitimate thing to restore.
  TARGET=$(realpath -m -- "$1")
fi
[[ $TARGET != / ]] || { echo 'Target must not be /.' >&2; exit 1; }
[[ ! -L $1 ]] || { echo 'Give the resolved path, not a symlink.' >&2; exit 1; }
STATE=$(realpath -m -- "$2")
USERS_ARG=$3
[[ -d $STATE ]] || { echo "State dir $STATE does not exist; start fim_detect.sh first (it creates the baseline)." >&2; exit 1; }
overlaps() { case "$1/" in "$2"/*) return 0;; esac; case "$2/" in "$1"/*) return 0;; esac; return 1; }
if overlaps "$TARGET" "$STATE"; then echo 'Target and state-dir must not overlap.' >&2; exit 1; fi

BASELINE=$STATE/original; MANIFEST=$STATE/original.manifest; TYPE_FILE=$STATE/type
PENDING=$STATE/writer.stat; WINDOW=$STATE/restore.window;    LOG_FILE=$STATE/restorer.log
[[ -d $BASELINE && -f $MANIFEST && -f $TYPE_FILE ]] || { echo 'No baseline in state-dir; run fim_detect.sh first.' >&2; exit 1; }
TYPE=$(<"$TYPE_FILE")

PID_WAIT=${FIM_PID_WAIT:-0}
KILL_PARENT=${FIM_KILL_PARENT:-0}; KILL_INTERACTIVE=${FIM_KILL_INTERACTIVE:-0}; DRY_RUN=${FIM_DRY_RUN:-0}

log() { printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "$LOG_FILE"; }
now_ms() { date +%s%3N; }

exec {LFD}>"$STATE/state.lock"
lock()   { flock -x "$LFD"; }
unlock() { flock -u "$LFD"; }
exec {ILFD}>"$STATE/restorer.lock"
flock -n "$ILFD" || { echo 'Previous restorer run still active; skipping.' >&2; exit 0; }

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

process_pending() {
  local recs='' ts pid ppid uid user exe comm path
  lock
  if [[ -s $PENDING ]]; then recs=$(<"$PENDING"); : >"$PENDING"; fi
  unlock
  [[ -n $recs ]] || return 0
  load_authorized
  while IFS=$RS read -r ts pid ppid uid user exe comm path; do
    [[ $pid =~ ^[0-9]+$ && $ts =~ ^[0-9]+$ ]] || continue
    if [[ -n ${AUTH[$uid]:-} ]]; then log "SKIP pid=$pid user=$user is authorized here"; continue; fi
    log "KILL_REQUEST pid=$pid user=$user exe=$exe path=$path"
    respond "$pid" "$exe" "$ts" writer
    if [[ $R == gone && $KILL_PARENT == 1 && $ppid =~ ^[0-9]+$ ]] && (( ppid > 1 )); then
      respond "$ppid" '' "$ts" parent
    fi
  done <<<"$recs"
}

# ---------------------------------------------------------------- restore
copy_tree() { if command -v rsync >/dev/null 2>&1; then rsync -aHAX --numeric-ids --delete -- "$1/" "$2/"; else
                find "$2" -mindepth 1 -delete; cp -a -- "$1/." "$2/"; fi; }
restore() {
  local rc=0 tmp parent
  lock
  printf '%s %s\n' "$(now_ms)" "$(( $(now_ms) + 60000 ))" >"$WINDOW"   # tell the detector to ignore our own writes
  if [[ $TYPE == file ]]; then
    parent=$(dirname -- "$TARGET"); mkdir -p -- "$parent"
    [[ -d $TARGET && ! -L $TARGET ]] && rm -rf -- "$TARGET"
    tmp=$(mktemp "$parent/.fim-restore.XXXXXX") && cp -a -- "$BASELINE/item" "$tmp" && mv -fT -- "$tmp" "$TARGET" || rc=1
  else
    [[ -d $TARGET && ! -L $TARGET ]] || rm -rf -- "$TARGET"
    mkdir -p -- "$TARGET" && copy_tree "$BASELINE" "$TARGET" || rc=1
  fi
  if (( rc == 0 )) && integrity_ok; then log "RESTORE_VERIFIED target=$TARGET"
  else log "CRITICAL restore failed or did not verify; manual intervention required target=$TARGET"; rc=1; fi
  printf '%s %s\n' "$(now_ms)" "$(now_ms)" >"$WINDOW"
  unlock
  return $rc
}

# One pass. Exit status: 0 = nothing to restore, 3 = target restored and verified,
# 1 = restore failed.
run_once() {
  [[ -s $PENDING ]] && process_pending          # kill registered writers first
  integrity_ok && return 0
  log 'ALERT integrity mismatch'
  # Optional grace period, only useful when the detector runs concurrently.
  local sig0 i; sig0=$(stat -c '%i-%y' -- "$MANIFEST" 2>/dev/null)
  for ((i=0; i<PID_WAIT*10; i++)); do
    [[ -s $PENDING ]] && break
    [[ $(stat -c '%i-%y' -- "$MANIFEST" 2>/dev/null) != "$sig0" ]] && break
    sleep 0.1
  done
  process_pending
  if integrity_ok; then log 'INFO change no longer present (adopted as authorized, or reverted)'; return 0; fi
  restore && return 3
  return 1
}

run_once
exit $?
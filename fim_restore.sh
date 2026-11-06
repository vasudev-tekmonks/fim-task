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
# find, setfacl): no rsync, because its forked helpers could not be attributed from audit logs.
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
for c in sha256sum find sort xargs cmp flock realpath mktemp getconf diff tr cp rm mv chmod chown od awk; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing dependency: $c" >&2; exit 1; }
done
HAVE_GETFACL=0
command -v getfacl >/dev/null 2>&1 && HAVE_GETFACL=1

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
      if (( HAVE_GETFACL )); then
        find . \( ! -type l \) -print0 | LC_ALL=C sort -z | xargs -0 -r getfacl -n -p -- 2>/dev/null | awk '
          /^# file: / {
            if (f != "" && acl != "") printf "ACL\t%s\t%s\0", f, acl
            f = substr($0, 9); if (f != "." && substr(f, 1, 2) != "./") f = "./" f
            acl = ""; next
          }
          /^#/ || NF == 0 { next }
          { acl = (acl == "" ? $0 : acl "," $0) }
          END { if (f != "" && acl != "") printf "ACL\t%s\t%s\0", f, acl }
        '
      fi
      find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum -z -- 2>/dev/null
      true )
  else
    find "$t" -maxdepth 0 -printf '%y\t%m\t%U\t%G\t.\t%l\0' 2>/dev/null
    if (( HAVE_GETFACL )) && [[ -e $t && ! -L $t ]]; then
      getfacl -n -p -- "$t" 2>/dev/null | awk '
        /^#/ || NF == 0 { next }
        { acl = (acl == "" ? $0 : acl "," $0) }
        END { if (acl != "") printf "ACL\t.\t%s\0", acl }
      '
    fi
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
P_STATE=''; P_PPID=0; P_PGRP=0; P_SID=0; P_TTY=0; P_TPGID=0; P_START=0
read_proc() {   # sets P_STATE P_PPID P_PGRP P_SID P_TTY P_TPGID P_START for pid $1; fails if it does not exist
  local s; local -a f
  { s=$(<"/proc/$1/stat"); } 2>/dev/null || return 1
  s=${s##*) }; f=($s)
  P_STATE=${f[0]}; P_PPID=${f[1]}; P_PGRP=${f[2]}; P_SID=${f[3]}; P_TTY=${f[4]}; P_TPGID=${f[5]}; P_START=${f[19]}
}
cmdline_hex() {
  od -An -tx1 -v "/proc/$1/cmdline" 2>/dev/null | tr -d ' \n' | tr 'a-f' 'A-F'
}
proc_euid() {   # prints effective UID (field 3 of Uid: in /proc/$1/status)
  awk '/^Uid:/ {print $3; exit}' "/proc/$1/status" 2>/dev/null
}
declare -A PROT=()          # never terminated: this script and all its ancestors
PROT[$$]=1; p=$PPID
while (( p > 1 )) && [[ -z ${PROT[$p]:-} ]]; do PROT[$p]=1; read_proc "$p" || break; p=$P_PPID; done
PROTECTED_EXES=" systemd init auditd systemd-journald kthreadd sshd "
SHELLS=" bash sh dash zsh fish ksh mksh ash tcsh csh "

is_interactive() {   # pid exe: returns 0 ONLY if $1 is a live interactive shell session (not a script, -c, or background subshell)
  local pid=$1 exe=$2
  [[ $SHELLS == *" ${exe##*/} "* ]] || return 1
  local -a argv=(); local a i
  mapfile -d '' -t argv <"/proc/$pid/cmdline" 2>/dev/null
  (( ${#argv[@]} > 0 )) || return 1
  for ((i=1; i<${#argv[@]}; i++)); do
    a=${argv[i]}
    case $a in
      --)            (( i+1 < ${#argv[@]} )) && return 1; break;;
      --*)           ;;
      -o|+o|-O|+O)   i=$((i+1));;
      -*c*)          return 1;;   # e.g. sh -c '...' or dash -c '...'
      [-+]*)         ;;
      *)             return 1;;   # executing a script file argument
    esac
  done

  # Must have stdin connected to a terminal device to be an interactive shell
  local t; t=$(readlink "/proc/$pid/fd/0" 2>/dev/null) || return 1
  [[ $t == /dev/pts/* || $t == /dev/tty* || $t == /dev/console ]] || return 1

  # Inspect process group, session leadership, and parent relationship
  local st_ppid st_pgrp st_sid st_tty st_tpgid
  read_proc "$pid" || return 1
  st_ppid=$P_PPID; st_pgrp=$P_PGRP; st_sid=$P_SID; st_tty=$P_TTY; st_tpgid=$P_TPGID

  # Must have a controlling terminal
  (( st_tty != 0 )) || return 1

  # If this shell is in a background process group on its terminal (pgrp != tpgid)
  # and is NOT the session leader, it is a backgrounded subshell (e.g. `( while ...; done ) &`), not the user's login shell.
  if (( st_sid != pid && st_tpgid > 0 && st_pgrp != st_tpgid )); then
    return 1
  fi

  # If the parent is ALSO a shell in the same session and this process is not the session leader,
  # then this process is a subshell forked from the interactive shell.
  if (( st_sid != pid && st_ppid > 1 )); then
    local pexe; pexe=$(readlink "/proc/$st_ppid/exe" 2>/dev/null) || pexe=''
    if [[ -n $pexe && $SHELLS == *" ${pexe##*/} "* ]] && read_proc "$st_ppid"; then
      if (( P_SID == st_sid )); then
        return 1
      fi
    fi
  fi

  return 0
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
respond() {   # pid expected_exe event_ts_ms role [expected_comm expected_start_ticks det_int expected_cmd_hex] -> sets R
  local pid=$1 want=$2 ts=$3 role=$4 want_comm=${5:-} want_start=${6:-0} det_int=${7:-u} want_cmd=${8:-}
  local tag="pid=$1 role=$4" cur start start_ms cur_comm cur_cmd
  local -a seq=("TERM:2" "KILL:2")
  R=refused
  if ! read_proc "$pid" || [[ $P_STATE == Z || $P_STATE == X ]]; then log "PID_GONE $tag"; R=gone; return; fi
  start=$P_START
  if [[ -n $want_start && $want_start != 0 && $start != "$want_start" ]]; then
    log "PID_REFUSED pid_reused $tag"; return
  fi
  cur=$(readlink "/proc/$pid/exe" 2>/dev/null) || { log "PID_REFUSED no_exe $tag"; return; }
  if [[ -n $want && $cur != "$want" ]]; then log "PID_REFUSED identity_mismatch $tag"; return; fi
  start_ms=$(( BTIME * 1000 + start * 1000 / CLK_TCK ))
  if (( start_ms > ts + 2000 )); then log "PID_REFUSED pid_reused $tag"; return; fi   # started after the write: recycled PID
  if [[ -n ${PROT[$pid]:-} || $PROTECTED_EXES == *" ${cur##*/} "* ]]; then log "PID_REFUSED protected_process $tag exe=$cur"; return; fi

  # Time-consistent identity check: ensure the process has not exec'd or changed its command/cmdline since the write
  cur_comm=$(<"/proc/$pid/comm") 2>/dev/null || cur_comm=''
  if [[ $role == writer && -n $want_comm && $cur_comm != "$want_comm" ]]; then
    log "PID_REFUSED comm_changed $tag comm=$cur_comm expected=$want_comm"; return
  fi
  cur_cmd=$(cmdline_hex "$pid")
  if [[ $role == writer && -n $want_cmd && $cur_cmd != "$want_cmd" ]]; then
    log "PID_REFUSED cmdline_changed $tag exe=$cur"; return
  fi

  # Time-consistent interactive check: if classified as interactive either at detection time OR right now, refuse unless allowed
  if [[ $det_int == 1 ]] || is_interactive "$pid" "$cur"; then
    [[ $KILL_INTERACTIVE == 1 ]] || { log "KILL_PID_REFUSED interactive_shell $tag exe=$cur (set FIM_KILL_INTERACTIVE=1 to allow)"; return; }
    seq=("HUP:1" "KILL:2")     # interactive shells ignore SIGTERM
  fi
  if ! read_proc "$pid" || [[ $P_START != "$start" || $(readlink "/proc/$pid/exe" 2>/dev/null) != "$cur" ]]; then
    log "PID_REFUSED identity_changed $tag"; return
  fi
  if [[ $role == writer && -n $want_cmd && $(cmdline_hex "$pid") != "$want_cmd" ]]; then
    log "PID_REFUSED identity_changed $tag"; return
  fi
  log "PID_MATCH $tag exe=$cur"
  if [[ $DRY_RUN == 1 ]]; then log "PID_DRY_RUN $tag"; return; fi
  terminate "$pid" "$start" "${seq[@]}"
}
KILL_PARENT=${FIM_KILL_PARENT:-0}; KILL_INTERACTIVE=${FIM_KILL_INTERACTIVE:-0}; DRY_RUN=${FIM_DRY_RUN:-0}

process_pending() {
  local recs='' ts pid ppid euid user exe comm path st dint chex auid_info pexe peuid
  if [[ -s $PENDING ]]; then recs=$(<"$PENDING"); : >"$PENDING"; fi
  [[ -n $recs ]] || return 0
  load_authorized
  # 4th field in writer.stat is the effective actor UID (euid) recorded by fim_detect.sh.
  # Re-check authorization strictly against euid (unknown/non-numeric euid is always unauthorized).
  while IFS=$RS read -r ts pid ppid euid user exe comm path st dint chex auid_info; do
    [[ $pid =~ ^[0-9]+$ && $ts =~ ^[0-9]+$ ]] || continue
    if [[ $euid =~ ^[0-9]+$ && -n ${AUTH[$euid]:-} ]]; then log "SKIP pid=$pid user=$user euid=$euid is authorized here"; continue; fi
    log "KILL_REQUEST pid=$pid user=$user euid=$euid auid=${auid_info:-unknown} exe=$exe path=$path"
    respond "$pid" "$exe" "$ts" writer "$comm" "${st:-0}" "${dint:-u}" "${chex:-}"
    [[ $R == killed ]] && KILLED=$((KILLED+1))
    # If the writer already exited (e.g. a short-lived child command in a loop script),
    # check its parent if FIM_KILL_PARENT=1 OR if the parent is a non-interactive shell script with the same effective UID.
    if [[ $R == gone && $ppid =~ ^[0-9]+$ ]] && (( ppid > 1 )); then
      pexe=$(readlink "/proc/$ppid/exe" 2>/dev/null) || pexe=''
      peuid=$(proc_euid "$ppid") || peuid=''
      if [[ $KILL_PARENT == 1 ]] || { [[ -n $pexe && $SHELLS == *" ${pexe##*/} "* && -n $peuid && $peuid == "$euid" ]] && ! is_interactive "$ppid" "$pexe"; }; then
        respond "$ppid" '' "$ts" parent
        [[ $R == killed ]] && KILLED=$((KILLED+1))
      fi
    fi
  done <<<"$recs"
}

# ---------------------------------------------------------------- restore
# Every command below that touches the target is run directly by this script (no pipes
# into writers, no rsync, no command substitution around a writer), so the audit log
# shows it as a child of this PID.
restore_meta() {   # src dst: restore owner, mode, and extended POSIX ACLs on an existing directory
  local src=$1 dst=$2
  cp --attributes-only -afT -- "$src" "$dst" 2>/dev/null || true
  chown --reference="$src" -- "$dst" && chmod --reference="$src" -- "$dst"
}
restore_dir_full() {   # fallback: empty the target and copy everything back, including root dir ACLs
  find "$TARGET" -mindepth 1 -delete &&
  cp -aT -- "$BASELINE" "$TARGET" &&
  restore_meta "$BASELINE" "$TARGET"
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
  # 2. paths whose manifest records (stat, ACL, or sha256) differ
  cur=$(mktemp "$STATE/.restore.XXXXXX") || return 1
  manifest "$TARGET" >"$cur" 2>/dev/null
  while IFS= read -r line; do
    if [[ $line =~ ^[0-9a-f]{64}\ \ \./(.*)$ ]]; then
      rel=${BASH_REMATCH[1]}
    elif [[ $line == $'ACL\t'* ]]; then
      rel=${line#*$'\t'}; rel=${rel%%$'\t'*}
      [[ $rel == . ]] && rel='' || rel=${rel#./}
    else
      line=${line#*$'\t'}; line=${line#*$'\t'}; line=${line#*$'\t'}; line=${line#*$'\t'}
      rel=${line%%$'\t'*}
    fi
    CH["/$rel"]=1       # leading '/' so the root directory (empty rel) is a valid key
  done < <(diff --old-line-format='%L' --new-line-format='%L' --unchanged-line-format='' \
                <(tr '\0' '\n' <"$MANIFEST") <(tr '\0' '\n' <"$cur"))
  rm -f -- "$cur"
  # 3. copy them back, parents before children
  while IFS= read -r -d '' rel; do
    rel=${rel#/}
    if [[ -z $rel ]]; then restore_meta "$BASELINE" "$TARGET"; continue; fi
    src=$BASELINE/$rel; dst=$TARGET/$rel
    [[ -e $src || -L $src ]] || continue
    if [[ -d $src && ! -L $src ]]; then
      if [[ -d $dst && ! -L $dst ]]; then restore_meta "$src" "$dst" || return 1
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
    if tmp=$(mktemp "$parent/.fim-restore.XXXXXX"); then
      cp -afT -- "$BASELINE/item" "$tmp" && mv -fT -- "$tmp" "$TARGET" || { rm -f -- "$tmp"; rc=1; }
    else
      rc=1
    fi
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
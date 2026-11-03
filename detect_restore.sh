#!/usr/bin/env bash
# FIM v7: persistent baseline, SHA-256 + metadata manifest, recursive monitoring,
# audit-assisted response, rebaseline/status/restore, reconciliation and recovery.
set -Eeuo pipefail
umask 077

usage() {
  cat >&2 <<USAGE
Usage:
  sudo $0 [--rebaseline|--status|--restore] <file-or-directory>
  sudo $0 <file-or-directory>             # start monitoring

The first run creates a persistent baseline. --rebaseline intentionally trusts
current contents as the new baseline. Stop the monitor before rebaselining.

Optional environment for process termination (see detect_kill.sh):
  FIM_KILL_INTERACTIVE=1  FIM_DRY_RUN=1  FIM_KILL_PARENT=1  FIM_AUDIT_WAIT=<sec>
  e.g.  sudo env FIM_KILL_INTERACTIVE=1 $0 <file-or-directory>
USAGE
  exit 2
}
MODE=monitor
case ${1:-} in
  --rebaseline) MODE=rebaseline; shift;;
  --status) MODE=status; shift;;
  --restore) MODE=restore; shift;;
esac
[[ $# -eq 1 ]] || usage
[[ $EUID -eq 0 ]] || { echo 'Run with sudo/root.' >&2; exit 1; }
for c in realpath auditctl ausearch rsync sha256sum install inotifywait python3 flock; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing dependency: $c" >&2; exit 1; }
done
TARGET=$(realpath -e -- "$1")
[[ "$TARGET" != / && ( -f "$TARGET" || -d "$TARGET" ) ]] || { echo 'Target must be an existing regular file or directory, not /.' >&2; exit 1; }
[[ ! -L "$1" ]] || { echo 'Monitor the resolved target directly; symlink roots are not accepted.' >&2; exit 1; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
KILL_SCRIPT="$SCRIPT_DIR/detect_kill.sh"
[[ -f "$KILL_SCRIPT" ]] || { echo 'detect_kill.sh must be beside this script.' >&2; exit 1; }
STATE_ROOT=/var/lib/fim-monitor
LOG_ROOT=/var/log/fim-monitor
install -d -o root -g root -m 700 "$STATE_ROOT" "$LOG_ROOT"
LOG_FILE="$LOG_ROOT/incidents.log"
TARGET_ID=$(printf '%s' "$TARGET" | sha256sum | awk '{print $1}')
STATE_DIR="$STATE_ROOT/$TARGET_ID"; BASELINE="$STATE_DIR/baseline"; MANIFEST="$STATE_DIR/manifest.json"; TYPE_FILE="$STATE_DIR/type"
# The target must not contain, or lie inside, the monitor's own state/log
# directories: its own writes would look like tampering (and a restore with
# --delete could destroy its state).
overlaps() { case "$1/" in "$2"/*) return 0;; esac; case "$2/" in "$1"/*) return 0;; esac; return 1; }
for guarded in "$STATE_ROOT" "$LOG_ROOT"; do
  if overlaps "$TARGET" "$guarded"; then echo "Target overlaps FIM state/log directory $guarded." >&2; exit 1; fi
done
TYPE=file; [[ -d "$TARGET" ]] && TYPE=directory
log() { printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "$LOG_FILE"; }

# Manifest records relative path, object type, SHA-256 for regular files, mode,
# uid/gid, mtime and symlink target. JSON preserves arbitrary filename bytes via surrogate escapes.
make_manifest() {
  python3 - "$1" "$2" <<'PY'
import os,sys,json,hashlib,stat
root,out=sys.argv[1:]
def entry(path, rel):
    s=os.lstat(path); m={'p':rel,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime_ns':s.st_mtime_ns}
    if stat.S_ISREG(s.st_mode):
        m['t']='f'; h=hashlib.sha256()
        with open(path,'rb',buffering=0) as f:
            while True:
                b=f.read(1024*1024)
                if not b: break
                h.update(b)
        m['sha256']=h.hexdigest()
    elif stat.S_ISDIR(s.st_mode): m['t']='d'
    elif stat.S_ISLNK(s.st_mode): m['t']='l'; m['link']=os.readlink(path)
    else: m['t']='special'
    return m
items=[]
if os.path.isdir(root) and not os.path.islink(root):
    for base,dirs,files in os.walk(root,topdown=True,followlinks=False):
        dirs.sort(); files.sort()
        for n in list(dirs):
            p=os.path.join(base,n); rel=os.path.relpath(p,root)
            if os.path.islink(p): dirs.remove(n); items.append(entry(p,rel))
            else: items.append(entry(p,rel))
        for n in files: items.append(entry(os.path.join(base,n),os.path.relpath(os.path.join(base,n),root)))
else: items=[entry(root,'.')]
items.sort(key=lambda x:x['p'])
tmp=out+'.tmp'
with open(tmp,'w',encoding='utf-8') as f: json.dump(items,f,ensure_ascii=True,separators=(',',':')); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
}
manifest_diff() {
  python3 - "$1" "$2" <<'PYDIFF'
import json, sys

with open(sys.argv[1]) as f:
    a = {x["p"]: x for x in json.load(f)}

with open(sys.argv[2]) as f:
    b = {x["p"]: x for x in json.load(f)}

for p in sorted(a.keys() | b.keys()):
    if a.get(p) != b.get(p):
        status = "ADDED" if p not in a else "DELETED" if p not in b else "CHANGED"
        escaped = p.encode("unicode_escape").decode()
        print(f"{status}\t{escaped}")
PYDIFF
}
create_baseline() {
  local tmp="$STATE_DIR/baseline.new"
  rm -rf -- "$tmp"; mkdir -m 700 -- "$tmp"
  if [[ "$TYPE" == file ]]; then cp -a -- "$TARGET" "$tmp/item"; else rsync -aHAX --numeric-ids -- "$TARGET/" "$tmp/"; fi
  rm -rf -- "$BASELINE"; mv -- "$tmp" "$BASELINE"
  printf '%s\n' "$TYPE" > "$TYPE_FILE"; chmod 600 "$TYPE_FILE"
  make_manifest "$TARGET" "$MANIFEST"
  chmod 600 "$MANIFEST"; log "BASELINE_CREATED target=$TARGET"
}
restore_baseline() {
  if [[ "$TYPE" == file ]]; then
    local parent; parent=$(dirname -- "$TARGET"); mkdir -p -- "$parent"
    local tmp; tmp=$(mktemp "$parent/.fim-restore.XXXXXX")
    cp -a -- "$BASELINE/item" "$tmp" && mv -fT -- "$tmp" "$TARGET"
  else
    mkdir -p -- "$TARGET"
    rsync -aHAX --numeric-ids --delete -- "$BASELINE/" "$TARGET/"
  fi
  local check; check=$(mktemp "$STATE_DIR/check.XXXXXX")
  make_manifest "$TARGET" "$check"
  if cmp -s -- "$MANIFEST" "$check"; then log "RESTORE_VERIFIED target=$TARGET"; rm -f -- "$check"; return 0; fi
  log "ERROR restore verification failed target=$TARGET"; rm -f -- "$check"; return 1
}

if [[ "$MODE" == rebaseline ]]; then
  install -d -m 700 "$STATE_DIR"; create_baseline; echo 'New baseline accepted.'; exit 0
fi
[[ -f "$TYPE_FILE" && -f "$MANIFEST" && -d "$BASELINE" ]] || { if [[ "$MODE" == status || "$MODE" == restore ]]; then echo 'No baseline exists.' >&2; exit 1; else install -d -m 700 "$STATE_DIR"; create_baseline; fi; }
[[ $(<"$TYPE_FILE") == "$TYPE" ]] || { echo 'Target type differs from stored baseline. Use --rebaseline.' >&2; exit 1; }
if [[ "$MODE" == status ]]; then
  TMP=$(mktemp "$STATE_DIR/status.XXXXXX"); make_manifest "$TARGET" "$TMP"
  if cmp -s "$MANIFEST" "$TMP"; then echo 'INTEGRITY: OK'; else echo 'INTEGRITY: CHANGED'; manifest_diff "$MANIFEST" "$TMP"; fi
  rm -f -- "$TMP"; exit 0
fi
if [[ "$MODE" == restore ]]; then restore_baseline; exit $?; fi

LOCK="$STATE_DIR/monitor.lock"
exec 9>"$LOCK"; flock -n 9 || { echo 'A monitor already holds this target lock.' >&2; exit 1; }
KEY="fim_${TARGET_ID:0:16}_$$"
RULES=()
if [[ "$TYPE" == file ]]; then
  auditctl -w "$TARGET" -p wa -k "$KEY" || { echo 'Could not install audit watch.' >&2; exit 1; }
  RULES+=("file")
else
  # dir= is recursive for the watched tree on supported Linux Audit kernels.
  auditctl -a always,exit -F arch=b64 -F dir="$TARGET" -F perm=wa -k "$KEY" || { echo 'Could not install recursive audit rule.' >&2; exit 1; }
  RULES+=("dir64")
  if [[ $(uname -m) == x86_64 ]]; then auditctl -a always,exit -F arch=b32 -F dir="$TARGET" -F perm=wa -k "$KEY" 2>/dev/null && RULES+=("dir32") || log 'WARN 32-bit audit rule unavailable'; fi
fi
WATCH_PID=''; WATCH_FD=''; STOPPING=0
LAST_RESTORE_TS=0   # audit events at or before this time (our own restores) are ignored
remove_rules() {
  for r in "${RULES[@]}"; do
    case $r in file) auditctl -W "$TARGET" -p wa -k "$KEY" >/dev/null 2>&1 || true;;
      dir64) auditctl -d always,exit -F arch=b64 -F dir="$TARGET" -F perm=wa -k "$KEY" >/dev/null 2>&1 || true;;
      dir32) auditctl -d always,exit -F arch=b32 -F dir="$TARGET" -F perm=wa -k "$KEY" >/dev/null 2>&1 || true;; esac
  done
}
stop_watcher() { if [[ -n "$WATCH_PID" ]]; then kill "$WATCH_PID" 2>/dev/null || true; wait "$WATCH_PID" 2>/dev/null || true; WATCH_PID=''; fi; }
cleanup() { STOPPING=1; stop_watcher; remove_rules; log "MONITOR_STOPPED target=$TARGET"; }
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
log "MONITOR_STARTED target=$TARGET audit_key=$KEY"
# Users allowed to change the target; everyone else is reverted and killed.
# detect_kill.sh re-reads this file on every incident, so edits apply immediately.
AUTH_FILE=${FIM_AUTHORIZED_FILE:-/etc/fim-monitor/authorized_users}
export FIM_AUTHORIZED_FILE=$AUTH_FILE
if [[ ! -e "$AUTH_FILE" ]]; then
  install -d -m 755 -- "$(dirname -- "$AUTH_FILE")"
  printf '%s\n' '# Users allowed to change monitored files (login names or numeric uids).' \
    '# Changes by anyone else are reverted and the writing process is killed.' \
    '# Matching uses the LOGIN user, so "sudo" does not change who made the change.' > "$AUTH_FILE"
  chmod 600 "$AUTH_FILE"; log "NOTE created $AUTH_FILE with no authorized users"
fi
log "AUTHORIZED_USERS file=$AUTH_FILE listed=[$( { sed 's/#.*//' "$AUTH_FILE" 2>/dev/null; printf '%s\n' "${FIM_AUTHORIZED_USERS:-}"; } | tr -s ' ,\t\n' ' ')]"
# Without a running auditd and enabled kernel auditing no writer PID can be found.
grep -qsx auditd /proc/[0-9]*/comm || log 'WARN auditd does not appear to be running; writer PID cannot be resolved'
AUDIT_STATUS=$(auditctl -s 2>/dev/null || true)
grep -Eq '^enabled (1|2)' <<<"$AUDIT_STATUS" || log 'WARN kernel auditing appears disabled (try: auditctl -e 1)'

# Keeping an authorized change = adopting a snapshot of the current contents as the
# new baseline. Order matters: snapshot first, then classify the writers AGAIN, so
# the snapshot can only hold changes whose audit events were already attributed.
SNAP_DIR="$STATE_DIR/baseline.new"; SNAP_MANIFEST="$STATE_DIR/snapshot.json"
snapshot_current() {
  rm -rf -- "$SNAP_DIR"; mkdir -m 700 -- "$SNAP_DIR"
  if [[ "$TYPE" == file ]]; then
    cp -a -- "$TARGET" "$SNAP_DIR/item" && make_manifest "$SNAP_DIR/item" "$SNAP_MANIFEST"
  else
    rsync -aHAX --numeric-ids -- "$TARGET/" "$SNAP_DIR/" && make_manifest "$SNAP_DIR" "$SNAP_MANIFEST"
  fi
}
adopt_snapshot() {
  rm -rf -- "$BASELINE"; mv -- "$SNAP_DIR" "$BASELINE"
  mv -f -- "$SNAP_MANIFEST" "$MANIFEST"; chmod 600 "$MANIFEST"
  log "BASELINE_UPDATED target=$TARGET (authorized change kept)"
}
discard_snapshot() { rm -rf -- "$SNAP_DIR" "$SNAP_MANIFEST"; }
# One reconcile pass; a transient failure must never stop the monitor (set -e).
reconcile() { reconcile_once || true; return 0; }
reconcile_once() {
  local cur rc=0; cur=$(mktemp "$STATE_DIR/current.XXXXXX")
  if ! make_manifest "$TARGET" "$cur"; then log 'ERROR manifest generation failed'; rm -f "$cur"; return 0; fi
  if cmp -s "$MANIFEST" "$cur"; then rm -f "$cur"; return 0; fi
  log 'ALERT filesystem integrity mismatch'
  while IFS=$'\t' read -r status escaped; do
    [[ -n "$status" ]] && log "CHANGE status=$status path_escaped=$escaped"
  done < <(manifest_diff "$MANIFEST" "$cur")
  # Identify and stop the writer BEFORE rolling back, so it cannot immediately
  # re-tamper. One call per incident; detect_kill.sh matches audit events for
  # the whole target. stdin MUST NOT be the pipe feeding this loop (ausearch
  # would read it instead of the audit log), hence </dev/null.
  # Exit 10 = every writer found is an authorized user: keep the change.
  FIM_MONITOR_PID=$$ bash "$KILL_SCRIPT" "$TARGET" "$KEY" "$LAST_RESTORE_TS" </dev/null || rc=$?
  if (( rc == 10 )); then
    if snapshot_current; then
      rc=0
      FIM_MONITOR_PID=$$ bash "$KILL_SCRIPT" "$TARGET" "$KEY" "$LAST_RESTORE_TS" </dev/null || rc=$?
      if (( rc == 10 )); then adopt_snapshot; rm -f -- "$cur"; return 0; fi
      discard_snapshot   # an unauthorized writer showed up meanwhile: revert instead
    else
      discard_snapshot; log 'WARN could not snapshot authorized change; reverting'; rc=1
    fi
  fi
  (( rc == 0 )) || log 'WARN process response unsuccessful/ambiguous (reverting)'
  if restore_baseline; then log 'INCIDENT_RESOLVED'; else log 'CRITICAL restore failed; manual intervention required'; fi
  LAST_RESTORE_TS=$(date +%s.%N)
  rm -f -- "$cur"
}
start_watcher() {
  stop_watcher
  local root="$TARGET"; local -a args=()
  if [[ "$TYPE" == file ]]; then root=$(dirname -- "$TARGET"); else args=(-r); fi
  coproc FIMWATCH { exec inotifywait -m -q "${args[@]}" -e modify,attrib,close_write,create,delete,move,delete_self,move_self,unmount --format '%e' -- "$root"; }
  WATCH_PID=$FIMWATCH_PID; WATCH_FD=${FIMWATCH[0]}
}
start_watcher
last_scan=$SECONDS
while true; do
  event=''
  if IFS= read -r -t 1 -u "$WATCH_FD" event; then
    # Debounce event bursts; full manifest reconciliation is authoritative.
    while IFS= read -r -t 0.15 -u "$WATCH_FD" event; do :; done
    reconcile; last_scan=$SECONDS
  else
    if ! kill -0 "$WATCH_PID" 2>/dev/null; then log 'WARN inotify watcher exited; restarting'; start_watcher; fi
    if (( SECONDS-last_scan >= 5 )); then reconcile; last_scan=$SECONDS; fi
  fi
done
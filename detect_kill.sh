#!/usr/bin/env bash
# detect_kill.sh - find and terminate the process that modified a monitored path.
#
#   detect_kill.sh <monitored-path> <audit-key> [since-epoch]
#
# Called by detect_restore.sh once per incident. Searches the audit log (events tagged with
# <audit-key>) for successful write/create/delete/rename/attribute events that
# touched <monitored-path> (or anything below it, for a directory) after
# <since-epoch>, then terminates the responsible process.
#
# Environment (all optional):
#   FIM_MONITOR_PID     PID of the monitor; it and its ancestors are never targeted
#   FIM_AUDIT_WAIT      seconds to wait for the audit event to appear   (default 3)
#   FIM_EVENT_WINDOW    ignore audit events older than this many seconds (default 30)
#   FIM_KILL_PARENT=1   if the writer already exited, try its parent (e.g. a loop
#                       script running sed -i), subject to the same safety checks
#   FIM_KILL_INTERACTIVE=1  also terminate a writer that is an interactive shell
#                       (e.g. a loop typed at a terminal prompt); that closes the
#                       person's terminal session. Default: refuse.
#   FIM_DRY_RUN=1       log the match but send no signal
#
# Authorization: each audited write is attributed to the user who LOGGED IN
# (audit "auid", which survives sudo/su); if auid is unset the process uid is
# used. Users listed in FIM_AUTHORIZED_FILE (default /etc/fim-monitor/authorized_users,
# one user name or numeric uid per line, '#' comments; must be root-owned and not
# group/world-writable) or in FIM_AUTHORIZED_USERS (comma/space separated) may
# change the target. Writers outside that list are terminated; if every writer
# found is authorized nothing is killed and the exit status is 10, which tells
# fim.sh to keep the change and adopt it as the new baseline.
#
# Exit status: 0 = unauthorized writer identified and handled (terminated, or gone),
#              1 = nothing resolved / refused / signal failed (caller reverts),
#              2 = usage, 10 = all writers authorized (caller keeps the change).
set -uo pipefail

[[ $# -ge 2 && $# -le 3 ]] || {
    echo "Usage: $0 <monitored-path> <audit-key> [since-epoch]" >&2
    exit 2
}
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
for c in ausearch python3 realpath install; do
    command -v "$c" >/dev/null 2>&1 || { echo "Missing dependency: $c" >&2; exit 1; }
done

TARGET=$(realpath -m -- "$1")
LOG_ROOT=/var/log/fim-monitor
install -d -o root -g root -m 700 "$LOG_ROOT"
export FIM_LOG_FILE="$LOG_ROOT/incidents.log"

exec python3 -I - "$TARGET" "$2" "${3:-0}" <<'PY'
import datetime
import os
import pwd
import re
import select
import signal
import subprocess
import sys
import time

TARGET = os.path.realpath(sys.argv[1])
KEY = sys.argv[2]
try:
    SINCE = float(sys.argv[3])
except ValueError:
    SINCE = 0.0
IS_DIR = os.path.isdir(TARGET)


def env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


try:
    MONITOR_PID = int(os.environ.get("FIM_MONITOR_PID") or 0)
except ValueError:
    MONITOR_PID = 0
AUDIT_WAIT = env_float("FIM_AUDIT_WAIT", 3)
EVENT_WINDOW = env_float("FIM_EVENT_WINDOW", 30)
KILL_PARENT = os.environ.get("FIM_KILL_PARENT") == "1"
DRY_RUN = os.environ.get("FIM_DRY_RUN") == "1"
KILL_INTERACTIVE = os.environ.get("FIM_KILL_INTERACTIVE") == "1"
LOG_FILE = os.environ.get("FIM_LOG_FILE", "/var/log/fim-monitor/incidents.log")

# Never terminate these, whatever the audit log says.
PROTECTED_EXES = {"systemd", "init", "auditd", "systemd-journald", "kthreadd"}
SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "mksh", "ash", "tcsh", "csh"}


def log(msg):
    line = "[%s] %s" % (
        datetime.datetime.now().astimezone().isoformat(timespec="seconds"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- /proc helpers
CLK_TCK = os.sysconf("SC_CLK_TCK")


def boot_time():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


BTIME = boot_time()


def read_stat(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            s = f.read()
        rest = s[s.rfind(")") + 2:].split()
        return {"state": rest[0], "ppid": int(rest[1]), "start": int(rest[19])}
    except (OSError, ValueError, IndexError):
        return None


def start_epoch(st):
    return None if BTIME is None else BTIME + st["start"] / CLK_TCK


def exe_of(pid):
    try:
        return os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return None


def cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            raw = f.read()
    except OSError:
        return []
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]


def stdin_is_tty(pid):
    try:
        t = os.readlink("/proc/%d/fd/0" % pid)
    except OSError:
        return False
    return t.startswith(("/dev/pts/", "/dev/tty")) or t == "/dev/console"


def norm(p):
    return os.path.realpath(p)


def ancestors():
    seen = {os.getpid()}
    pid = os.getppid()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        st = read_stat(pid)
        if not st:
            break
        pid = st["ppid"]
    return seen


# The monitor, this script and everything above them (sudo, the operator's shell,
# terminal, sshd session...) are never candidates.
PROTECTED_PIDS = ancestors() | {MONITOR_PID}

# ------------------------------------------------------------------ authorization
AUTH_FILE = os.environ.get("FIM_AUTHORIZED_FILE", "/etc/fim-monitor/authorized_users")
UNSET_AUID = 4294967295


def user_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def load_authorized():
    """UIDs allowed to change the target (re-read on every incident)."""
    tokens = []
    try:
        st = os.stat(AUTH_FILE)
        if st.st_uid != 0 or st.st_mode & 0o022:
            log("WARN %s must be owned by root and not group/world-writable; ignoring it"
                % AUTH_FILE)
        else:
            with open(AUTH_FILE) as f:
                for line in f:
                    tokens += line.split("#", 1)[0].split()
    except FileNotFoundError:
        pass
    except OSError as e:
        log("WARN cannot read %s: %s" % (AUTH_FILE, e))
    tokens += os.environ.get("FIM_AUTHORIZED_USERS", "").replace(",", " ").split()
    uids = set()
    for t in tokens:
        if t.isdigit():
            uids.add(int(t))
            continue
        try:
            uids.add(pwd.getpwnam(t).pw_uid)
        except KeyError:
            log("WARN authorized user %r does not exist" % t)
    return uids


AUTHORIZED_UIDS = load_authorized()


def num(rec, name):
    try:
        return int(field(rec, name))
    except (TypeError, ValueError):
        return None


def shell_kind(pid, exe):
    """'interactive' for a shell a person is sitting in, 'command' for a shell
    running -c, a script, or piped stdin; None if the process is not a shell."""
    if os.path.basename(exe) not in SHELLS:
        return None
    argv = cmdline(pid)
    login = bool(argv) and argv[0].startswith("-")
    has_c = flag_i = operand = False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            operand = i + 1 < len(argv)
            break
        if a in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if len(a) > 1 and a[0] in "-+":
            if a[0] == "-" and "c" in a[1:]:
                has_c = True
            if a[0] == "-" and "i" in a[1:]:
                flag_i = True
            i += 1
            continue
        operand = True
        break
    if has_c or operand:
        return "command"
    if flag_i or login:
        return "interactive"
    return "interactive" if stdin_is_tty(pid) else "command"


# ------------------------------------------------------------------ audit parsing
EVENT_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def field(rec, name, path=False):
    """Value of name=... in a raw audit record. Raw audit uses lower-case field
    names (syscall=257, not SYSCALL=). Hex-encoded paths are decoded."""
    m = re.search(r'(?:^|\s)' + re.escape(name) + r'=("(?:[^"\\]|\\.)*"|\S+)', rec)
    if not m:
        return None
    v = m.group(1)
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    if path and HEX_RE.match(v):
        try:
            return bytes.fromhex(v).decode("utf-8", "surrogateescape")
        except ValueError:
            pass
    return v


def under_target(p):
    return p == TARGET or (IS_DIR and p.startswith(TARGET.rstrip("/") + "/"))


def read_events():
    # --input-logs is essential: when stdin is a pipe (as it is when fim.sh calls
    # this from inside a "while read ... < <(...)" loop) ausearch otherwise reads
    # the pipe instead of the audit log and finds nothing.
    try:
        r = subprocess.run(
            ["ausearch", "--input-logs", "-k", KEY, "-ts", "recent", "--raw"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
    except OSError:
        return {}
    groups = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        m = EVENT_RE.search(line)
        if m:
            groups.setdefault((float(m.group(1)), int(m.group(2))), []).append(line)
    return groups


def find_candidates():
    now = time.time()
    best = {}
    for (ts, serial), recs in read_events().items():
        if ts <= SINCE or now - ts > EVENT_WINDOW:
            continue
        cwd, names, sysrec = None, [], None
        for rec in recs:
            if rec.startswith("type=CWD "):
                cwd = field(rec, "cwd", path=True)
            elif rec.startswith("type=PATH "):
                n = field(rec, "name", path=True)
                if n and n != "(null)":
                    names.append(n)
            elif rec.startswith("type=SYSCALL "):
                sysrec = rec
        if sysrec is None or field(sysrec, "success") != "yes":
            continue
        matched = None
        for n in names:
            full = os.path.normpath(n if os.path.isabs(n) else os.path.join(cwd or "/", n))
            for p in (full, os.path.realpath(full)):
                if under_target(p):
                    matched = p
                    break
            if matched:
                break
        if not matched:
            continue
        try:
            pid = int(field(sysrec, "pid"))
            ppid = int(field(sysrec, "ppid"))
        except (TypeError, ValueError):
            continue
        exe = field(sysrec, "exe", path=True)
        if not exe:
            continue
        # Skip init, the monitor, this script and its ancestors, and the monitor's
        # own children (rsync/cp/mv doing a restore).
        if pid <= 1 or pid in PROTECTED_PIDS or ppid == MONITOR_PID:
            continue
        auid, uid = num(sysrec, "auid"), num(sysrec, "uid")
        actor = auid if auid not in (None, UNSET_AUID, -1) else uid
        ev = {"ts": ts, "id": "%.3f:%d" % (ts, serial), "pid": pid, "ppid": ppid,
              "exe": exe, "comm": field(sysrec, "comm", path=True) or "unknown",
              "path": matched, "actor": actor,
              "actor_name": user_name(actor) if actor is not None else "unknown",
              "authorized": actor is not None and actor in AUTHORIZED_UIDS}
        if pid not in best or ts > best[pid]["ts"]:
            best[pid] = ev
    return sorted(best.values(), key=lambda e: e["ts"], reverse=True)


# --------------------------------------------------------------------- terminating
def signal_proc(pidfd, pid, sig):
    if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(pidfd, sig)
    else:
        os.kill(pid, sig)


def has_exited(pidfd, pid, start):
    if pidfd is not None:
        r, _, _ = select.select([pidfd], [], [], 0)
        if r:
            return True
    st = read_stat(pid)
    return st is None or st["start"] != start or st["state"] in ("Z", "X")


def wait_exit(pidfd, pid, start, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if has_exited(pidfd, pid, start):
            return True
        time.sleep(0.05)
    return has_exited(pidfd, pid, start)


TERM_SEQUENCE = ((signal.SIGTERM, "TERM", 2.0), (signal.SIGKILL, "KILL", 2.0))
# Interactive shells ignore SIGTERM; SIGHUP is what a closing terminal sends.
TTY_SEQUENCE = ((signal.SIGHUP, "HUP", 1.0), (signal.SIGKILL, "KILL", 2.0))


def terminate(pid, pidfd, start, tag, sequence=TERM_SEQUENCE):
    for sig, name, timeout in sequence:
        try:
            signal_proc(pidfd, pid, sig)
        except ProcessLookupError:
            log("PID_EXITED %s" % tag)
            return "gone"
        except OSError as e:
            log("PID_%s_FAILED %s error=%s" % (name, tag, e))
            return "failed"
        if wait_exit(pidfd, pid, start, timeout):
            log("PID_TERMINATED signal=%s %s" % (name, tag))
            return "killed"
    log("PID_KILL_FAILED %s still-running" % tag)
    return "failed"


def respond(pid, expected_exe, ev, role):
    tag = "pid=%d role=%s" % (pid, role)
    st = read_stat(pid)
    if st is None or st["state"] in ("Z", "X"):
        log("PID_GONE %s" % tag)
        return "gone"
    cur = exe_of(pid)
    if cur is None or (expected_exe is not None and norm(cur) != norm(expected_exe)):
        log("PID_REFUSED identity_mismatch %s" % tag)
        return "refused"
    # A process that started after the audited write cannot be the writer: the
    # PID was recycled.
    se = start_epoch(st)
    if se is not None and se > ev["ts"] + 2.0:
        log("PID_REFUSED pid_reused %s" % tag)
        return "refused"
    if pid in PROTECTED_PIDS or os.path.basename(cur) in PROTECTED_EXES:
        log("PID_REFUSED protected_process %s exe=%s" % (tag, cur))
        return "refused"
    sequence = TERM_SEQUENCE
    if shell_kind(pid, cur) == "interactive":
        if not KILL_INTERACTIVE:
            log("PID_REFUSED interactive_shell %s exe=%s (set FIM_KILL_INTERACTIVE=1 to allow)"
                % (tag, cur))
            return "refused"
        sequence = TTY_SEQUENCE

    pidfd = None
    try:
        pidfd = os.pidfd_open(pid)  # Python 3.9+/Linux 5.3+; falls back to os.kill
    except (AttributeError, OSError):
        pidfd = None
    st2 = read_stat(pid)
    if st2 is None or st2["start"] != st["start"] or exe_of(pid) != cur:
        if pidfd is not None:
            os.close(pidfd)
        log("PID_REFUSED identity_changed %s" % tag)
        return "refused"

    log("PID_MATCH event=%s pid=%d ppid=%d comm=%s exe=%s path=%s role=%s"
        % (ev["id"], pid, ev["ppid"], ev["comm"], cur, ev["path"], role))
    try:
        if DRY_RUN:
            log("PID_DRY_RUN %s" % tag)
            return "refused"
        return terminate(pid, pidfd, st["start"], tag, sequence)
    finally:
        if pidfd is not None:
            os.close(pidfd)


def main():
    deadline = time.time() + AUDIT_WAIT
    while True:
        cands = find_candidates()
        if cands or time.time() >= deadline:
            break
        time.sleep(0.2)  # auditd may not have written the event yet
    if not cands:
        log("PID_UNRESOLVED path=%s reason=no-external-write-audit-event" % TARGET)
        return 1
    if all(e["authorized"] for e in cands):
        time.sleep(0.3)  # let a concurrent unauthorized writer's event reach the log
        cands = find_candidates() or cands
    for e in cands:
        if e["authorized"]:
            log("AUTHORIZED_WRITER user=%s pid=%d exe=%s path=%s"
                % (e["actor_name"], e["pid"], e["exe"], e["path"]))
    unauth = [e for e in cands if not e["authorized"]]
    if not unauth:
        log("CHANGE_AUTHORIZED users=%s" % ",".join(sorted({e["actor_name"] for e in cands})))
        return 10
    handled = False
    for ev in unauth:
        log("UNAUTHORIZED_WRITER user=%s pid=%d exe=%s path=%s"
            % (ev["actor_name"], ev["pid"], ev["exe"], ev["path"]))
        out = respond(ev["pid"], ev["exe"], ev, "writer")
        if out == "gone" and KILL_PARENT and ev["ppid"] > 1:
            out = respond(ev["ppid"], None, ev, "parent")
        handled = handled or out in ("killed", "gone")
    return 0 if handled else 1


try:
    sys.exit(main())
except SystemExit:
    raise
except Exception as exc:  # never crash the monitor
    log("ERROR detect_kill exception: %r" % (exc,))
    sys.exit(1)
PY
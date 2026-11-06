# File Integrity Monitor (FIM): detect, kill, restore

Two independent one-shot scripts. They share only a state directory.

## What it does
- Watches a file or directory (nested files and folders included) for unauthorized changes.
- Finds the process that made the change and records its PID.
- Kills that process and restores the original contents.
- Changes by authorized users are kept and become the new baseline.

## Scripts
| Script | Job |
|---|---|
| `fim_detect.sh` | Compares the target with the baseline. On a mismatch, finds the writer via the audit log. Unauthorized writers are recorded in `writer.stat`. Authorized changes become the new baseline. |
| `fim_restore.sh` | Kills the PIDs listed in `writer.stat`, then restores the target from the stored copy and verifies it. |

Both take the same arguments:
```
sudo ./fim_detect.sh  <file-or-dir> <state-dir> <authorized-users>
sudo ./fim_restore.sh <file-or-dir> <state-dir> <authorized-users>
```
- `file-or-dir`: absolute path of the target (not a symlink).
- `state-dir`: a directory outside the target, where state is kept.
- `authorized-users`: comma-separated login names or uids, or a path to a root-owned file with one user per line.

## How it works
- **Baseline:** the first run copies the target to `<state-dir>/original/` and writes `original.manifest` (SHA-256 of every file, plus type, mode, uid, gid, and POSIX Access Control Lists via `getfacl`).
- **Detection:** each run rebuilds the manifest and compares it with the baseline. Added, deleted, modified, permission-changed, and ACL-changed items all count.
- **Authorization & Identity Semantics (Effective UID):**
  - Authorization is strictly fail-closed based on the process **Effective UID (`euid`)** extracted from the kernel audit event (`type=SYSCALL`).
  - If `euid` is unset, invalid, or absent from the authorized-users list, the modification is treated as unauthorized (`actor=unknown`).
  - The login/audit user (`auid`) and real process UID (`uid`) are parsed and retained for forensic logging and debugging (`auid=...`) but **never** determine whether a modification is authorized. This correctly handles privilege transitions such as `su` or `sudo` where session inheritance retains the original login uid.
- **Unauthorized writers** are appended to `writer.stat`. If every writer is authorized, the current contents are adopted as the new baseline.
- **Unresolved writes:** if a change has no usable PID, or no audit event at all, the detector reports `UNRESOLVED` on stderr and exits 1. Nothing is killed for it. The restorer still reverts the content, and the next cycle checks again.
- **Process Classification & Time-Consistent Safety Checks:**
  - Advanced interactive shell protection (`is_interactive` / `is_interactive_proc`) correctly distinguishes true interactive login terminals from non-interactive script executions, `-c` command strings, and forked background subshells (using `pgrp`, `sid`, `tpgid`, session leadership, and parent relationship checks).
  - Time-consistent validation matches audit `PROCTITLE` command-line hex signatures, process start ticks (`starttime`), and `comm` identifiers to guarantee that a process has not `exec`'d or mutated its identity between the write event and termination time.
  - The restorer checks each PID before killing it, skipping its own ancestors, `systemd`/`auditd`, recycled PIDs, and interactive shells (unless `FIM_KILL_INTERACTIVE=1`). It sends TERM (or HUP for interactive shells), then KILL.
- **Restore:** the target is restored from `original/` and checked against the manifest. Existing directory ACLs and metadata are fully restored in-place using `restore_meta`. The detector ignores events from this restore.

## How to run
1. Prerequisites: root, `auditd` running (`auditctl -s` shows `enabled 1`), standard tools (`find`, `sha256sum`, `flock`, `awk`, `getfacl`), and the `acl` package. `rsync` is optional.
2. Put both scripts in one folder, `chmod +x` them, and call them every 30 seconds, **detector first**:
   ```bash
   while :; do
     sudo ./fim_detect.sh  /path/to/target /var/lib/fim-state alice,bob
     sudo ./fim_restore.sh /path/to/target /var/lib/fim-state alice,bob
     sleep 30
   done
   ```
   Or run the two commands from cron or a systemd timer.
3. The first run takes the target's current contents as the trusted original, so make sure it is in a good state (including pre-configuring any required ACL permissions).

## Exit codes
Both scripts use only two codes.
| Script | Code | Meaning |
|---|---|---|
| detect | 0 | target intact, or only authorized changes (adopted as the new baseline) |
| detect | 1 | unauthorized or unresolved modification detected, or an error |
| restore | 0 | success: nothing to restore, or restored and verified |
| restore | 1 | restore failed, or an error |

## Output
- Every run ends with one summary line: `RESULT exit=<code> status=<text>`, for example `RESULT exit=1 status=ALERT - unauthorized change: 1 writer(s) registered in writer.stat`.
- No log files are written. Messages go to stdout; problems (`ERROR`, `CRITICAL`, `UNRESOLVED`, `WARN`) go to stderr.

## Files in the state directory
- `original/`: copy of the trusted contents.
- `original.manifest`: hashes, metadata, and POSIX ACL records.
- `state.meta`: key=value file (target type, target path, last audit event handled, restorer runs). Always updated atomically via temporary files and `mv`.
- `writer.stat`: PIDs waiting to be killed.
- There are no lock files; sequential running is enforced with `flock` on the state directory itself.
- The state directory must be owned by root and not group/world-writable, and it belongs to one target only.

## Sequential running
- Always run `fim_detect.sh` and then `fim_restore.sh`, one after the other. A run that finds the state directory busy prints an `ERROR` and exits 1.
- The detector ignores audit events made by the restorer (via process identity: its PID and its direct child commands during a recorded run).

## Deleted or replaced targets
- If the target is deleted, or swapped for a symlink or another kind of object, that counts as a change: it is reported and restored.

## Options (environment variables)
- `FIM_EVENT_WINDOW=120`: how far back to look in the audit log, in seconds. Keep it longer than your call interval.
- `FIM_AUDIT_WAIT=3`: seconds to wait for the audit event.
- `FIM_DRY_RUN=1`: log what would be killed, but kill nothing.
- `FIM_KILL_PARENT=1`: if the writer has already exited, try its parent (for example a loop script).
- `FIM_KILL_INTERACTIVE=1`: also kill a writer that is an interactive shell.

## Limits
- Without auditd, changes are still detected and restored, but no PID is recorded (`UNRESOLVED`).
- Services and cron jobs lacking a valid effective UID context count as unauthorized.
- Symlinks inside a directory are tracked as links and are not followed.
- POSIX ACLs (`getfacl`) and ownership/mode are fully tracked and verified.
- To accept new contents as the baseline, delete `<state-dir>/original` and run the detector again.
- To remove the audit rule, run `auditctl -l | grep fim_` and delete the matching rule.
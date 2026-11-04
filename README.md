# File Integrity Monitor (FIM): detect, kill, restore

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
- **Baseline:** the first run copies the target to `<state-dir>/original/` and writes `original.manifest` (SHA-256 of every file, plus type, mode, uid and gid).
- **Detection:** each run rebuilds the manifest and compares it with the baseline. Added, deleted, modified and permission-changed items all count.
- **Who changed it:** the detector installs a Linux audit rule once and leaves it in place. It reads the audit log to get the writer's PID, exe and login user. The login user is used, so `sudo` doesn't hide who it was.
- **Authorization:** unauthorized writers are appended to `writer.stat`. If every writer is authorized, the current contents are adopted as the new baseline.
- **Kill:** the restorer checks each PID before killing it. It skips its own ancestors, `systemd`/`auditd`, recycled PIDs and interactive shells. It sends TERM, then KILL.
- **Restore:** the target is restored from `original/` and checked against the manifest. The detector ignores events from this restore.

## How to run
1. Prerequisites: root, `auditd` running (`auditctl -s` shows `enabled 1`), and standard tools (`find`, `sha256sum`, `flock`, `awk`). `rsync` is optional.
2. Put both scripts in one folder, `chmod +x` them, and call them every 30 seconds, **detector first**:
   ```bash
   while :; do
     sudo ./fim_detect.sh  /path/to/target /var/lib/fim-state alice,bob
     sudo ./fim_restore.sh /path/to/target /var/lib/fim-state alice,bob
     sleep 30
   done
   ```
   Or run the two commands from cron or a systemd timer.
3. The first run takes the target's current contents as the trusted original, so make sure it is in a good state.

## Exit codes
| Script | Code | Meaning |
|---|---|---|
| detect | 0 | unchanged, or authorized change adopted |
| detect | 3 | unauthorized writer registered |
| detect | 4 | changed, but writer not identified |
| detect | 1 | error |
| restore | 0 | nothing to restore |
| restore | 3 | restored and verified |
| restore | 1 | restore failed |

## Files in the state directory
- `original/`: copy of the trusted contents.
- `original.manifest`: hashes and metadata.
- `writer.stat`: PIDs waiting to be killed.
- `detector.log` and `restorer.log`: logs.

## Options (environment variables)
- `FIM_EVENT_WINDOW=120`: how far back to look in the audit log, in seconds. Keep it longer than your call interval.
- `FIM_AUDIT_WAIT=3`: seconds to wait for the audit event.
- `FIM_DRY_RUN=1`: log what would be killed, but kill nothing.
- `FIM_KILL_PARENT=1`: if the writer has already exited, try its parent (for example a loop script).
- `FIM_KILL_INTERACTIVE=1`: also kill a writer that is an interactive shell.

## Limits
- Without auditd, changes are still detected and restored, but no PID is recorded (detector exit 4).
- A change made before the audit rule is first installed can't be attributed.
- Symlinks inside a directory are tracked as links and are not followed.
- Timestamps, ACLs and xattrs are not compared.
- To accept new contents as the baseline, delete `<state-dir>/original` and run the detector again.
- To remove the audit rule, run `auditctl -l | grep fim_` and delete the matching rule.
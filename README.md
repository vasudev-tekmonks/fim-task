# File Integrity Monitoring System (FIM)

## 1. Components
- `detect_restore.sh`: Detects filesystem changes, compares them with the baseline, and restores unauthorized changes.
- `detect_kill.sh`: Identifies the process responsible for a change and terminates unauthorized writers.

## 2. Change Detection
- Accepts a file or directory as an argument.
- A file argument monitors only that file.
- A directory argument monitors the entire directory recursively.
- Creates an initial baseline containing:
  - SHA-256 file hashes.
  - File and directory permissions.
  - Ownership (UID/GID).
  - Modification timestamps.
  - File types and symbolic link targets.
- Uses `inotifywait` to detect filesystem events.
- Periodically scans the target to detect missed events.
- Compares the current manifest with the stored baseline to identify changes.

## 3. Process Identification
- Uses Linux Audit (`auditd`) to track filesystem operations.
- Installs audit rules for the monitored file or directory.
- Audit events provide:
  - PID and PPID.
  - Executable path.
  - Modified file path.
  - User ID and login user ID (`auid`).
- `detect_kill.sh` searches audit logs using a unique audit key.
- Matches audit events with the modified file to identify the writer.
- Validates PID, executable path, and process start time to avoid targeting an unrelated process.

## 4. User Authorization
- Maintains an authorization list at `/etc/fim-monitor/authorized_users`.
- Supports usernames and numeric UIDs.
- Uses `auid` to identify the original logged-in user, even when `sudo` or `su` is used.
- Authorized users:
  - Changes are accepted.
  - Current contents become the new baseline.
- Unauthorized users:
  - Changes are rejected.
  - Their responsible processes are targeted for termination.

## 5. Process Termination
- `detect_restore.sh` automatically invokes `detect_kill.sh` when a change is detected.
- Validates the identified process before sending signals.
- Sends `SIGTERM` first.
- Sends `SIGKILL` if the process does not terminate.
- Protects interactive shells by default.
- If the process cannot be safely identified or terminated, the system restores the baseline instead.

## 6. File Restoration
- Restores unauthorized changes using the stored baseline.
- For individual files, copies the original file back.
- For directories, uses `rsync` to restore contents recursively.
- Removes unauthorized additions.
- Recovers deleted or modified files.
- Generates a new manifest to verify restoration.
- Logs restoration success or failure.

## 7. Logging and Storage
- Incident logs:
  `/var/log/fim-monitor/incidents.log`
- Persistent baseline and state:
  `/var/lib/fim-monitor/`
- Logs include:
  - Detected changes.
  - Authorized and unauthorized writers.
  - PID identification and termination.
  - Restoration and verification results.

## 8. Execution Commands

Start monitoring:
```bash
sudo ./detect_restore.sh /path/to/file-or-directory
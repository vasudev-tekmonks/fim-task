# File Integrity Monitoring System (FIM)

## How It Works

- The system consists of two Bash scripts:
  - `detect_restore.sh`: Detects file changes, verifies integrity, and restores unauthorized changes.
  - `detect_kill.sh`: Identifies the process responsible for a change and terminates unauthorized writers.

## 1. Change Detection

- Accepts a file or directory as a command-line argument.
- If a file is provided, only that file is monitored.
- If a directory is provided, the entire directory and its nested contents are monitored.
- Creates an initial baseline containing:
  - SHA-256 file hashes.
  - File and directory permissions.
  - Ownership (UID/GID).
  - Modification timestamps.
  - File types and symbolic link targets.
- Uses **inotifywait** to detect filesystem events such as modification, creation, deletion, and renaming.
- Periodically performs a full integrity check to catch missed events.
- Compares the current manifest with the stored baseline to identify changes.

## 2. Process Identification

- Uses **Linux Audit (`auditd`)** to track filesystem write operations.
- Audit rules are installed for the monitored file or directory.
- Each audit event contains information such as:
  - PID and PPID.
  - Executable path.
  - Modified file path.
  - User ID and login user ID (`auid`).
- `detect_kill.sh` searches audit logs using the monitor's unique audit key.
- Correlates audit events with the modified file to identify the responsible process.
- Uses PID and process start-time checks to avoid accidentally targeting a different process after PID reuse.

## 3. User Authorization

- Maintains an authorization list at `/etc/fim-monitor/authorized_users`.
- Supports usernames and numeric UIDs.
- Uses `auid` to identify the original logged-in user, even when commands are executed using `sudo` or `su`.
- **Authorized users:**
  - Their changes are accepted.
  - The current contents are adopted as the new baseline.
- **Unauthorized users:**
  - Their changes are rejected.
  - Their responsible processes are targeted for termination.

## 4. Process Termination

- `detect_restore.sh` automatically invokes `detect_kill.sh` when an integrity mismatch is detected.
- The termination script validates the identified PID and executable before sending signals.
- Uses `SIGTERM` first, followed by `SIGKILL` if necessary.
- Interactive shells are protected by default to avoid unexpectedly closing user sessions.
- If the writer cannot be safely identified or terminated, the system falls back to restoring the baseline.

## 5. File Restoration

- Unauthorized changes trigger restoration from the stored baseline.
- For individual files, the original file is copied back.
- For directories, `rsync` restores the original contents recursively.
- Newly added unauthorized files are removed.
- Deleted or modified files are recovered.
- A new integrity manifest is generated to verify restoration.
- Logs whether restoration succeeded or failed.

## 6. Logging

- Incident logs are stored at `/var/log/fim-monitor/incidents.log`.
- Logs include:
  - Monitor startup and shutdown.
  - Detected changes.
  - Authorized and unauthorized writers.
  - PID identification and termination results.
  - Restoration and verification results.
- Persistent baseline and monitoring state are stored under `/var/lib/fim-monitor/`.

## 7. Execution

**Start monitoring:**

    sudo ./detect_restore.sh /path/to/file-or-directory

**Check integrity:**

    sudo ./detect_restore.sh --status /path/to/file-or-directory

**Restore baseline manually:**

    sudo ./detect_restore.sh --restore /path/to/file-or-directory

**Create a new baseline:**

    sudo ./detect_restore.sh --rebaseline /path/to/file-or-directory

**View incident logs:**

    sudo tail -f /var/log/fim-monitor/incidents.log

## Overall Workflow

`Monitor → Detect Change → Compare Baseline → Identify Writer → Check Authorization → Terminate Unauthorized Process → Restore Original Content → Verify Integrity`

- Authorized changes are retained and become the new baseline.
- Unauthorized changes are reverted, and the responsible process is terminated when it can be safely identified.
//! Remote-side logic: worker and attach modes.
//!
//! These run on the remote host, started via SSH exec by the local rexec.
//! Communication with the local side uses the binary frame protocol over
//! stdin/stdout (which are connected to the SSH channel).

use std::io::{IsTerminal, SeekFrom};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::protocol::{Frame, FrameReader, FrameType};

/// Write a frame to both the log file and stdout (SSH channel).
///
/// Log file is written first (source of truth), then stdout.
/// If stdout write fails (SSH disconnected), the flag is cleared
/// and subsequent writes skip stdout — the log file still has all data.
///
/// Returns Ok(true) on success, Ok(false) if the log file write failed
/// (non-fatal — child process should still be waited on).
async fn write_frame(
    frame: &Frame,
    log: &mut tokio::fs::File,
    stdout: &mut tokio::io::Stdout,
    stdout_ok: &mut bool,
) -> Result<bool> {
    let encoded = frame.encode();
    // Log file first — source of truth
    if log.write_all(&encoded).await.is_err() || log.flush().await.is_err() {
        // Log file write failed (disk full, etc.) — non-fatal
        // Continue streaming to stdout if possible, just can't reconnect later
        return Ok(false);
    }
    // Then try stdout (SSH channel)
    if *stdout_ok && stdout.write_all(&encoded).await.is_err() {
        *stdout_ok = false;
    }
    Ok(true)
}

/// Parse an env block received over stdin: `KEY=VALUE\0KEY2=VALUE2\0...`.
/// Entries without `=` or with an empty key are skipped.
fn parse_env_block(buf: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in buf.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(entry);
        if let Some((k, v)) = s.split_once('=')
            && !k.is_empty()
        {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

/// Extract the command and remaining env vars from a stdin env block.
/// The block is `__REXEC_CMD__=<command>\0` followed by `KEY=VALUE\0` entries.
/// The command never appears in the worker's argv (sent over stdin instead),
/// so `pkill -f`/`pgrep -f` cannot match the worker by command content.
fn extract_command_and_env(buf: &[u8]) -> Result<(String, Vec<(String, String)>)> {
    let mut entries = parse_env_block(buf);
    let cmd_idx = entries.iter().position(|(k, _)| k == "__REXEC_CMD__");
    let command = match cmd_idx {
        Some(i) => entries.remove(i).1,
        None => {
            return Err(anyhow!(
                "worker received no __REXEC_CMD__ over stdin (run via `rexec <host> run`)"
            ));
        }
    };
    Ok((command, entries))
}

/// Worker mode: spawn a child process, stream its output via the frame protocol.
///
/// Runs on the remote host. stdin/stdout are connected to the SSH channel.
/// Output is written to both the log file (always) and stdout (when connected).
/// SIGHUP is ignored so the worker survives SSH disconnection.
///
/// The child process is always waited on, even if the worker encounters errors.
/// The log file is cleaned up on successful exit (exit code 0).
pub async fn worker() -> Result<()> {
    // Ignore SIGHUP — survive SSH disconnect
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let pid = std::process::id();

    // Create log directory and file
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let log_dir = home.join(".rexec").join("logs");
    std::fs::create_dir_all(&log_dir).with_context(|| format!("creating {}", log_dir.display()))?;
    let log_path = log_dir.join(format!("{}.log", pid));
    let mut log_file = tokio::fs::File::create(&log_path)
        .await
        .with_context(|| format!("creating {}", log_path.display()))?;

    let mut stdout = tokio::io::stdout();
    let mut stdout_ok = true;

    // Read command + environment sent over stdin by the local rexec.
    // The local side writes `__REXEC_CMD__=<command>\0` first (the command to
    // run), then `KEY=VALUE\0`... (env vars), then EOFs stdin. This keeps the
    // command and secrets out of the worker's argv, so `pkill -f`/`pgrep -f`
    // cannot match the worker by command content. When invoked directly on a
    // tty (manual debugging) there is nothing to read — error out.
    let (command, child_env): (String, Vec<(String, String)>) = if !std::io::stdin().is_terminal() {
        let mut stdin = tokio::io::stdin();
        let mut buf = Vec::new();
        let _ = stdin.read_to_end(&mut buf).await;
        extract_command_and_env(&buf)?
    } else {
        return Err(anyhow!(
            "worker requires a command over stdin (run via `rexec <host> run`)"
        ));
    };

    // Run the command from a private script file (`sh <script>`) instead of
    // `sh -c <command>`. With `sh -c`, the full command text is exposed in the
    // child's cmdline, so a command containing `pkill -f <pattern>` matches
    // (and kills) the very shell that carries it — the classic
    // `sh -c "pkill -f foo"` self-kill. A script path in argv keeps the
    // cmdline clean; the command's own target processes still match pkill
    // normally because their cmdlines are their own.
    let run_dir = home.join(".rexec").join("run");
    create_private_dir(&run_dir)?;
    cleanup_stale_scripts(&run_dir);
    let script_path = write_command_script(&run_dir, pid, &command)?;
    // Delete the script on every exit path — early `?` returns, panics, and
    // normal completion (Drop). It holds the user's command verbatim.
    let _script_guard = ScriptGuard(script_path.clone());

    // Spawn child process with the env vars applied.
    let mut child_cmd = tokio::process::Command::new("sh");
    child_cmd.arg(&script_path);
    for (k, v) in &child_env {
        child_cmd.env(k, v);
    }
    let mut child = child_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn child process")?;

    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Send Started frame (non-fatal if log write fails)
    write_frame(
        &Frame::started(pid),
        &mut log_file,
        &mut stdout,
        &mut stdout_ok,
    )
    .await?;

    // Channel for collecting output frames from stdout/stderr readers
    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(256);

    // stdout reader task
    let tx_out = frame_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_out.send(Frame::stdout(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // stderr reader task
    let tx_err = frame_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match child_stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_err.send(Frame::stderr(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Drop last sender so frame_rx closes when both readers finish
    drop(frame_tx);

    // Main writer loop: write frames to log + stdout
    // Errors are non-fatal — we still need to wait for the child process
    while let Some(frame) = frame_rx.recv().await {
        let _ = write_frame(&frame, &mut log_file, &mut stdout, &mut stdout_ok).await;
    }

    // Always wait for child to exit, regardless of write errors.
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(-1);

    // Send Exited frame
    let _ = write_frame(
        &Frame::exited(exit_code),
        &mut log_file,
        &mut stdout,
        &mut stdout_ok,
    )
    .await;

    // Final flush
    let _ = log_file.flush().await;
    let _ = stdout.flush().await;

    // Clean up log file on successful exit (exit code 0)
    if exit_code == 0 {
        let _ = tokio::fs::remove_file(&log_path).await;
    }

    // The command script is removed by `_script_guard`'s Drop on return.
    // Unlike the log (kept on non-zero exit for post-mortem), the script may
    // contain secrets. Stale files from killed workers are swept on the next
    // worker startup.
    Ok(())
}

/// Deletes the command script when dropped — covers every worker exit path
/// (early `?` returns, panics, normal completion).
struct ScriptGuard(std::path::PathBuf);

impl Drop for ScriptGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create `dir` (and parents); ensure the leaf dir is owner-only. The run dir
/// holds command scripts that may contain secrets — other local users must
/// not be able to enumerate them.
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // DirBuilder::create_dir_all is unstable; fs::create_dir_all has no mode
    // parameter. Parents (~/.rexec) may be created with the default umask —
    // they hold no secrets; the leaf is tightened before any script lands.
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 700 {}", dir.display()))?;
    Ok(())
}

/// Write `command` to `<run_dir>/<pid>.sh` with owner-only permissions.
///
/// The file is created exclusively with mode 0600 (no 0644 window; O_EXCL
/// never follows a symlink into a victim file) because the command may
/// contain secrets. A trailing newline is appended so the last line is
/// well-formed for `sh`. On write failure the partial file is removed.
fn write_command_script(
    run_dir: &std::path::Path,
    pid: u32,
    command: &str,
) -> Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = run_dir.join(format!("{}.sh", pid));
    // A pre-existing file with this name can only be stale (the PID is this
    // worker's own) or an attack (symlink) — remove it and create exclusively.
    let open_new = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
    };
    let mut f = match open_new() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&path);
            open_new().with_context(|| format!("creating {}", path.display()))?
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("creating {}", path.display())));
        }
    };
    if let Err(e) = f
        .write_all(command.as_bytes())
        .and_then(|_| f.write_all(b"\n"))
    {
        let _ = std::fs::remove_file(&path);
        return Err(anyhow::Error::new(e).context(format!("writing {}", path.display())));
    }
    Ok(path)
}

/// Remove script files left behind by workers that died without cleanup.
///
/// A file `<pid>.sh` is stale when no process with that PID exists, or when
/// it is older than `MAX_AGE_SECS` (covers PID reuse by an unrelated process).
/// Files owned by live PIDs are never touched.
fn cleanup_stale_scripts(run_dir: &std::path::Path) {
    const MAX_AGE_SECS: u64 = 7 * 24 * 3600;
    let entries = match std::fs::read_dir(run_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Some(stem) = name_str.strip_suffix(".sh") else {
            continue; // not a worker script
        };
        // Positive PIDs only: u32 rejects "-1", the filter rejects "0"
        // (kill(-1,0)/kill(0,0) would falsely report "alive").
        let Some(owner_pid) = stem.parse::<u32>().ok().filter(|p| *p > 0) else {
            continue; // not a worker script
        };
        // kill(pid, 0) == 0 → alive (ours or reused by anyone: keep).
        let alive = unsafe { libc::kill(owner_pid as i32, 0) == 0 };
        let too_old = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() > MAX_AGE_SECS);
        if !alive || too_old {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Attach mode: replay log from offset, then tail live.
///
/// Runs on the remote host. Reads the log file written by a worker process
/// and streams it to stdout (SSH channel). Used for reconnection after
/// SSH disconnect.
///
/// Uses a single file handle for the duration of the session.
/// Uses `read()` (not `read_exact()`) to handle partial writes gracefully.
pub async fn attach(pid: u32, offset: u64) -> Result<()> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let log_path = home
        .join(".rexec")
        .join("logs")
        .join(format!("{}.log", pid));

    if !log_path.exists() {
        // Log file may have been deleted by the worker after successful exit.
        // Check if the process is still alive — if dead, assume success.
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive {
            // Worker exited and cleaned up — synthesize success exit
            let mut stdout = tokio::io::stdout();
            let frame = Frame::exited(0);
            stdout.write_all(&frame.encode()).await?;
            stdout.flush().await?;
            return Ok(());
        }
        return Err(anyhow!(
            "log file not found for PID {} and process is alive",
            pid
        ));
    }

    let mut stdout = tokio::io::stdout();
    let mut offset = offset;
    let mut reader = FrameReader::new();

    // Open file once and reuse
    let mut file = tokio::fs::File::open(&log_path).await?;
    file.seek(SeekFrom::Start(offset)).await?;

    loop {
        // Check current file size
        let file_size = match file.metadata().await {
            Ok(m) => m.len(),
            Err(_) => {
                // Can't stat — synthesize exit
                let frame = Frame::exited(-1);
                stdout.write_all(&frame.encode()).await?;
                stdout.flush().await?;
                return Ok(());
            }
        };

        if file_size > offset {
            // Seek to the new data position and read what's available
            file.seek(SeekFrom::Start(offset)).await?;

            let to_read = (file_size - offset) as usize;
            // Cap read size to avoid huge allocations
            let read_size = to_read.min(65536);
            let mut buf = vec![0u8; read_size];

            // Use read() not read_exact() — may return fewer bytes
            let n = match file.read(&mut buf).await {
                Ok(0) => 0,
                Ok(n) => n,
                Err(_) => 0, // Read error — try again next iteration
            };

            if n > 0 {
                offset += n as u64;

                // Write raw bytes to stdout (frames are already encoded in the log)
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;

                // Parse to check for EXITED frame
                reader.push(&buf[..n]);
                while let Some(frame) = reader.next_frame() {
                    if frame.frame_type == FrameType::Exited {
                        return Ok(()); // Process exited — done
                    }
                }
            }
        }

        // Check if worker process is still alive
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive && file_size <= offset {
            // Worker is dead and no more data to read.
            // Give one more chance for the filesystem to sync.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let new_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
            if new_size <= offset {
                // Still no new data — synthesize exit
                let frame = Frame::exited(-1);
                stdout.write_all(&frame.encode()).await?;
                stdout.flush().await?;
                return Ok(());
            }
            // New data appeared — loop will read it
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_command_and_env() {
        let buf = b"__REXEC_CMD__=echo hello\0KEY=val\0";
        let (cmd, env) = extract_command_and_env(buf).unwrap();
        assert_eq!(cmd, "echo hello");
        assert_eq!(env, vec![("KEY".to_string(), "val".to_string())]);
    }

    #[test]
    fn test_extract_command_with_equals_in_value() {
        // command containing '=' must not be split
        let buf = b"__REXEC_CMD__=python -c 'print(1+1)'\0A=b\0";
        let (cmd, env) = extract_command_and_env(buf).unwrap();
        assert_eq!(cmd, "python -c 'print(1+1)'");
        assert_eq!(env, vec![("A".to_string(), "b".to_string())]);
    }

    #[test]
    fn test_extract_command_only_no_env() {
        let buf = b"__REXEC_CMD__=ls\0";
        let (cmd, env) = extract_command_and_env(buf).unwrap();
        assert_eq!(cmd, "ls");
        assert!(env.is_empty());
    }

    #[test]
    fn test_extract_command_missing_is_error() {
        let buf = b"KEY=val\0";
        assert!(extract_command_and_env(buf).is_err());
    }

    #[test]
    fn test_write_command_script_content_and_mode() {
        let dir = std::env::temp_dir().join(format!("rexec-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_command_script(&dir, 4242, "echo hi").unwrap();
        assert_eq!(path, dir.join("4242.sh"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "echo hi\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_write_command_script_rejects_symlink_and_stale() {
        let dir = std::env::temp_dir().join(format!("rexec-test-cnex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // A stale leftover at the target name must not survive as our inode:
        // pre-existing world-readable mode is not inherited.
        let path = dir.join("4242.sh");
        std::fs::write(&path, "stale\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let returned = write_command_script(&dir, 4242, "echo fresh").unwrap();
        assert_eq!(returned, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "echo fresh\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "pre-existing loose mode must not be inherited");
        }

        // A symlink at the target name must never be written through.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let victim = dir.join("victim.txt");
            std::fs::write(&victim, "do not touch\n").unwrap();
            let _ = std::fs::remove_file(&path);
            symlink(&victim, &path).unwrap();
            write_command_script(&dir, 4242, "echo hijack").unwrap();
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "do not touch\n",
                "symlink must be replaced, not followed"
            );
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_file(),
                "target must be a regular file after rewrite"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_script_guard_removes_file_on_drop() {
        let dir = std::env::temp_dir().join(format!("rexec-test-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_command_script(&dir, 7777, "secret").unwrap();
        assert!(path.exists());
        {
            let _guard = ScriptGuard(path.clone());
        } // dropped here — even a panic path would run Drop
        assert!(!path.exists(), "guard must delete the script on drop");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleanup_stale_scripts() {
        let dir = std::env::temp_dir().join(format!("rexec-test-cleanup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Live PID (this test process): script must be kept.
        let live = dir.join(format!("{}.sh", std::process::id()));
        std::fs::write(&live, "keep\n").unwrap();

        // Dead PID: spawn a process, wait for it to exit, use its PID.
        // (Theoretical flake: the OS could reuse the PID before the sweep —
        // acceptably improbable on a test host.)
        let mut child = std::process::Command::new("sleep")
            .arg("0.01")
            .spawn()
            .unwrap();
        let dead_pid = child.id();
        let _ = child.wait().unwrap();
        let stale = dir.join(format!("{}.sh", dead_pid));
        std::fs::write(&stale, "remove\n").unwrap();

        // Non-PID names: untouched by the sweep.
        let other = dir.join("notes.txt");
        std::fs::write(&other, "keep\n").unwrap();

        cleanup_stale_scripts(&dir);

        assert!(live.exists(), "script of a live PID must survive");
        assert!(!stale.exists(), "script of a dead PID must be removed");
        assert!(other.exists(), "non-script files must be untouched");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleanup_removes_ancient_script_even_for_live_pid() {
        let dir = std::env::temp_dir().join(format!("rexec-test-ancient-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Own PID, but mtime set to the epoch: older than MAX_AGE.
        let path = dir.join(format!("{}.sh", std::process::id()));
        std::fs::write(&path, "ancient\n").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::UNIX_EPOCH)
                .set_accessed(std::time::SystemTime::UNIX_EPOCH),
        )
        .unwrap();
        drop(f);

        cleanup_stale_scripts(&dir);
        assert!(
            !path.exists(),
            "ancient script must be removed despite live PID"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

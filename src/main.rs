use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use russh::ChannelMsg;
use ssh2_config::{ParseRule, SshConfig};

mod protocol;
mod remote;
mod ssh;

use protocol::{FrameReader, FrameType};

/// Global quiet flag. When set, all progress/status output (Remote PID,
/// exit, sync, reconnect, host-key prompts) is suppressed so stdout/stderr
/// carry only the remote command's own output.
pub(crate) static QUIET: AtomicBool = AtomicBool::new(false);

/// Print a progress/status line to stderr unless --quiet is set.
#[macro_export]
macro_rules! status {
    ($($t:tt)*) => {{
        if !crate::QUIET.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($t)*);
        }
    }};
}

#[derive(Parser)]
#[command(
    name = "rexec",
    version,
    about = "Remote code execution + folder sync over SSH"
)]
struct Cli {
    /// SSH host alias (resolved via ~/.ssh/config) or user@host:port
    host: Option<String>,

    /// SSH port (overrides host:port and ssh-config Port)
    #[arg(short = 'p', long = "port", value_name = "PORT", global = true)]
    port: Option<u16>,

    /// Suppress progress/status output (Remote PID, exit, sync, reconnect)
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check remote dependencies (rsync, sh) and install if missing
    Init,

    /// Execute a command on the remote host
    Run {
        /// Set an environment variable on the remote command (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a local file (KEY=VALUE per line). Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Sync a local file or folder to the remote host before executing (LOCAL:REMOTE)
        #[arg(long, value_name = "LOCAL:REMOTE")]
        sync: Option<String>,

        /// Command to execute on the remote host
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Sync a local script to the remote and run it (interpreter auto-detected)
    Script {
        /// Set an environment variable on the remote command (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a local file (KEY=VALUE per line). Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Remote directory to sync the script into (default ~/.rexec/scripts)
        #[arg(long = "sync-to", value_name = "REMOTE_DIR")]
        sync_to: Option<String>,

        /// Interpreter to run the script with (default: shebang or extension)
        #[arg(long = "interpreter", value_name = "CMD")]
        interpreter: Option<String>,

        /// Local script file to sync and run
        script: PathBuf,

        /// Arguments passed to the script (use -- to separate options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List SSH hosts configured in ~/.ssh/config
    List {
        /// Optional: show resolved details for a single alias
        alias: Option<String>,
    },

    /// [internal] Run as worker on the remote host (reads command from stdin)
    Worker,

    /// [internal] Attach to a running worker's log
    Attach {
        #[arg(long)]
        pid: u32,

        #[arg(long)]
        offset: u64,
    },
}

#[derive(Clone)]
pub struct RemoteHost {
    pub hostname: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
}

fn parse_sync_arg(arg: &str) -> Result<(PathBuf, String)> {
    let (local, remote) = arg
        .split_once(':')
        .ok_or_else(|| anyhow!("--sync must be LOCAL:REMOTE, got '{}'", arg))?;
    if local.is_empty() || remote.is_empty() {
        return Err(anyhow!("--sync LOCAL and REMOTE must both be non-empty"));
    }
    Ok((PathBuf::from(local), remote.to_string()))
}

/// Parse a local env file into (KEY, VALUE) pairs.
///
/// One `KEY=VALUE` per line. Blank lines and `#` comments are skipped, a
/// leading `export ` is stripped, and one layer of surrounding quotes on the
/// value is removed. Lines without `=` are skipped with a warning.
fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, mut v)) = line.split_once('=') else {
            eprintln!("⚠ env file: skipping malformed line (no '='): {:?}", line);
            continue;
        };
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        v = v.trim();
        // Strip one layer of matching surrounding quotes.
        if v.len() >= 2 {
            let (first, last) = (v.as_bytes()[0] as char, v.as_bytes()[v.len() - 1] as char);
            if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
                v = &v[1..v.len() - 1];
            }
        }
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

fn resolve_host(host: &str, port_override: Option<u16>) -> Result<RemoteHost> {
    let mut remote = if host.contains('@')
        || (host.contains(':') && !host.chars().next().unwrap().is_alphabetic())
    {
        parse_user_host_port(host)?
    } else {
        let ssh_config_path = dirs::home_dir()
            .context("cannot determine home directory")?
            .join(".ssh/config");

        if !ssh_config_path.exists() {
            RemoteHost {
                hostname: host.to_string(),
                port: None,
                user: None,
                identity_file: None,
            }
        } else {
            let config_str = std::fs::read_to_string(&ssh_config_path)
                .with_context(|| format!("reading {}", ssh_config_path.display()))?;
            let mut reader = BufReader::new(config_str.as_bytes());
            let config =
                SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;
            let host_config = config.query(host);
            RemoteHost {
                hostname: host_config
                    .host_name
                    .clone()
                    .unwrap_or_else(|| host.to_string()),
                port: host_config.port,
                user: host_config.user.clone(),
                identity_file: host_config
                    .identity_file
                    .as_ref()
                    .and_then(|v| v.first().cloned()),
            }
        }
    };

    // --port overrides host:port and ssh-config Port.
    if let Some(p) = port_override {
        remote.port = Some(p);
    }
    Ok(remote)
}

fn parse_user_host_port(s: &str) -> Result<RemoteHost> {
    let (user, rest) = if let Some((u, r)) = s.split_once('@') {
        (Some(u.to_string()), r)
    } else {
        (None, s)
    };

    let (hostname, port) = if let Some((h, p)) = rest.rsplit_once(':') {
        (h.to_string(), Some(p.parse::<u16>()?))
    } else {
        (rest.to_string(), None)
    };

    Ok(RemoteHost {
        hostname,
        port,
        user,
        identity_file: None,
    })
}

async fn do_sync(local: &Path, remote_path: &str, remote: &RemoteHost) -> Result<()> {
    let ssh_opts = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=3";
    let ssh_e = match remote.port {
        Some(p) => format!("ssh -p {} {}", p, ssh_opts),
        None => format!("ssh {}", ssh_opts),
    };
    // rsync target host must NOT contain ":port" (rsync would treat it as a
    // path); use user@hostname and pass the port via `ssh -p`.
    let rsync_host = match &remote.user {
        Some(u) => format!("{}@{}", u, remote.hostname),
        None => remote.hostname.clone(),
    };

    // Single file: rsync the file directly (no --delete, no trailing-slash
    // rewriting). If `remote` ends with '/', rsync drops the file into that
    // remote directory; otherwise it writes to the given file path.
    if local.is_file() {
        let remote_target = format!("{}:{}", rsync_host, remote_path);
        let mut child = tokio::process::Command::new("rsync")
            .args([
                "-az",
                "-e",
                ssh_e.as_str(),
                &local.to_string_lossy(),
                &remote_target,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .context("failed to spawn rsync")?;
        return wait_rsync(&mut child, local, &rsync_host, remote, remote_path).await;
    }

    if !local.is_dir() {
        return Err(anyhow!(
            "local sync path '{}' does not exist (expected a file or directory)",
            local.display()
        ));
    }

    // Directory: sync contents (trailing slash on both sides) with --delete.
    let local_str = local.to_string_lossy();
    let local_arg = if local_str.ends_with('/') {
        local_str.into_owned()
    } else {
        format!("{}/", local_str)
    };
    let remote_arg = if remote_path.ends_with('/') {
        remote_path.to_string()
    } else {
        format!("{}/", remote_path)
    };

    let mut child = tokio::process::Command::new("rsync")
        .args([
            "-az",
            "--delete",
            "-e",
            ssh_e.as_str(),
            &local_arg,
            &format!("{}:{}", rsync_host, remote_arg),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("failed to spawn rsync")?;

    wait_rsync(&mut child, local, &rsync_host, remote, &remote_arg).await
}

/// Wait for an rsync child process with a timeout, surfacing a manual-recovery
/// hint on timeout. `remote_path` is the remote-side path (no host prefix).
async fn wait_rsync(
    child: &mut tokio::process::Child,
    local: &Path,
    rsync_host: &str,
    remote: &RemoteHost,
    remote_path: &str,
) -> Result<()> {
    let timeout = Duration::from_secs(300);
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            if !status.success() {
                return Err(anyhow!("rsync failed with status {}", status));
            }
        }
        Ok(Err(e)) => {
            return Err(anyhow!("failed to wait for rsync: {}", e));
        }
        Err(_) => {
            let _ = child.kill().await;
            let port_hint = remote
                .port
                .map(|p| format!(" -p {}", p))
                .unwrap_or_default();
            return Err(anyhow!(
                "rsync timed out after {} seconds. \
                 Use `rsync -az -e 'ssh{}' {}:{}` manually to diagnose.",
                timeout.as_secs(),
                port_hint,
                rsync_host,
                remote_path
            ));
        }
    }
    status!(
        "✓ Synced {} -> {}:{}",
        local.display(),
        rsync_host,
        remote_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `sh -c shell_quote(input)` reproduces the original input.
    /// This tests the full quoting round-trip through a real shell.
    fn assert_shell_roundtrip(input: &str) {
        let quoted = shell_quote(input).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", quoted))
            .output()
            .expect("failed to run sh");
        let result = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            result, input,
            "shell_quote roundtrip failed for {:?}",
            input
        );
    }

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell_quote("hello").unwrap(), "'hello'");
    }

    #[test]
    fn test_shell_quote_empty() {
        assert_eq!(shell_quote("").unwrap(), "''");
    }

    #[test]
    fn test_shell_quote_with_double_quotes() {
        // Double quotes inside single quotes are literal
        let quoted = shell_quote(r#"echo "hello world""#).unwrap();
        assert_eq!(quoted, r#"'echo "hello world"'"#);
        assert_shell_roundtrip(r#"echo "hello world""#);
    }

    #[test]
    fn test_shell_quote_with_single_quotes() {
        // Single quotes must be escaped with the '"'"' trick
        let quoted = shell_quote("echo 'hello'").unwrap();
        assert_eq!(quoted, "'echo '\"'\"'hello'\"'\"''");
        assert_shell_roundtrip("echo 'hello'");
    }

    #[test]
    fn test_shell_quote_with_special_chars() {
        // $, backticks, \, !, etc. should all be literal inside single quotes
        assert_shell_roundtrip("echo $HOME");
        assert_shell_roundtrip("echo `whoami`");
        assert_shell_roundtrip("echo $((1+2))");
        assert_shell_roundtrip("echo a; echo b");
        assert_shell_roundtrip("echo a | grep b");
        assert_shell_roundtrip("echo a && echo b");
        assert_shell_roundtrip("echo a > /tmp/test");
    }

    #[test]
    fn test_shell_quote_mixed_quotes() {
        assert_shell_roundtrip(r#"echo "it's $HOME""#);
        assert_shell_roundtrip("echo 'single' && echo \"double\"");
    }

    #[test]
    fn test_shell_quote_newline() {
        assert_shell_roundtrip("echo hello\necho world");
    }

    #[test]
    fn test_shell_quote_rejects_null_byte() {
        let result = shell_quote("echo hello\0; rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn test_run_env_and_command_parsing() {
        // -e/--env flags parse before the trailing command; --env-file accepts a path.
        let cli = Cli::parse_from([
            "rexec", "h", "run", "-e", "A=b", "--env", "C=d", "--", "echo", "hi",
        ]);
        match cli.action {
            Action::Run {
                env,
                env_file,
                command,
                ..
            } => {
                assert_eq!(
                    env,
                    vec!["A=b".to_string(), "C=d".to_string()],
                    "env: {:?}",
                    env
                );
                assert!(env_file.is_empty());
                assert_eq!(
                    command,
                    vec!["echo".to_string(), "hi".to_string()],
                    "cmd: {:?}",
                    command
                );
            }
            _ => panic!("not Run"),
        }
    }

    /// Test the full quoting chain: command → shell_quote → sh -c → result.
    /// This simulates what happens when rexec passes a command to the remote worker.
    #[test]
    fn test_full_quoting_chain() {
        // The command the user types (after local shell processing)
        let commands = vec![
            "echo hello",
            "echo 'hello world'",
            r#"echo "hello world""#,
            "echo $HOME",
            "python -c 'print(42)'",
            "cd /tmp && ls -la",
            "echo 'it'\''s a test'",
        ];

        for cmd in commands {
            // Step 1: shell_quote the command (as done in run_command)
            let quoted = shell_quote(cmd).unwrap();

            // Step 2: simulate the remote `sh` parsing a quoted fragment.
            // Today the command travels over stdin (__REXEC_CMD__), but
            // script paths and args are still embedded quoted (run_script),
            // so the quote → remote-sh round-trip must be lossless.
            let worker_output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {}", quoted))
                .output()
                .expect("failed to run sh");
            let received = String::from_utf8(worker_output.stdout).unwrap();

            // Step 3: the remote shell must see the exact original fragment
            assert_eq!(
                received, cmd,
                "command corrupted through quoting chain: {:?} → {:?} → {:?}",
                cmd, quoted, received
            );
        }
    }

    #[test]
    fn test_detect_runner_shebang() {
        let dir = std::env::temp_dir();
        let p = dir.join("rexec_test_shebang.sh");
        std::fs::write(&p, "#!/bin/bash\necho hi\n").unwrap();
        assert_eq!(detect_runner(&p).unwrap(), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_detect_runner_by_extension() {
        let dir = std::env::temp_dir();
        let py = dir.join("rexec_test_detect.py");
        std::fs::write(&py, "print(1)\n").unwrap();
        assert_eq!(detect_runner(&py).unwrap(), Some("python3".to_string()));
        let sh = dir.join("rexec_test_detect.sh");
        std::fs::write(&sh, "echo hi\n").unwrap();
        assert_eq!(detect_runner(&sh).unwrap(), Some("sh".to_string()));
        let _ = std::fs::remove_file(&py);
        let _ = std::fs::remove_file(&sh);
    }

    #[test]
    fn test_collect_env_flags() {
        let env = vec!["A=b".to_string(), "C=d".to_string()];
        assert_eq!(
            collect_env(&env, &[]).unwrap(),
            vec![
                ("A".to_string(), "b".to_string()),
                ("C".to_string(), "d".to_string())
            ]
        );
        // missing '='
        assert!(collect_env(&["noequal".to_string()], &[]).is_err());
        // empty key
        assert!(collect_env(&["=nokey".to_string()], &[]).is_err());
    }
}

/// Simple shell quoting for a single argument.
/// Rejects null bytes to prevent command injection via C-string truncation.
fn shell_quote(s: &str) -> Result<String> {
    if s.contains('\0') {
        return Err(anyhow!("command contains null byte — rejected for safety"));
    }
    Ok(format!("'{}'", s.replace('\'', "'\"'\"'")))
}

/// Core run logic: deploy worker, stream output, reconnect on disconnect.
///
/// `unused_assignments`: `session = new_session` on reconnect keeps the SSH
/// handle alive (channel holds an implicit ref), but the compiler can't see it.
#[allow(unused_assignments)]
async fn run_command(
    remote: &RemoteHost,
    host: &str,
    command: &str,
    env: &[(String, String)],
) -> Result<()> {
    let mut session = ssh::connect(remote).await?;
    ssh::ensure_remote_binary(&mut session, host).await?;

    // Start worker on remote. The command itself is NOT passed on argv (so
    // `pkill -f`/`pgrep -f` cannot match the worker by command content); it is
    // sent over stdin as a special env entry, alongside any -e/--env vars.
    let worker_cmd = "~/.rexec/rexec worker";
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, worker_cmd).await?;

    // Send the command + environment to the worker over the channel's stdin.
    // The worker reads these before spawning the child, so neither the command
    // nor secrets appear in the remote process's argv (ps).
    // Format: `__REXEC_CMD__=<command>\0` first, then `KEY=VALUE\0`..., EOF.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"__REXEC_CMD__=");
    payload.extend_from_slice(command.as_bytes());
    payload.push(0);
    for (k, v) in env {
        payload.extend_from_slice(k.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(v.as_bytes());
        payload.push(0);
    }
    channel.data(payload.as_slice()).await?;
    // Signal stdin EOF so the worker's read completes.
    channel.eof().await?;

    let mut frame_reader = FrameReader::new();
    let mut offset: u64 = 0;
    // base_offset preserves the total log-file offset across FrameReader resets.
    // After reconnection, frame_reader is reset to 0, so:
    //   offset = base_offset + frame_reader.consumed_bytes()
    let mut base_offset: u64 = 0;
    let mut pid: Option<u32> = None;
    // Track whether signal handler is available — if it fails to init,
    // stop polling sig_rx to avoid busy-loop on None.
    let mut signal_available = true;

    // Signal handler: print remote info and exit on Ctrl+C / SIGTERM
    let (sig_tx, mut sig_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
        let _ = sig_tx.send(()).await;
    });

    loop {
        tokio::select! {
            // Signal received — print remote info and exit
            sig = async {
                if signal_available { sig_rx.recv().await }
                else { std::future::pending::<Option<()>>().await }
            } => {
                if sig.is_none() {
                    // Signal handler task failed to init — disable polling to avoid busy-loop
                    signal_available = false;
                    status!("⚠ Signal handler unavailable; Ctrl+C will not work");
                    continue;
                }
                if let Some(p) = pid {
                    status!(
                        "\n⚠ Interrupted by signal. Remote process still running.\n  PID: {}",
                        p
                    );
                }
                return Ok(());
            }
            // Normal channel reading
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { ref data }) => {
                        frame_reader.push(data);
                        while let Some(frame) = frame_reader.next_frame() {
                            // Track offset at frame boundaries, not raw SSH bytes
                            offset = base_offset + frame_reader.consumed_bytes();
                            match frame.frame_type {
                                FrameType::Stdout => {
                                    use std::io::Write;
                                    let stdout = std::io::stdout();
                                    let mut lock = stdout.lock();
                                    lock.write_all(&frame.data)?;
                                    lock.flush()?;
                                }
                                FrameType::Stderr => {
                                    use std::io::Write;
                                    let stderr = std::io::stderr();
                                    let mut lock = stderr.lock();
                                    lock.write_all(&frame.data)?;
                                    lock.flush()?;
                                }
                                FrameType::Started => {
                                    pid = frame.as_pid();
                                    if let Some(p) = pid {
                                        status!("Remote PID: {}", p);
                                    }
                                }
                                FrameType::Exited => {
                                    use std::io::Write;
                                    std::io::stdout().flush()?;
                                    let code = frame.as_exit_code().unwrap_or(-1);
                                    if code == 0 {
                                        status!("\n✓ Remote process exited");
                                    } else {
                                        status!("\n✗ Remote process exited with code {}", code);
                                    }
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(ChannelMsg::ExitStatus { .. }) => {}
                    Some(ChannelMsg::Eof) | None => {
                        // Channel closed — try to reconnect
                        let pid_val = match pid {
                            Some(p) => p,
                            None => {
                                return Err(anyhow!(
                                    "connection lost before worker started"
                                ));
                            }
                        };

                        status!(
                            "\n⚠ Connection lost. Remote process still running.\n  PID: {}",
                            pid_val
                        );

                        // Reconnect with exponential backoff
                        let mut backoff = Duration::from_secs(1);
                        let max_backoff = Duration::from_secs(30);
                        let max_retries = 10;
                        let mut reconnected = false;

                        for retry in 1..=max_retries {
                            status!(
                                "  Retry {}/{} in {:?}...",
                                retry, max_retries, backoff
                            );
                            // Allow Ctrl+C during backoff
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                sig = async {
                                    if signal_available { sig_rx.recv().await }
                                    else { std::future::pending::<Option<()>>().await }
                                } => {
                                    if sig.is_none() {
                                        signal_available = false;
                                        status!("⚠ Signal handler unavailable");
                                        continue;
                                    }
                                    if let Some(p) = pid {
                                        status!(
                                            "\n⚠ Interrupted by signal. Remote process still running.\n  PID: {}",
                                            p
                                        );
                                    }
                                    return Ok(());
                                }
                            }
                            backoff = (backoff * 2).min(max_backoff);

                            match ssh::connect(remote).await {
                                Ok(new_session) => {
                                    let attach_cmd = format!(
                                        "~/.rexec/rexec attach --pid {} --offset {}",
                                        pid_val, offset
                                    );
                                    match new_session.channel_open_session().await {
                                        Ok(new_channel) => {
                                            match new_channel.exec(true, attach_cmd.as_str()).await {
                                                Ok(()) => {
                                                    session = new_session;
                                                    channel = new_channel;
                                                    // Preserve total offset across FrameReader reset
                                                    base_offset = offset;
                                                    frame_reader = FrameReader::new();
                                                    status!("✓ Reconnected. Resuming...");
                                                    reconnected = true;
                                                    break;
                                                }
                                                Err(e) => {
                                                    status!("  Failed to exec attach: {}", e);
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            status!("  Failed to open channel: {}", e);
                                            continue;
                                        }
                                    }
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        }

                        if !reconnected {
                            return Err(anyhow!(
                                "connection lost after {} retries. Remote PID: {}",
                                max_retries, pid_val
                            ));
                        }
                        // Continue reading from the new (attach) channel
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Collect env vars from `-e/--env` flags first, then `--env-file` contents.
fn collect_env(env: &[String], env_file: &[PathBuf]) -> Result<Vec<(String, String)>> {
    let mut env_vars: Vec<(String, String)> = Vec::new();
    for e in env {
        let (k, v) = e
            .split_once('=')
            .ok_or_else(|| anyhow!("--env expects KEY=VALUE, got '{}'", e))?;
        if k.is_empty() {
            return Err(anyhow!("--env key is empty in '{}'", e));
        }
        env_vars.push((k.to_string(), v.to_string()));
    }
    for f in env_file {
        env_vars.extend(parse_env_file(f)?);
    }
    Ok(env_vars)
}

/// Decide how to run a script. Returns `None` to execute it directly (script has
/// a `#!` shebang), or `Some(cmd)` to run it via `cmd <script>`.
fn detect_runner(script: &Path) -> Result<Option<String>> {
    use std::io::Read;
    let mut f = std::fs::File::open(script)
        .with_context(|| format!("opening script {}", script.display()))?;
    let mut buf = [0u8; 2];
    let n = f.read(&mut buf)?;
    if n == 2 && &buf == b"#!" {
        return Ok(None); // shebang → direct exec
    }
    match script.extension().and_then(|e| e.to_str()) {
        Some("py") => Ok(Some("python3".to_string())),
        _ => Ok(Some("sh".to_string())),
    }
}

/// Sync a local script to the remote and run it (the `script` subcommand).
async fn run_script(
    remote: &RemoteHost,
    host: &str,
    script: &Path,
    interpreter: Option<&str>,
    sync_to: Option<&str>,
    args: &[String],
    env_vars: &[(String, String)],
) -> Result<()> {
    let basename = script
        .file_name()
        .ok_or_else(|| {
            anyhow!(
                "cannot determine script file name from {}",
                script.display()
            )
        })?
        .to_string_lossy()
        .to_string();

    // Ensure the remote dir exists (single-file rsync does not create parents)
    // and resolve it to an absolute path. Using an absolute path for the
    // runner command avoids relying on shell tilde expansion, which quoting
    // would disable (python3 '$HOME/...' does not expand).
    let remote_script = {
        let mut session = ssh::connect(remote).await?;
        ssh::ensure_remote_binary(&mut session, host).await?;
        let home = ssh::exec_remote(&mut session, "printf %s \"$HOME\"")
            .await?
            .trim()
            .to_string();
        let dir = match sync_to {
            Some(s) if s.starts_with('~') => format!("{}{}", home, &s[1..]),
            Some(s) => s.to_string(),
            None => format!("{}/.rexec/scripts", home),
        };
        ssh::exec_remote(&mut session, &format!("mkdir -p {}", shell_quote(&dir)?)).await?;
        format!("{}/{}", dir, basename)
    };

    do_sync(script, &remote_script, remote).await?;

    let runner = match interpreter {
        Some(i) => Some(i.to_string()),
        None => detect_runner(script)?,
    };
    let mut parts: Vec<String> = Vec::new();
    match &runner {
        Some(r) => {
            parts.push(r.clone());
            parts.push(shell_quote(&remote_script)?);
        }
        None => {
            // shebang: chmod +x then run directly
            let q = shell_quote(&remote_script)?;
            parts.push(format!("chmod +x {} && {}", q, q));
        }
    }
    for a in args {
        parts.push(shell_quote(a)?);
    }
    let command = parts.join(" ");
    run_command(remote, host, &command, env_vars).await?;
    Ok(())
}

/// List SSH hosts from ~/.ssh/config (the `list` subcommand).
fn list_hosts(alias: Option<&str>) -> Result<()> {
    let path = dirs::home_dir()
        .context("cannot determine home directory")?
        .join(".ssh/config");
    if !path.exists() {
        return Err(anyhow!("~/.ssh/config not found at {}", path.display()));
    }
    let config_str =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = BufReader::new(config_str.as_bytes());
    let config = SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;

    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    if let Some(a) = alias {
        let p = config.query(a);
        let host = p.host_name.clone().unwrap_or_else(|| a.to_string());
        let port = p.port.unwrap_or(22);
        let user = p.user.clone().unwrap_or_else(|| default_user);
        println!("{:<24} {}@{}:{}", a, user, host, port);
        if let Some(id) = &p.identity_file {
            if let Some(first) = id.first() {
                println!("{:<24} identity: {}", "", first.display());
            }
        }
        return Ok(());
    }

    println!(
        "{:<24} {:<28} {:<6} {}",
        "ALIAS", "HOSTNAME", "PORT", "USER"
    );
    for host in config.get_hosts() {
        let patterns: Vec<String> = host.pattern.iter().map(|c| c.to_string()).collect();
        // Skip pure-wildcard entries (e.g. "Host *") — no useful alias.
        if patterns.iter().all(|p| p == "*") {
            continue;
        }
        let alias = patterns.join(" ");
        let hostname = host
            .params
            .host_name
            .clone()
            .unwrap_or_else(|| alias.split_whitespace().next().unwrap_or("").to_string());
        let port = host.params.port.unwrap_or(22);
        let user = host
            .params
            .user
            .clone()
            .unwrap_or_else(|| default_user.clone());
        println!("{:<24} {:<28} {:<6} {}", alias, hostname, port, user);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    QUIET.store(cli.quiet, Ordering::Relaxed);

    match (cli.host, cli.action, cli.port) {
        // ── Local operations ──
        (Some(host), Action::Init, port) => {
            let remote = resolve_host(&host, port)?;
            let mut session = ssh::connect(&remote).await?;
            ssh::check_and_install_deps(&mut session).await?;
        }
        (
            Some(host),
            Action::Run {
                sync,
                env,
                env_file,
                command,
            },
            port,
        ) => {
            if command.is_empty() {
                return Err(anyhow!(
                    "no command provided. Usage: rexec <host> run [--sync LOCAL:REMOTE] [--env KEY=VALUE]... -- <command...>"
                ));
            }
            let remote = resolve_host(&host, port)?;
            if let Some(sync_arg) = &sync {
                let (local, remote_path) = parse_sync_arg(sync_arg)?;
                do_sync(&local, &remote_path, &remote).await?;
            }
            let env_vars = collect_env(&env, &env_file)?;
            let command = command.join(" ");
            run_command(&remote, &host, &command, &env_vars).await?;
        }
        (
            Some(host),
            Action::Script {
                script,
                interpreter,
                sync_to,
                env,
                env_file,
                args,
            },
            port,
        ) => {
            let remote = resolve_host(&host, port)?;
            let env_vars = collect_env(&env, &env_file)?;
            run_script(
                &remote,
                &host,
                &script,
                interpreter.as_deref(),
                sync_to.as_deref(),
                &args,
                &env_vars,
            )
            .await?;
        }

        // ── Host listing (no host needed) ──
        (_, Action::List { alias }, _) => {
            list_hosts(alias.as_deref())?;
        }

        // ── Remote operations (internal, invoked via SSH exec) ──
        (None, Action::Worker, _) => {
            remote::worker().await?;
        }
        (None, Action::Attach { pid, offset }, _) => {
            remote::attach(pid, offset).await?;
        }

        // ── Mismatches ──
        (Some(_), Action::Worker, _) | (Some(_), Action::Attach { .. }, _) => {
            return Err(anyhow!(
                "worker/attach are internal commands, not used with a host"
            ));
        }
        (None, Action::Init, _) => {
            return Err(anyhow!("init requires a host"));
        }
        (None, Action::Run { .. }, _) => {
            return Err(anyhow!("run requires a host"));
        }
        (None, Action::Script { .. }, _) => {
            return Err(anyhow!("script requires a host"));
        }
    }

    Ok(())
}

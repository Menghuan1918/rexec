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

/// Load an SSH config with `Include` directives fully expanded.
///
/// The ssh2-config crate resolves relative Include paths with a glob against
/// the process CWD, while OpenSSH anchors every relative Include path at the
/// directory of the *top-level* user config (~/.ssh), regardless of nesting.
/// Without this expansion, aliases defined in e.g. `~/.ssh/config.d/*.conf`
/// silently vanish. We expand Includes ourselves — tilde, glob (skipping
/// directories and dotfiles), anchored at the top-level config dir, cycle
/// guard, depth limit — and hand the parser plain text with no Include lines
/// left. `%token`/`${VAR}` expansion (OpenSSH 9.9+) and `Match` conditionals
/// (unsupported by the crate) are not expanded.
fn load_ssh_config_text(path: &Path) -> Result<String> {
    // Every relative Include path anchors at the top-level config's dir.
    let root_dir = path.parent().unwrap_or(Path::new("."));
    let mut out = String::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    expand_config_file(path, root_dir, &mut out, &mut stack, Scope::Global)?;
    Ok(out)
}

/// The parse scope a line belongs to. OpenSSH tracks this as the `active`
/// boolean inherited down the Include chain (readconf.c `*activep`); the
/// textual equivalent here is the enclosing `Host` line — or a `Host *` line
/// for the global scope.
#[derive(Clone)]
enum Scope {
    Global,
    Host(String), // verbatim `Host` line
}

impl Scope {
    /// The line to re-emit after an Include to restore this scope.
    fn restore_line(&self) -> &str {
        match self {
            // Global directives must apply to every host: `Host *` makes the
            // crate attach them to the wildcard block (first-wins, so more
            // specific blocks defined earlier keep their values).
            Scope::Global => "Host *",
            Scope::Host(line) => line,
        }
    }
}

/// Append the contents of `path` to `out`, replacing `Include` lines with the
/// expanded contents of the referenced files. `root_dir` is the directory of
/// the top-level config (~/.ssh): every relative Include path anchors there,
/// at any nesting depth, matching OpenSSH user-config behavior. `inherited`
/// is the scope active where this file was Included from — child files start
/// in that scope and restore it after their own Includes, mirroring
/// readconf.c's `oactive`/`*activep = oactive` save/restore.
fn expand_config_file(
    path: &Path,
    root_dir: &Path,
    out: &mut String,
    stack: &mut Vec<PathBuf>,
    inherited: Scope,
) -> Result<()> {
    const MAX_INCLUDE_DEPTH: usize = 16;
    // OpenSSH fatals when include depth EXCEEDS 16 (readconf.c), i.e. 16
    // nested include levels are allowed; stack.len() counts open ancestors.
    if stack.len() > MAX_INCLUDE_DEPTH {
        return Err(anyhow!(
            "ssh config include depth exceeds {} at {}",
            MAX_INCLUDE_DEPTH,
            path.display()
        ));
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // Cycle guard: only the *ancestor chain* is deduplicated, so a file
    // included from two sibling blocks (diamond) is still expanded twice,
    // matching OpenSSH (which guards depth only).
    if stack.contains(&canonical) {
        return Ok(());
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        // OpenSSH tolerates a file vanishing between glob and open (ENOENT).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Non-UTF8 configs can't be parsed by the crate; OpenSSH reads bytes.
        // An included file is skipped with a warning rather than failing
        // every alias — but the top-level config itself stays a hard error
        // (silently ignoring ~/.ssh/config would turn every alias into a raw
        // hostname). At this point the top level has an empty stack.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData && !stack.is_empty() => {
            eprintln!("⚠ ssh config: skipping non-UTF8 include {}", path.display());
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("reading {}", path.display())));
        }
    };
    stack.push(canonical);
    let mut current_scope = inherited;
    for line in text.lines() {
        if let Some(args) = include_args(line) {
            for arg in args {
                let expanded = expand_tilde_path(&arg);
                let target = if expanded.is_absolute() {
                    expanded
                } else {
                    root_dir.join(expanded)
                };
                // Each matched file is emitted as its own block, preceded by
                // the current scope line (see expand_include_target): the
                // crate is last-wins WITHIN a block but first-wins ACROSS
                // blocks, and OpenSSH is first-obtained-wins AND restores the
                // scope after every single matched file — so an include must
                // neither override enclosing pre-include values nor let one
                // included file's trailing `Host` block capture the next
                // file's global directives.
                if let Err(e) =
                    expand_include_target(&target, root_dir, out, stack, current_scope.clone())
                {
                    stack.pop(); // keep the ancestor chain balanced on error paths
                    return Err(e);
                }
            }
            // OpenSSH restores the enclosing block's state after an include
            // (readconf.c: `*activep = oactive`) — including the state
            // inherited from a parent include. Directives after the Include
            // keep applying to the enclosing host (or globally).
            out.push_str(current_scope.restore_line());
            out.push('\n');
        } else {
            if is_host_line(line) {
                current_scope = Scope::Host(line.to_string());
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    stack.pop();
    Ok(())
}

/// Expand one Include argument (already tilde-expanded and anchored): glob it,
/// skip directories and dotfiles (OpenSSH's glob(3) does not match leading
/// dots), recurse into each matched file. A glob with no match is a silent
/// no-op (OpenSSH behavior).
fn expand_include_target(
    target: &Path,
    root_dir: &Path,
    out: &mut String,
    stack: &mut Vec<PathBuf>,
    scope: Scope,
) -> Result<()> {
    let pattern = target.to_string_lossy();
    let options = glob::MatchOptions {
        require_literal_leading_dot: true,
        ..Default::default()
    };
    let paths = match glob::glob_with(pattern.as_ref(), options) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("⚠ ssh config: invalid Include pattern {pattern}: {e}");
            return Ok(());
        }
    };
    for entry in paths.flatten() {
        // Directories matched by the glob are skipped, not fatal (OpenSSH
        // reads them as empty configs). This also skips dangling symlinks
        // (metadata follows the link, ENOENT → not a file).
        let is_file = std::fs::metadata(&entry)
            .map(|m| m.is_file())
            .unwrap_or(false);
        if !is_file {
            continue;
        }
        // OpenSSH restores the active scope after EVERY matched file
        // (readconf.c: "don't let Match in includes clobber the containing
        // file's Match state"). Textually: start each file's block with the
        // enclosing scope line, so a file ending inside its own `Host` block
        // cannot capture the next file's global directives.
        out.push_str(scope.restore_line());
        out.push('\n');
        expand_config_file(&entry, root_dir, out, stack, scope.clone())?;
    }
    Ok(())
}

/// True if `line` opens a `Host` block (case-insensitive keyword, whitespace
/// or `=` after it).
fn is_host_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    trimmed[..kw_end].eq_ignore_ascii_case("host")
}

/// If `line` is an `Include` directive (`Include paths...`, fully
/// case-insensitive keyword, `=` with optional surrounding whitespace
/// allowed, args may be single- or double-quoted to carry spaces), return
/// the parsed path arguments.
fn include_args(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    if !trimmed[..kw_end].eq_ignore_ascii_case("include") {
        return None; // any other keyword — including lookalikes (IncludeX)
    }
    let rest = trimmed[kw_end..].trim_start();
    let rest = rest
        .strip_prefix('=')
        .map(|r| r.trim_start())
        .unwrap_or(rest);
    // Tokenize like OpenSSH's argv_split (misc.c): quotes carry spaces and
    // ADJACENT quoted/unquoted fragments join into one token
    // (`"dir/"*.conf` is a single arg); an unquoted `#` starting a token ends
    // the argument list (comment). Returns Some(vec![]) for a bare/malformed
    // keyword line: the line is consumed (dropped) rather than passed through
    // to the crate's own CWD-relative Include handling.
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false; // current token has content (possibly just quotes)
    'chars: for ch in rest.chars() {
        match quote {
            Some(q) if ch == q => quote = None, // fragment continues; do not split
            Some(_) => {
                cur.push(ch);
                started = true;
            }
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '#' if !started => break 'chars, // comment: stop parsing args
                c if c.is_whitespace() => {
                    if started {
                        args.push(std::mem::take(&mut cur));
                        started = false;
                    }
                }
                _ => {
                    cur.push(ch);
                    started = true;
                }
            },
        }
    }
    if started {
        args.push(cur);
    }
    Some(args)
}

/// Expand a leading `~` or `~/` to the user's home directory.
fn expand_tilde_path(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if p == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    PathBuf::from(p)
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
            let config_str = load_ssh_config_text(&ssh_config_path)?;
            let mut reader = BufReader::new(config_str.as_bytes());
            let config = SshConfig::default()
                .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
                .context("parsing ssh config (after Include expansion)")?;
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

            // Step 2: simulate remote shell parsing the worker_cmd
            // The remote shell sees: <binary> worker -- <quoted_command>
            // It strips the single quotes and passes the original command to the worker
            let worker_output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {}", quoted))
                .output()
                .expect("failed to run sh");
            let received = String::from_utf8(worker_output.stdout).unwrap();

            // Step 3: the worker runs sh -c with the received command
            assert_eq!(
                received, cmd,
                "command corrupted through quoting chain: {:?} → {:?} → {:?}",
                cmd, quoted, received
            );
        }
    }

    #[test]
    fn test_ssh_config_include_expansion() {
        // Layout (root-anchored: every relative Include path resolves against
        // the TOP-LEVEL config dir, matching OpenSSH — not the including
        // file's dir, not the CWD; the test CWD is the crate root):
        //   tmp/ssh/config            → Host main + Include config.d/*.conf
        //   tmp/ssh/config.d/a.conf   → Host alias-a (Port 27001)
        //   tmp/ssh/config.d/b.conf   → nested iNcLuDe = extra.conf
        //   tmp/ssh/extra.conf        → Host alias-b
        // Plus a directory and a dotfile in config.d/ that the glob must not
        // blow up on (dirs are skipped, dotfiles are not matched).
        let base = std::env::temp_dir().join(format!("rexec-test-inc-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d/subdir")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host main\n  HostName 1.2.3.4\nInclude config.d/*.conf\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("config.d/a.conf"),
            "Host alias-a\n  HostName 5.6.7.8\n  Port 27001\n",
        )
        .unwrap();
        std::fs::write(ssh.join("config.d/b.conf"), "iNcLuDe = extra.conf\n").unwrap();
        std::fs::write(ssh.join("extra.conf"), "Host alias-b\n  HostName 9.9.9.9\n").unwrap();
        std::fs::write(
            ssh.join("config.d/.hidden.conf"),
            "Host hidden\n  HostName 3.3.3.3\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(
            !text.lines().any(|l| include_args(l).is_some()),
            "Include lines must be expanded away: {text}"
        );
        assert!(
            text.contains("Host alias-a"),
            "included host missing: {text}"
        );
        assert!(text.contains("Port 27001"));
        assert!(
            text.contains("Host alias-b"),
            "nested include missing: {text}"
        );
        assert!(
            text.contains("Host main"),
            "including file content must survive"
        );
        assert!(!text.contains("hidden"), "dotfiles must not be globbed");

        // The expanded text must actually parse and resolve the included alias.
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alias-a").port.unwrap(), 27001);
        assert_eq!(config.query("alias-a").host_name.unwrap(), "5.6.7.8");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_restores_host_scope() {
        // OpenSSH: after an Include inside a Host block, the enclosing host's
        // state is restored — `Port 27001` below belongs to prod, and the
        // included `Host net` gets its own block without leaking.
        let base = std::env::temp_dir().join(format!("rexec-test-scope-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("prod.d")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include prod.d/net.conf\n  Port 27001\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("prod.d/net.conf"),
            "Host net\n  HostName 10.0.0.9\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            27001,
            "prod keeps its port after the include"
        );
        assert_eq!(config.query("net").host_name.unwrap(), "10.0.0.9");
        assert!(
            config.query("net").port.is_none(),
            "net must not inherit prod's port"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_restores_inherited_host_scope() {
        // The scope INHERITED from a parent include must be restored after a
        // nested Include (readconf.c's oactive is inherited down the chain):
        // prod.conf is included inside `Host prod` and itself includes
        // extra.conf; after that nested include, prod.conf's directives must
        // keep applying to prod — not leak into extra.conf's `Host other`.
        let base = std::env::temp_dir().join(format!("rexec-test-inh-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("conf.d")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include conf.d/prod.conf\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("conf.d/prod.conf"),
            "Include conf.d/extra.conf\nHostName 10.0.0.1\nPort 27001\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("conf.d/extra.conf"),
            "Host other\n  HostName 1.1.1.1\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").host_name.unwrap(),
            "10.0.0.1",
            "prod must keep its directives after the nested include"
        );
        assert_eq!(config.query("prod").port.unwrap(), 27001);
        assert_eq!(config.query("other").host_name.unwrap(), "1.1.1.1");
        assert!(
            config.query("other").port.is_none(),
            "other must not inherit prod's port"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_top_include_then_global_directive() {
        // A global directive after a top-level Include applies to every host
        // (OpenSSH seeds active=1 at file scope); without a scope restore it
        // would be absorbed into the last included Host block.
        let base = std::env::temp_dir().join(format!("rexec-test-glob-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("inc")).unwrap();
        std::fs::write(ssh.join("config"), "Include inc/a.conf\nPort 2222\n").unwrap();
        std::fs::write(ssh.join("inc/a.conf"), "Host alpha\n  HostName 5.5.5.5\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alpha").port.unwrap(), 2222);
        assert_eq!(
            config.query("unrelated").port.unwrap(),
            2222,
            "global directive must apply to hosts other than the included ones"
        );
        assert_eq!(config.query("alpha").host_name.unwrap(), "5.5.5.5");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_dir_matched_by_glob_is_skipped() {
        // A directory matched by the include glob must be skipped, not fatal
        // (a git-managed ~/.ssh has .git dirs; `config.d/*` matches subdirs).
        let base = std::env::temp_dir().join(format!("rexec-test-dirg-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d/adir")).unwrap();
        std::fs::write(ssh.join("config"), "Include config.d/*\nHost top\n").unwrap();
        std::fs::write(ssh.join("config.d/adir/inner.conf"), "Host inner\n").unwrap();
        std::fs::write(ssh.join("config.d/real.conf"), "Host real\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(text.contains("Host top"));
        assert!(text.contains("Host real"), "regular files load: {text}");
        assert!(
            !text.contains("inner"),
            "a directory hit by the glob must not be read"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_depth_boundary() {
        // OpenSSH allows 16 nested include levels and fatals beyond.
        let base = std::env::temp_dir().join(format!("rexec-test-depb-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let make_chain = |n: usize| {
            for i in 0..n {
                let next = if i + 1 < n {
                    format!("Include c{}.conf\n", i + 1)
                } else {
                    "Host deepest\n".to_string()
                };
                std::fs::write(ssh.join(format!("c{i}.conf")), next).unwrap();
            }
        };
        // chain(n) = n files = n-1 include levels; OpenSSH allows 16 levels.
        make_chain(17);
        let ok = load_ssh_config_text(&ssh.join("c0.conf")).unwrap();
        assert!(
            ok.contains("Host deepest"),
            "16 include levels must be allowed"
        );

        make_chain(18);
        assert!(
            load_ssh_config_text(&ssh.join("c0.conf")).is_err(),
            "17 include levels must fail"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_no_override_of_enclosing_values() {
        // OpenSSH is first-obtained-wins: an include without Host lines must
        // NOT override a value the enclosing host set before the Include,
        // even though the crate is last-wins within a single block. The
        // pre-include scope re-emit splits the blocks so first-wins applies.
        let base = std::env::temp_dir().join(format!("rexec-test-ovr-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("inc.conf"), "Port 9999\nUser included\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Port 2202\n  Include inc.conf\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            2202,
            "the enclosing host's pre-include value must win (OpenSSH first-obtained)"
        );
        assert_eq!(
            config.query("prod").user.unwrap(),
            "included",
            "non-conflicting include values must still apply to the enclosing host"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_glob_files_do_not_capture_each_other() {
        // OpenSSH restores the scope after EVERY matched file: a defaults
        // file that sorts after an alias file must still contribute global
        // directives — not be captured into the alias file's trailing
        // `Host` block. This is the realistic config.d/*.conf shape.
        let base = std::env::temp_dir().join(format!("rexec-test-cap-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("inc")).unwrap();
        std::fs::write(ssh.join("config"), "Include inc/*.conf\nHost marker\n").unwrap();
        std::fs::write(
            ssh.join("inc/a-alias.conf"),
            "Host alpha\n  HostName 5.5.5.5\n",
        )
        .unwrap();
        std::fs::write(ssh.join("inc/b-defaults.conf"), "Port 8888\nUser gu\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alpha").host_name.unwrap(), "5.5.5.5");
        assert_eq!(
            config.query("beta").port.unwrap(),
            8888,
            "global directives from a later file must apply to unrelated hosts"
        );
        assert_eq!(config.query("beta").user.unwrap(), "gu");
        assert_eq!(config.query("alpha").port.unwrap(), 8888);
        assert_eq!(config.query("marker").port.unwrap(), 8888);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_two_include_args_in_host_block() {
        // `Include A B` inside a Host block: OpenSSH restores the scope after
        // each arg; values from B (which has no Host lines) must reach the
        // enclosing host even though A ended inside its own Host block.
        let base = std::env::temp_dir().join(format!("rexec-test-2arg-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("a.conf"), "Host inner\n  HostName 7.7.7.7\n").unwrap();
        std::fs::write(ssh.join("b.conf"), "Port 8888\nUser gu\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include a.conf b.conf\n  Port 2202\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            8888,
            "values from the second include arg must reach prod (first-obtained)"
        );
        assert_eq!(config.query("prod").user.unwrap(), "gu");
        assert_eq!(config.query("inner").host_name.unwrap(), "7.7.7.7");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_diamond_include() {
        // The same file included from two Host blocks must be expanded twice
        // (OpenSSH re-includes; only the ancestor chain is deduplicated).
        let base = std::env::temp_dir().join(format!("rexec-test-dia-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("shared.conf"), "Port 2999\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host a\n  Include shared.conf\nHost b\n  Include shared.conf\n",
        )
        .unwrap();
        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("a").port.unwrap(), 2999);
        assert_eq!(config.query("b").port.unwrap(), 2999);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_quoted_and_spaces() {
        let base = std::env::temp_dir().join(format!("rexec-test-q-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("dir with space")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Include \"dir with space/x.conf\"\nInclude 'y.conf'\n",
        )
        .unwrap();
        std::fs::write(ssh.join("dir with space/x.conf"), "Host qx\n").unwrap();
        std::fs::write(ssh.join("y.conf"), "Host qy\n").unwrap();
        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(text.contains("Host qx"), "quoted path with space: {text}");
        assert!(text.contains("Host qy"), "single-quoted path: {text}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_depth_limit() {
        let base = std::env::temp_dir().join(format!("rexec-test-dep-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        for i in 0..20 {
            std::fs::write(
                ssh.join(format!("c{i}.conf")),
                format!("Include c{}.conf\n", i + 1),
            )
            .unwrap();
        }
        let result = load_ssh_config_text(&ssh.join("c0.conf"));
        assert!(
            result.is_err(),
            "chain of 20 includes must hit the depth limit"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_cycle_and_missing_glob() {
        let base = std::env::temp_dir().join(format!("rexec-test-inc2-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        // a includes a missing glob and b; b includes a back (cycle).
        std::fs::write(
            ssh.join("a.conf"),
            "Include missing-dir/*.conf b.conf\nHost ha\n",
        )
        .unwrap();
        std::fs::write(ssh.join("b.conf"), "Include a.conf\nHost hb\n").unwrap();
        let text = load_ssh_config_text(&ssh.join("a.conf")).unwrap();
        assert!(text.contains("Host ha"));
        assert!(text.contains("Host hb"));
        assert!(
            !text.lines().any(|l| include_args(l).is_some()),
            "no Include lines may survive: {text}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_include_args_forms() {
        assert_eq!(
            include_args("Include config.d/x.conf"),
            Some(vec!["config.d/x.conf".to_string()])
        );
        assert_eq!(
            include_args("include=z.conf"),
            Some(vec!["z.conf".to_string()])
        );
        assert_eq!(
            include_args("iNcLuDe = a.conf b.conf"),
            Some(vec!["a.conf".to_string(), "b.conf".to_string()])
        );
        assert_eq!(
            include_args("INCLUDE \"a b.conf\" c.conf"),
            Some(vec!["a b.conf".to_string(), "c.conf".to_string()])
        );
        assert_eq!(
            include_args("Include \"dir/\"*.conf"),
            Some(vec!["dir/*.conf".to_string()]),
            "adjacent quoted/unquoted fragments must join"
        );
        assert_eq!(
            include_args("Include a.conf # trailing comment"),
            Some(vec!["a.conf".to_string()]),
            "unquoted # starting a token ends the arg list"
        );
        assert_eq!(
            include_args("Include a#b.conf"),
            Some(vec!["a#b.conf".to_string()]),
            "# inside a token is literal"
        );
        assert_eq!(
            include_args("Include"),
            Some(vec![]),
            "bare keyword: consumed (dropped), not passed through"
        );
        assert_eq!(include_args("Host foo"), None, "other keyword");
        assert_eq!(
            include_args("  IncludeX y"),
            None,
            "IncludeX is not Include"
        );
        assert_eq!(
            include_args("hostname 1.2.3.4"),
            None,
            "hostname is not include"
        );
        assert!(is_host_line("Host prod"));
        assert!(is_host_line("  host = x"));
        assert!(!is_host_line("HostName 1.2.3.4"));
        assert!(!is_host_line("HostKeyAlias k"));
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
    let config_str = load_ssh_config_text(&path)?;
    let mut reader = BufReader::new(config_str.as_bytes());
    let config = SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
        .context("parsing ssh config (after Include expansion)")?;

    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    if let Some(a) = alias {
        let p = config.query(a);
        let host = p.host_name.clone().unwrap_or_else(|| a.to_string());
        let port = p.port.unwrap_or(22);
        let user = p.user.clone().unwrap_or_else(|| default_user);
        println!("{:<24} {}@{}:{}", a, user, host, port);
        if let Some(id) = &p.identity_file
            && let Some(first) = id.first()
        {
            println!("{:<24} identity: {}", "", first.display());
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

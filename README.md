# rexec — Remote Code Execution + Folder Sync

A CLI to sync local files/folders and run commands on remote hosts over SSH, designed to survive SSH disconnections. The remote worker keeps running after SSH drops; the CLI auto-reconnects and resumes output from the last byte.

**Platforms**: local macOS/Linux → remote Linux (amd64/arm64). When the two differ (e.g. macOS local → Linux remote), the worker binary for the remote is downloaded from GitHub Releases automatically — the remote needs no internet access.

## Features

- **Folder/file sync**: rsync a local file or folder to the remote before running
- **Script run**: one-command sync + run a local script (`script` subcommand)
- **Host listing**: list SSH hosts from `~/.ssh/config` (`list` subcommand)
- **Disconnect resilience**: remote worker ignores SIGHUP and writes to a log; CLI reconnects with backoff and resumes from the last byte
- **Auto binary deploy**: deploys a version-matched worker to the remote on first use — uploads itself when platforms match, otherwise downloads the prebuilt worker from GitHub Releases (e.g. macOS local → Linux remote)
- **Secrets/command out of argv**: env vars and the command are sent over stdin and the command runs from a private script file — neither appears on any cmdline, so `pkill -f`/`pgrep -f` can't match them by command content (env vars are still visible in `/proc/<pid>/environ` to the same user)
- **SSH config**: resolves host aliases from `~/.ssh/config`; `user@host:port` literals work everywhere (run **and** sync)
- **Quiet mode**: `--quiet` suppresses progress lines so stdout carries only the command's own output

## Install

```bash
# From source
cargo build --release
cp target/release/remote-exec ~/.local/bin/rexec

# Or download a prebuilt binary (linux/macos × amd64/arm64 — pick your platform)
curl -fL -o ~/.local/bin/rexec \
  https://github.com/Menghuan1918/rexec/releases/latest/download/rexec-macos-arm64
chmod +x ~/.local/bin/rexec
```

## Usage

```bash
# Check and install remote dependencies (run once per host)
rexec <host> init

# Sync a folder and run a command
rexec <host> run --sync local_dir:remote_dir -- "bash deploy.sh"

# Run a command without syncing
rexec <host> run -- "python train.py --epochs 100"

# ssh-config alias OR user@host:port — both work for run and --sync
rexec my-server run --sync ./project:/home/user/project -- "python main.py"
rexec root@192.168.1.100:2222 run --sync ./deploy.sh:/opt/deploy.sh -- "bash /opt/deploy.sh"

# Override the port (applies to both SSH and rsync)
rexec -p 2222 root@192.168.1.100 run -- "df -h"

# Sync + run a local script in one step (interpreter auto-detected)
rexec <host> script ./deploy.sh -- arg1 arg2
rexec <host> script --interpreter python3 ./train.py -- --epochs 10
rexec <host> script -e API_KEY=sk-xxx ./fetch.py

# List hosts from ~/.ssh/config
rexec list
rexec list my-server

# Suppress progress output (Remote PID, exit, sync, reconnect)
rexec -q <host> run -- "echo only-this"
```

### `run` options

| Option | Description |
|--------|-------------|
| `--sync LOCAL:REMOTE` | rsync a local **file or folder** to the remote before running. Folders sync contents with `--delete`; a single file is sent as-is. |
| `-e KEY=VALUE` / `--env KEY=VALUE` | Set an env var on the remote command. Repeatable. Not exposed in `ps`. |
| `--env-file PATH` | Read `KEY=VALUE` lines from a local file (supports `#` comments and `export ` prefix). Repeatable. |
| `-- <command...>` | Command to run on the remote (joined; executed by the worker from a private script file). |

### Global options

| Option | Description |
|--------|-------------|
| `-p PORT` / `--port PORT` | SSH port (overrides `host:port` and ssh-config `Port`) |
| `-q` / `--quiet` | Suppress progress/status output (Remote PID, exit, sync, reconnect) |

### `script` — sync and run a local script

```bash
rexec <host> script [--interpreter CMD] [--sync-to REMOTE_DIR] [-e K=V] [--env-file F] <local_script> [-- args...]
```

Syncs the script to `~/.rexec/scripts/` (or `--sync-to`), then runs it. The interpreter is auto-detected: a `#!` shebang runs the script directly; otherwise `.py` → `python3`, else `sh`. Override with `--interpreter`. Args after `--` are passed to the script.

### `list` — show configured hosts

```bash
rexec list [alias]
```

Reads `~/.ssh/config` and prints each host's alias, hostname, port, and user (pure-wildcard entries like `Host *` are skipped). Pass an alias for the resolved details of a single host.

## How it works

1. If `--sync` is given, runs `rsync -az [--delete] -e "ssh [-p PORT] ..."` to sync the local file/folder to the remote. The port from `host:port` or `--port` is passed to rsync via `ssh -p` (so `user@host:port` works for sync too).
2. Connects via russh (pure Rust SSH), authenticates via agent → identity-file → default keys.
3. Ensures `~/.rexec/rexec` exists on the remote and matches the local version. If the remote platform matches the local one, it uploads the running binary via rsync; otherwise it downloads the version-pinned worker from GitHub Releases (cached in `~/.rexec/cache/`, so each version/target is downloaded once) and rsyncs that over.
4. Starts `~/.rexec/rexec worker` over the SSH channel. The **command and env vars are sent over stdin** (not argv), so neither appears in the remote worker's `ps`/`pkill -f`/`pgrep -f` output.
5. The worker ignores SIGHUP, writes the command to a private script (`~/.rexec/run/<pid>.sh`, mode 0600, removed on exit; stale ones swept on startup), spawns `sh <script>`, and streams stdout/stderr back via a binary frame protocol — writing every frame to `~/.rexec/logs/<pid>.log` and to the SSH channel. The script-file indirection keeps command text out of every process's cmdline, so `sh -c "pkill -f foo"`-style self-kills cannot happen.
6. On SSH disconnect: the worker keeps running; the CLI reconnects with exponential backoff (1s→30s, max 10) and resumes from the last byte offset via `~/.rexec/rexec attach --pid <PID> --offset <N>`.
7. On process completion: prints exit status; the log file is removed on exit code 0.

## SSH Disconnection Behavior

- Remote process **continues running** (worker ignores SIGHUP — not killed when SSH drops)
- Local CLI **auto-reconnects** with exponential backoff (1s→30s, max 10)
- Output **resumes from the last byte offset** — no data lost
- If reconnection fails after 10 retries, prints the remote PID and exits
- The log file persists at `~/.rexec/logs/<pid>.log` on the remote (cleaned up on exit code 0)
- Re-attach manually: `ssh <host> "~/.rexec/rexec attach --pid <PID> --offset 0"`

## `init` Command

Checks that `rsync` and `sh` exist on the remote host. If `rsync` is missing, auto-detects the package manager (`apt-get`/`yum`/`dnf`/`apk`/`pacman`) and installs it. (`nohup` is not required — the worker handles disconnect survival via SIGHUP.)

```bash
rexec my-server init
```

## Build

```bash
cargo build --release
# Binary at target/release/remote-exec
```

### Releasing

Push a tag to trigger both release workflows: `.github/workflows/release.yml` builds native binaries for linux/macos × amd64/arm64 and attaches them to a GitHub Release, while `.github/workflows/publish.yml` publishes the crate to [crates.io](https://crates.io/crates/remote-exec) via trusted publishing (OIDC token exchange, no API token stored as a secret). A tag can also be published manually: `gh workflow run publish.yml -f tag=v0.2.1`.

```bash
git tag v0.2.1 && git push origin v0.2.1
```

Cross-platform deploys (e.g. macOS local → Linux remote) download these release assets pinned to the running version, so a version must be released before it can deploy a mismatched remote platform.

## Dependencies

- `russh` — pure Rust SSH client
- `ssh2-config` — parse ~/.ssh/config
- `clap` — CLI parsing
- `tokio` — async runtime
- `anyhow` — error handling
- `dirs`, `libc`, `rsa`, `russh-keys`, `rand`
- `rsync` (system) — required for sync (local + remote)
- `curl` (system) — required locally, to download cross-platform workers from GitHub Releases
- `sh` (system) — required on the remote

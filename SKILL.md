---
name: rexec
description: "Remote code execution + folder sync over SSH. Use when the user wants to run commands on a remote server, sync local folders/files to remote, or execute scripts remotely with SSH disconnect resilience. Activates on keywords: rexec, remote exec, remote sync, sync and run."
---

# rexec — Remote Execution + Folder Sync over SSH

Sync local files/folders and run commands on a remote host over SSH. Commands survive SSH disconnects: the remote worker keeps running, and the CLI auto-reconnects and resumes output.

## Binary

```
rexec   # ~/.local/bin/rexec   (source: /root/Code/rexec)
```

Run `rexec <host> init` once per new host to check/install remote deps (rsync, sh).

## Usage

```bash
# Sync a folder + run a command
rexec <host> run --sync ./project:/home/user/project -- "python main.py"

# Run only (no sync)
rexec <host> run -- "bash deploy.sh"

# ssh-config alias or user@host:port both work (for run AND --sync)
rexec prod run -- "systemctl status nginx"
rexec root@1.2.3.4:2222 run --sync ./deploy.sh:/opt/deploy.sh -- "bash /opt/deploy.sh"

# Override port globally (applies to SSH and rsync)
rexec -p 2222 root@1.2.3.4 run -- "df -h"

# Sync + run a local script in one step
rexec <host> script ./deploy.sh -- arg1 arg2

# List hosts from ~/.ssh/config
rexec list

# Quiet: stdout carries only the command's output
rexec -q <host> run -- "echo hi"
```

### `run` options

| Option | Description |
|--------|-------------|
| `--sync LOCAL:REMOTE` | rsync a local **file or folder** to the remote before running. Folders sync *contents* with `--delete`; a single file is sent as-is. |
| `-e KEY=VALUE` / `--env KEY=VALUE` | Set an env var on the remote command. Repeatable. Secrets never appear in the remote `ps`. |
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

Syncs the script to `~/.rexec/scripts/` (or `--sync-to`), then runs it. Interpreter auto-detected: `#!` shebang runs directly; `.py` → `python3`; else `sh`. Override with `--interpreter`.

### `list` — show configured hosts

```bash
rexec list [alias]
```

Reads `~/.ssh/config` and prints each host's alias/hostname/port/user (pure-wildcard entries skipped). Pass an alias for single-host details.

### Environment variables

Pass secrets or config without inline `export`/escaping pain:

```bash
rexec <host> run -e API_KEY=sk-xxx -e DEBUG=1 -- "python app.py"

# Or load many from a local file (KEY=VALUE per line):
rexec <host> run --env-file ./secrets.env -- "python app.py"
```

Env vars are sent to the remote over the SSH channel and applied to the command — they are **not** exposed in the remote process's command line (`ps`).

### Syncing files vs folders

```bash
# Folder: syncs directory contents (trailing slash optional on LOCAL)
rexec dev run --sync ./src:/opt/app/src -- "make build"

# Single file: send one script and run it
rexec dev run --sync ./deploy.sh:/opt/app/deploy.sh -- "bash /opt/app/deploy.sh"
```

- Folders use `rsync --delete`: remote files absent locally are removed — keep the remote path dedicated to your project.
- For a single file, the remote **parent directory must exist** (rsync does not create it).

## Tips

- **Long-running jobs: run rexec in the background.** rexec streams until the remote process exits, which may outlast a foreground shell's timeout (and get killed mid-stream). Launch long jobs with a background command — `&`, `nohup`, or your agent's background-task tool — so the remote worker isn't cut off. If interrupted, rexec prints the remote PID; the worker keeps running (see Disconnect behavior to resume).
- **Output not streaming?** When stdout is not a TTY (pipes, `cmd | tail`, docker build), programs block-buffer their output, so rexec shows nothing until they flush or exit. Avoid `| tail`/`| head`; stream the command directly, or force line buffering with `stdbuf -oL -eL <cmd>` / `PYTHONUNBUFFERED=1` (pass via `-e`).
- **Local edit → sync → remote run** is the recommended loop: edit locally, then `rexec <host> run --sync ./dir:/remote/dir -- "..."` pushes and executes in one step.
- **Use `--quiet` for scriptable output.** `rexec -q <host> run -- "..."` suppresses Remote PID/exit/sync/reconnect lines so stdout holds only the command's output — no need to `grep -v` them.
- **`pkill -f`/`pgrep -f` won't match the worker or its shell by command text.** The command and env vars are sent over stdin, not argv, and the command runs from a private script file (`sh ~/.rexec/run/<pid>.sh`, mode 0600, deleted on exit) instead of `sh -c <cmd>` — no process in the chain exposes the command text in its cmdline, so the classic `sh -c "pkill -f foo"` self-kill cannot happen. Target processes still match `pkill -f` normally (their cmdlines are their own). Caveat: a pattern that matches the chain's fixed strings (`rexec`, `.sh`, `run/`) still hits — scope patterns to command content. Also note `$0` inside the command is now the script path, not `sh`.

## Disconnect behavior

- **SSH drops:** the remote worker keeps running and writing to a log; the CLI reconnects (backoff 1s→30s, up to 10 tries) and resumes output from the last byte — no data lost.
- **CLI killed (Ctrl+C / SIGTERM):** prints the remote PID; the remote process continues. Re-attach later with `ssh <host> "~/.rexec/rexec attach --pid <PID> --offset 0"`.

## Prerequisites

- Local (macOS or Linux): `rsync`, `curl`, SSH agent or keys.
- Remote: Linux only — `rsync`, `sh` (`rexec <host> init` verifies/installs).
- Cross-platform (e.g. macOS local → Linux remote) works out of the box: the worker is downloaded from GitHub Releases (needs a released tag matching the rexec version; cached in `~/.rexec/cache/`). Same-platform pairs deploy the running binary directly.

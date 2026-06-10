import os
import re
import select
import shlex
import subprocess
import sys
import threading
import time

from db import add_artifact
from creds import RECON_CREDS_BANNER
from creds import import_hydra
from creds import emit_import_results
from db import add_execution
from db import find_done_execution
from url_util import canonicalize_probe_command
from db import finish_execution


DEFAULT_TIMEOUT_SEC = 300
DEFAULT_EXEC_SHELL = os.environ.get("RECON_EXEC_SHELL", "zsh")
DEFAULT_EXEC_MODE = os.environ.get("RECON_EXEC_MODE", "shell")  # shell|argv
# Load zsh aliases/functions (scan, scout, gb-dirs, etc.) before running the command.
DEFAULT_EXEC_INIT = os.environ.get(
    "RECON_EXEC_INIT",
    "[[ -f ~/.zshrc ]] && source ~/.zshrc; setopt aliases 2>/dev/null",
)
# Use a pseudo-TTY when streaming so tools like hydra (-V) line-buffer output.
USE_PTY = os.environ.get("RECON_EXEC_PTY", "1") != "0"


def _shell_argv(command: str) -> list:
    init = (DEFAULT_EXEC_INIT or "").strip()
    if init:
        full = f"{init}; {command}"
    else:
        full = command
    return [DEFAULT_EXEC_SHELL, "-lc", full]


def _extract_artifacts(ip: str, execution_id: int, text: str):
    if not text:
        return

    for m in re.finditer(r"flag\{[^}]+\}", text, flags=re.IGNORECASE):
        add_artifact(ip, "flag_candidate", "", m.group(0), execution_id)


def _run_subprocess_capture(args, timeout_sec, env):
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
        env=env,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _run_subprocess_stream(args, timeout_sec, env, use_pty: bool):
    """Stream child output to the terminal while accumulating for DB storage."""
    if use_pty:
        import pty

        master_fd, slave_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                args,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                close_fds=True,
            )
        finally:
            os.close(slave_fd)

        chunks = []
        deadline = time.monotonic() + timeout_sec

        def _drain():
            while True:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                text = data.decode(errors="replace")
                chunks.append(text)
                sys.stdout.write(text)
                sys.stdout.flush()

        while proc.poll() is None:
            if time.monotonic() > deadline:
                proc.kill()
                proc.wait()
                os.close(master_fd)
                return None, "".join(chunks), ""
            r, _, _ = select.select([master_fd], [], [], 0.2)
            if master_fd in r:
                _drain()

        _drain()
        os.close(master_fd)
        proc.wait()
        return proc.returncode, "".join(chunks), ""

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )
    stdout_parts = []
    stderr_parts = []

    def _pump(stream, parts, out):
        for line in iter(stream.readline, ""):
            parts.append(line)
            out.write(line)
            out.flush()
        stream.close()

    t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_parts, sys.stdout))
    t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_parts, sys.stderr))
    t_out.start()
    t_err.start()

    try:
        proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t_out.join()
        t_err.join()
        return None, "".join(stdout_parts), "".join(stderr_parts)

    t_out.join()
    t_err.join()
    return proc.returncode, "".join(stdout_parts), "".join(stderr_parts)


def run_command(
    ip: str,
    command: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    task_id=None,
    task_type="manual",
    stream: bool = False,
):
    """
    Run an arbitrary command and store stdout/stderr in executions table.
    When stream=True, print output as it arrives (PTY by default for line buffering).
    """
    if not ip:
        raise ValueError("ip required")
    if not command or not command.strip():
        raise ValueError("command required")

    command = command.strip()
    exec_id = add_execution(task_id, ip, task_type, command, cwd="/", status="running")

    try:
        mode = (DEFAULT_EXEC_MODE or "shell").strip().lower()
        if mode == "argv":
            args = shlex.split(command)
        else:
            args = _shell_argv(command)

        env = os.environ.copy()

        if stream:
            exit_code, stdout, stderr = _run_subprocess_stream(
                args, timeout_sec, env, use_pty=USE_PTY
            )
        else:
            exit_code, stdout, stderr = _run_subprocess_capture(args, timeout_sec, env)

        if exit_code is None:
            finish_execution(
                exec_id,
                status="timeout",
                exit_code=None,
                stdout=stdout[-20000:],
                stderr=stderr[-20000:],
            )
            return exec_id

        status = "done" if exit_code == 0 else "failed"
        finish_execution(
            exec_id,
            status=status,
            exit_code=exit_code,
            stdout=stdout[-20000:],
            stderr=stderr[-20000:],
        )

        _extract_artifacts(ip, exec_id, stdout)
        _extract_artifacts(ip, exec_id, stderr)

        combined = (stdout or "") + "\n" + (stderr or "")
        # hydrassh/hydraftp already run creds-import-hydra; skip duplicate recon block
        if RECON_CREDS_BANNER not in combined:
            cred_results = import_hydra(combined, ip=ip, execution_id=exec_id)
            emit_import_results(cred_results)

        return exec_id

    except Exception as e:
        finish_execution(exec_id, status="failed", exit_code=None, stdout="", stderr=str(e)[-20000:])
        raise


def run_command_or_cache(
    ip: str,
    command: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    stream: bool = False,
    task_type: str = "manual",
):
    """
    If a successful execution exists for ip+command, return it without re-running.
    Otherwise run the command and store a new execution.

    Returns (exec_id, cached: bool).
    """
    command = canonicalize_probe_command((command or "").strip())
    if not ip:
        raise ValueError("ip required")
    if not command:
        raise ValueError("command required")

    cached = find_done_execution(ip, command)
    if cached:
        return int(cached["id"]), True

    exec_id = run_command(
        ip=ip,
        command=command,
        timeout_sec=timeout_sec,
        stream=stream,
        task_type=task_type,
    )
    return exec_id, False


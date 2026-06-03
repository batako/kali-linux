import sys
import os

from db import init_db
from db import show_hosts
from db import show_host
from db import show_tasks
from db import complete_task
from db import print_host_summary_json
from db import add_artifact
from db import creds_upsert
from db import list_ssh_creds
from db import get_ssh_last_user
from db import set_ssh_last_user
from db import list_executions
from db import get_execution
from db import list_artifacts
from db import delete_artifact
from creds import import_hydra_ssh
from creds import RECON_CREDS_BANNER
from creds import emit_import_results
import json

from scanner import network_scan
from scanner import host_scan
from executor import run_task
from executor import run_command
from executor import run_command_or_cache
from form_parse import format_exec_form_shell
from form_parse import parse_upload_form_html


def _print_execution_body(row):
    out = row["stdout"] or ""
    err = row["stderr"] or ""
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        if out:
            print("")
        print(err, end="" if err.endswith("\n") else "\n")


def main():
    if len(sys.argv) < 2:
        print("usage: recon.py <command>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "init":
        init_db()

    elif cmd == "net-scan":
        if len(sys.argv) < 3:
            print("usage: recon.py net-scan <cidr>")
            sys.exit(1)

        network_scan(sys.argv[2])

    elif cmd == "net-view":
        show_hosts()

    elif cmd == "host-scan":
        if len(sys.argv) < 4:
            print("usage: recon.py host-scan <ip> <quick|full>")
            sys.exit(1)

        host_scan(sys.argv[2], sys.argv[3])

    elif cmd == "host-view":
        if len(sys.argv) < 3:
            print("usage: recon.py host-view <ip>")
            sys.exit(1)

        show_host(sys.argv[2])

    elif cmd == "host-summary":
        if len(sys.argv) < 3:
            print("usage: recon.py host-summary <ip> [--json]")
            sys.exit(1)

        ip = sys.argv[2]
        # currently only JSON is supported (explicit flag for future extension)
        if len(sys.argv) >= 4 and sys.argv[3] != "--json":
            print("usage: recon.py host-summary <ip> [--json]")
            sys.exit(1)

        print_host_summary_json(ip)

    elif cmd == "task-view":
        show_tasks()

    elif cmd == "task-done":
        if len(sys.argv) < 3:
            print("usage: recon.py task-done <id>")
            sys.exit(1)

        complete_task(sys.argv[2])

    elif cmd == "task-run":
        if len(sys.argv) < 3:
            print("usage: recon.py task-run <id>")
            sys.exit(1)

        from db import get_task_by_id
        task = get_task_by_id(int(sys.argv[2]))
        if not task:
            print("task not found")
            sys.exit(1)

        if int(task["requires_human_ok"] or 0) == 1:
            print("blocked: requires human approval (set requires_human_ok=0 to allow)")
            sys.exit(2)

        exec_id = run_task(int(sys.argv[2]))
        print(f"executed: exec_id={exec_id}")

    elif cmd == "exec-run":
        # run arbitrary command and store outputs for a host (THM helper)
        # usage: exec-run [-s] <ip> <command...>
        silence = False
        args = sys.argv[2:]

        if args and args[0] == "-s":
            silence = True
            args = args[1:]

        if len(args) < 2:
            print("usage: recon.py exec-run [-s] <ip> <command...>")
            sys.exit(1)

        ip = args[0]
        command = " ".join(args[1:])
        # stream=True: show output while the command runs (PTY for hydra etc.)
        exec_id = run_command(ip=ip, command=command, stream=not silence)

        if not silence:
            print("")
            print("-----")
        print(f"executed: exec_id={exec_id}")

    elif cmd == "exec-cache":
        # cache-or-run: reuse done execution for same ip+command, else execute
        # usage: exec-cache [-s] <ip> <command...>
        silence = False
        args = sys.argv[2:]

        if args and args[0] == "-s":
            silence = True
            args = args[1:]

        if len(args) < 2:
            print("usage: recon.py exec-cache [-s] <ip> <command...>")
            sys.exit(1)

        ip = args[0]
        command = " ".join(args[1:])
        exec_id, cached = run_command_or_cache(
            ip=ip,
            command=command,
            stream=not silence,
        )

        if cached:
            if not silence:
                row = get_execution(exec_id)
                if row:
                    _print_execution_body(row)
                print("")
                print("-----")
            print(f"executed: exec_id={exec_id} (cached)")
        else:
            if not silence:
                print("")
                print("-----")
            print(f"executed: exec_id={exec_id}")

    elif cmd == "exec-list":
        # list recent executions; default = target IP ($IP), -l = all hosts
        args = sys.argv[2:]
        list_all = False

        if args and args[0] in ("-l", "--all"):
            list_all = True
            args = args[1:]

        if args:
            ip = args[0]
        elif list_all:
            ip = None
        else:
            ip = os.environ.get("IP")
            if not ip:
                print("usage: recon.py exec-list [-l] [ip]")
                print("hint: target-set <ip>  or  exec-list -l  for all hosts")
                sys.exit(1)

        rows = list_executions(ip=ip, limit=50)

        print("")
        print("EXEC_ID\tIP\tSTATUS\tEXIT\tENDED_AT\tCOMMAND")
        for r in rows:
            ended = r["ended_at"] or "-"
            code = r["exit_code"] if r["exit_code"] is not None else "-"
            cmd_s = (r["command"] or "").replace("\n", " ")
            if len(cmd_s) > 120:
                cmd_s = cmd_s[:117] + "..."
            print(f"{r['id']}\t{r['ip']}\t{r['status']}\t{code}\t{ended}\t{cmd_s}")

    elif cmd == "exec-view":
        # view a single execution outputs
        if len(sys.argv) < 3:
            print("usage: recon.py exec-view <exec_id> [--tail N]")
            sys.exit(1)

        exec_id = int(sys.argv[2])
        tail_n = None
        if len(sys.argv) >= 5 and sys.argv[3] == "--tail":
            tail_n = int(sys.argv[4])

        row = get_execution(exec_id)
        if not row:
            print("execution not found")
            sys.exit(1)

        print("")
        print(f"EXEC_ID: {row['id']}")
        print(f"IP: {row['ip']}")
        print(f"STATUS: {row['status']}  EXIT: {row['exit_code']}")
        print(f"STARTED: {row['started_at']}  ENDED: {row['ended_at']}")
        print("")
        print("COMMAND:")
        print(row["command"] or "")
        print("")

        def _tail(s: str):
            if s is None:
                return ""
            if tail_n is None:
                return s
            lines = s.splitlines()
            return "\n".join(lines[-tail_n:])

        print("STDOUT:")
        print(_tail(row["stdout"] or ""))
        print("")
        print("STDERR:")
        print(_tail(row["stderr"] or ""))

    elif cmd == "exec-form":
        # parse upload form fields from exec-view stdout (e.g. curl panel page)
        if len(sys.argv) < 3:
            print("usage: recon.py exec-form <exec_id> [--shell]")
            sys.exit(1)

        exec_id = int(sys.argv[2])
        shell_mode = len(sys.argv) >= 4 and sys.argv[3] == "--shell"

        row = get_execution(exec_id)
        if not row:
            print("execution not found")
            sys.exit(1)

        parsed = parse_upload_form_html(row["stdout"] or "", row["command"] or "")
        if not parsed:
            print("no upload form found in execution stdout")
            sys.exit(1)

        if shell_mode:
            print(format_exec_form_shell(parsed), end="")
        else:
            print("")
            print(f"EXEC_ID: {exec_id}")
            print(f"url:   {parsed['url']}")
            print(f"field: {parsed['field']}")
            for item in parsed.get("extra") or []:
                print(f"extra: {item}")
            print("")
            print("upsh example:")
            args = [f"-f {parsed['field']}"]
            for item in parsed.get("extra") or []:
                args.append(f"-F {item}")
            args.append(parsed["url"])
            print("  upsh " + " ".join(args))

    elif cmd == "artifact-add":
        # manually register a finding so it shows up in host-summary / host-view
        if len(sys.argv) < 5:
            print("usage: recon.py artifact-add <ip> <kind> <value> [key]")
            sys.exit(1)

        ip = sys.argv[2]
        kind = sys.argv[3]
        value = sys.argv[4]
        key = sys.argv[5] if len(sys.argv) >= 6 else ""

        add_artifact(ip=ip, kind=kind, key=key, value=value, execution_id=None)
        print("ok")

    elif cmd == "creds-add":
        if len(sys.argv) < 5:
            print("usage: recon.py creds-add <ip> <username> <password>")
            sys.exit(1)

        ip = sys.argv[2]
        username = sys.argv[3]
        password = sys.argv[4]

        status = creds_upsert(ip=ip, username=username, password=password)
        print(status)

    elif cmd == "creds-list":
        args = sys.argv[2:]
        as_json = False
        if args and args[0] == "--json":
            as_json = True
            args = args[1:]

        ip = args[0] if args else None
        if not ip:
            print("usage: recon.py creds-list [--json] <ip>")
            sys.exit(1)

        rows = list_ssh_creds(ip)
        if as_json:
            # omit passwords in json? user needs them for ssh - include
            print(json.dumps(rows))
        else:
            if not rows:
                print(f"(no ssh creds for {ip})")
            else:
                for r in rows:
                    print(f"{r['username']}\t{r['password']}")

    elif cmd == "creds-import-hydra":
        if len(sys.argv) < 3:
            print("usage: recon.py creds-import-hydra <ip> [--file path]")
            sys.exit(1)

        ip = sys.argv[2]
        path = None
        args = sys.argv[3:]
        i = 0
        while i < len(args):
            if args[i] == "--file" and i + 1 < len(args):
                path = args[i + 1]
                i += 2
            else:
                i += 1

        if path:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        else:
            text = sys.stdin.read()

        results = import_hydra_ssh(text, ip=ip)
        emit_import_results(results)
        if not results:
            print("", file=sys.stdout)
            print(RECON_CREDS_BANNER, file=sys.stdout)
            print("[i] no hydra ssh credentials found in output", file=sys.stdout)

    elif cmd == "ssh-last-get":
        if len(sys.argv) < 3:
            print("usage: recon.py ssh-last-get <ip>")
            sys.exit(1)
        last = get_ssh_last_user(sys.argv[2])
        if last:
            print(last)

    elif cmd == "ssh-last-set":
        if len(sys.argv) < 4:
            print("usage: recon.py ssh-last-set <ip> <username>")
            sys.exit(1)
        set_ssh_last_user(sys.argv[2], sys.argv[3])
        print("ok")

    elif cmd == "artifact-list":
        ip = sys.argv[2] if len(sys.argv) >= 3 else None
        rows = list_artifacts(ip=ip, limit=200)

        print("")
        print("ART_ID\tIP\tKIND\tKEY\tVALUE")
        for r in rows:
            key = r["key"] or ""
            val = (r["value"] or "").replace("\n", " ")
            if len(val) > 120:
                val = val[:117] + "..."
            print(f"{r['id']}\t{r['ip']}\t{r['kind']}\t{key}\t{val}")

    elif cmd == "artifact-del":
        if len(sys.argv) < 3:
            print("usage: recon.py artifact-del <artifact_id>")
            sys.exit(1)

        deleted = delete_artifact(int(sys.argv[2]))
        if deleted:
            print("ok")
        else:
            print("not found")
            sys.exit(1)

    elif cmd == "host-run-next":
        # run next pending task for host (highest priority first)
        if len(sys.argv) < 3:
            print("usage: recon.py host-run-next <ip>")
            sys.exit(1)

        from db import claim_next_task_for_host, get_task_by_id, set_task_status
        task_id = claim_next_task_for_host(sys.argv[2])
        if not task_id:
            print("no pending tasks")
            sys.exit(0)

        task = get_task_by_id(int(task_id))
        if int(task["requires_human_ok"] or 0) == 1:
            # release back to pending for manual run
            set_task_status(int(task_id), "pending")
            print("blocked: next task requires human approval")
            sys.exit(2)

        exec_id = run_task(int(task_id))
        print(f"executed: task_id={task_id} exec_id={exec_id}")

    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()

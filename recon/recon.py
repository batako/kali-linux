import sys
import os
from pathlib import Path

from db import init_db
from db import show_hosts
from db import show_host
from db import show_scan_report
from db import reset_host_scan_data
from db import show_tasks
from db import complete_task
from db import print_host_summary_json
from db import add_artifact
from db import creds_delete
from db import creds_upsert
from db import list_ssh_creds
from db import get_ssh_last_user
from db import set_ssh_last_user
from db import list_executions
from db import get_execution
from db import list_artifacts
from db import delete_artifact
from creds import import_hydra
from creds import RECON_CREDS_BANNER
from creds import emit_import_results
import json

from scanner import network_scan
from scan_run import run_basic_scan
from scan_run import run_scan
from scan_run import PROFILE_FULL
from scan_run import clamp_full_jobs
from scan_run import DEFAULT_FULL_JOBS
from scout_run import run_scout
from scout_run import show_scout_ports
from scout_run import show_scout_report
from scout_run import show_scout_report_exploits
from scout_run import show_scout_status
from scout_exploit import run_exploit_phase
from scout_run import is_dirs_path_arg
from scout_run import DEFAULT_GB_THREADS
from scout_run import DEFAULT_GB_WORDLIST
from scout_run import DIRS_EXTENSION_WORDLIST
from executor import run_task
from executor import run_command
from executor import run_command_or_cache
from form_parse import format_exec_form_shell
from form_parse import parse_upload_form_html
from wordlists.cli import run_wordlist_cli

SCOUT_REPORT_FLAGS = ("-r", "--report")
SCOUT_REPORT_PORTS_FLAGS = ("-rp", "--report-ports")
SCOUT_REPORT_EXPLOITS_FLAGS = ("-re", "--report-exploits")
SCOUT_SEARCH_EXPLOITS_FLAGS = ("-se", "--search-exploits")
SCOUT_LEGACY_FLAG_MAP = {
    "-p": "--report-ports",
    "--ports": "--report-ports",
    "-e": "--search-exploits",
    "--exploit": "--search-exploits",
}


def _scout_legacy_flag(flag: str) -> str:
    new = SCOUT_LEGACY_FLAG_MAP.get(flag)
    if new:
        print(f"[!] {flag} is deprecated — use {new}", file=sys.stderr)
        return new
    return flag


def _scout_parse_tail(
    args: list[str],
    *,
    usage: str,
    allow_search: bool = False,
    allow_force: bool = False,
    allow_dry_run: bool = False,
    ignore_force: bool = False,
) -> tuple[str, bool, bool, bool]:
    ip = None
    search_exploits = False
    force_exploit = False
    dry_run = False
    rest = list(args)
    while rest:
        a = rest[0]
        if a == "--force":
            if ignore_force:
                print(
                    "[!] --force ignored — scout -se always refreshes exploit cache",
                    file=sys.stderr,
                )
                rest = rest[1:]
            elif allow_force:
                force_exploit = True
                rest = rest[1:]
            else:
                print(f"unknown option: {a}")
                print(usage)
                sys.exit(1)
        elif allow_search and a in SCOUT_SEARCH_EXPLOITS_FLAGS:
            search_exploits = True
            rest = rest[1:]
        elif allow_dry_run and a in ("-n", "--dry-run"):
            dry_run = True
            rest = rest[1:]
        elif a.startswith("-"):
            print(f"unknown option: {a}")
            print(usage)
            sys.exit(1)
        else:
            ip = a
            rest = rest[1:]
    if not ip:
        ip = os.environ.get("IP")
    if not ip:
        print(usage)
        sys.exit(1)
    return ip, search_exploits, force_exploit, dry_run


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

    elif cmd == "scan":
        args = sys.argv[2:]
        ip = None
        profile = "basic"
        report = False
        force = False
        dry_run = False
        quiet_ports = False
        jobs = DEFAULT_FULL_JOBS

        while args:
            a = args[0]
            if a in ("-f", "--full"):
                profile = PROFILE_FULL
                args = args[1:]
            elif a in ("-r", "--report"):
                report = True
                args = args[1:]
            elif a == "--force":
                force = True
                args = args[1:]
            elif a in ("-n", "--dry-run"):
                dry_run = True
                args = args[1:]
            elif a in ("-q", "--quiet"):
                quiet_ports = True
                args = args[1:]
            elif a in ("-j", "--jobs"):
                if len(args) < 2:
                    print("usage: recon.py scan --full <ip> -j <N>")
                    sys.exit(1)
                jobs = clamp_full_jobs(int(args[1]))
                args = args[2:]
            elif a.startswith("-j") and len(a) > 2 and a[2:].isdigit():
                jobs = clamp_full_jobs(int(a[2:]))
                args = args[1:]
            elif a.startswith("-"):
                print(f"unknown option: {a}")
                print(
                    "usage: recon.py scan [options] <ip>"
                    "  (-f|--full, -r|--report, --force, -n, -q, -j N)"
                )
                sys.exit(1)
            elif a in ("full", "report"):
                print(f"[-] use scan -f or scan --{a} (positional '{a}' removed)")
                sys.exit(1)
            else:
                ip = a
                args = args[1:]

        if not ip:
            ip = os.environ.get("IP")
        if not ip:
            print(
                "usage: recon.py scan [options] <ip>"
                "  (-f|--full, -r|--report, --force, -n, -q, -j N)"
            )
            sys.exit(1)

        if report and profile == PROFILE_FULL:
            print("[-] use either --full/-f or --report/-r, not both")
            sys.exit(1)
        if report:
            if force or dry_run or quiet_ports or jobs != DEFAULT_FULL_JOBS:
                print("[-] --report does not take --force, -n, -q, or -j")
                sys.exit(1)
            show_scan_report(ip)
            sys.exit(0)

        if profile != PROFILE_FULL and jobs != DEFAULT_FULL_JOBS:
            print("[-] -j is only for scan --full")
            sys.exit(1)

        rc = run_scan(
            ip,
            profile=profile,
            force=force,
            dry_run=dry_run,
            quiet_ports=quiet_ports,
            jobs=jobs,
        )
        sys.exit(0 if rc == 0 else 1)

    elif cmd == "scout":
        args = sys.argv[2:]

        # legacy: scout status → --status; scout status --watch → --wait-dirs
        if args and args[0] == "status":
            args = args[1:]
            if args and args[0] in ("--watch", "-W", "--wait-dirs", "-ws", "-wd"):
                flag = args[0]
                if flag in ("--watch", "-W", "-wd"):
                    flag = "--wait-dirs"
                elif flag == "-ws":
                    flag = "--wait-dirs"
                args = [flag, *args[1:]]
            else:
                args = ["--status", *args]

        if args:
            args[0] = _scout_legacy_flag(args[0])

        if args and args[0] in SCOUT_REPORT_PORTS_FLAGS:
            ip, _, _, _ = _scout_parse_tail(
                args[1:],
                usage="usage: recon.py scout -rp|--report-ports [ip]",
            )
            rc = show_scout_ports(ip)
            sys.exit(0 if rc == 0 else 1)

        if args and args[0] in SCOUT_REPORT_EXPLOITS_FLAGS:
            ip, _, _, _ = _scout_parse_tail(
                args[1:],
                usage="usage: recon.py scout -re|--report-exploits [ip]",
            )
            rc = show_scout_report_exploits(ip)
            sys.exit(0 if rc == 0 else 1)

        if args and args[0] in SCOUT_SEARCH_EXPLOITS_FLAGS:
            ip, _, _, dry_run = _scout_parse_tail(
                args[1:],
                usage="usage: recon.py scout -se|--search-exploits [-n] [ip]",
                allow_dry_run=True,
                ignore_force=True,
            )
            rc = run_exploit_phase(ip, dry_run=dry_run, force=not dry_run)
            sys.exit(0 if rc == 0 else 1)

        if args and args[0] in SCOUT_REPORT_FLAGS:
            ip, search_exploits, _, _ = _scout_parse_tail(
                args[1:],
                usage="usage: recon.py scout -r|--report [-se] [ip]",
                allow_search=True,
                ignore_force=True,
            )
            if search_exploits:
                erc = run_exploit_phase(ip, force=True)
                if erc != 0:
                    sys.exit(erc)
            rc = show_scout_report(ip)
            sys.exit(0 if rc == 0 else 1)

        ip = None
        force_scan = False
        force_dirs = False
        dry_run = False
        quiet_ports = False
        dirs_only = False
        search_exploits_only = False
        force_exploit = False
        status_mode = False
        wait_dirs_mode = False
        wait_dirs_interval_sec = 2.0
        wordlist = os.environ.get("GB_WORDLIST") or DEFAULT_GB_WORDLIST
        wordlist_from_flag = False
        threads = DEFAULT_GB_THREADS
        if os.environ.get("GB_THREADS"):
            try:
                threads = int(os.environ["GB_THREADS"])
            except ValueError:
                pass
        extensions = None
        dirs_urls = []

        while args:
            a = args[0]
            if a in ("-s", "--status"):
                if wait_dirs_mode:
                    print("[-] use -s or -ws, not both")
                    sys.exit(1)
                status_mode = True
                args = args[1:]
            elif a in ("--wait-dirs", "-ws", "-wd"):
                if status_mode:
                    print("[-] use -s or -ws, not both")
                    sys.exit(1)
                wait_dirs_mode = True
                args = args[1:]
                if args and not args[0].startswith("-"):
                    try:
                        wait_dirs_interval_sec = float(args[0])
                        args = args[1:]
                    except ValueError:
                        pass
            elif a in ("--watch", "-W"):
                print("[-] use -ws (or --wait-dirs), not --watch")
                sys.exit(1)
            elif a in ("-d", "--dirs"):
                dirs_only = True
                args = args[1:]
                if args and is_dirs_path_arg(args[0]):
                    dirs_urls.append(args[0])
                    args = args[1:]
            elif a in SCOUT_SEARCH_EXPLOITS_FLAGS:
                search_exploits_only = True
                args = args[1:]
            elif a in ("-e", "--exploit"):
                print("[!] -e is deprecated — use -se", file=sys.stderr)
                search_exploits_only = True
                args = args[1:]
            elif a == "--force":
                force_scan = True
                force_dirs = True
                force_exploit = True
                args = args[1:]
            elif a in ("-n", "--dry-run"):
                dry_run = True
                args = args[1:]
            elif a in ("-q", "--quiet"):
                quiet_ports = True
                args = args[1:]
            elif a in ("-w", "--wordlist"):
                if len(args) < 2:
                    print("usage: recon.py scout --dirs -w <wordlist> [ip|url]")
                    sys.exit(1)
                wordlist = args[1]
                wordlist_from_flag = True
                args = args[2:]
            elif a in ("-t", "--threads"):
                if len(args) < 2:
                    print("usage: recon.py scout --dirs -t <N> [ip|url]")
                    sys.exit(1)
                threads = int(args[1])
                args = args[2:]
            elif a in ("-x", "--ext", "--extensions"):
                if len(args) < 2:
                    print("usage: recon.py scout --dirs -x <ext> [ip|url]")
                    sys.exit(1)
                extensions = args[1]
                args = args[2:]
            elif a.startswith("http://") or a.startswith("https://"):
                dirs_urls.append(a)
                args = args[1:]
            elif dirs_only and is_dirs_path_arg(a):
                dirs_urls.append(a)
                args = args[1:]
            elif a.startswith("-"):
                print(f"unknown option: {a}")
                print(
                    "usage: recon.py scout [options] [ip|path|url...]"
                    "  (-r|-rp|-re|-se, -s, -ws, -d, ...)"
                )
                sys.exit(1)
            else:
                ip = a
                args = args[1:]

        if not ip:
            ip = os.environ.get("IP")
        if not ip:
            print(
                "usage: recon.py scout [options] <ip>"
                "  (-r|-rp|-re|-se, -s, -ws, -d, ...)"
            )
            sys.exit(1)

        if search_exploits_only:
            if status_mode or wait_dirs_mode or dirs_only:
                print("[-] -se does not combine with -s, -ws, or -d")
                sys.exit(1)
            rc = run_exploit_phase(ip, dry_run=dry_run, force=not dry_run)
            sys.exit(0 if rc == 0 else 1)

        if status_mode or wait_dirs_mode:
            if dirs_only or search_exploits_only or force_scan or force_dirs or dry_run or quiet_ports:
                print("[-] -s/-ws does not take -d, -se, --force, -n, or -q")
                sys.exit(1)
            if dirs_urls or extensions is not None:
                print("[-] --status/--wait-dirs does not take paths, -w, -t, or -x")
                sys.exit(1)
            rc = show_scout_status(
                ip,
                wait_dirs=wait_dirs_mode,
                interval_sec=wait_dirs_interval_sec,
            )
            sys.exit(0 if rc == 0 else 1)

        if extensions is not None and not wordlist_from_flag:
            if Path(DIRS_EXTENSION_WORDLIST).is_file():
                wordlist = DIRS_EXTENSION_WORDLIST
            else:
                print(
                    f"[!] -x without -w: {DIRS_EXTENSION_WORDLIST} not found; "
                    f"using {wordlist}",
                    file=sys.stderr,
                )
            print(
                "[i] -x uses basename+extension (e.g. backup.bak); "
                "compound names need -w with a larger list",
                file=sys.stderr,
            )

        rc = run_scout(
            ip,
            force_scan=force_scan,
            force_dirs=force_dirs,
            dry_run=dry_run,
            quiet_ports=quiet_ports,
            dirs_only=dirs_only,
            dirs_urls=dirs_urls or None,
            wordlist=wordlist,
            threads=threads,
            extensions=extensions,
        )
        sys.exit(0 if rc == 0 else 1)

    elif cmd == "host-reset":
        ip = sys.argv[2] if len(sys.argv) >= 3 else os.environ.get("IP")
        if not ip:
            print("usage: recon.py host-reset <ip>")
            sys.exit(1)
        counts = reset_host_scan_data(ip)
        print(f"[+] host-reset {ip}")
        for table, n in counts.items():
            print(f"    {table}: {n} row(s) deleted")
        print("[i] re-test: scout  /  scan  /  scan -f")

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

    elif cmd == "creds-rm":
        if len(sys.argv) < 3:
            print("usage: recon.py creds-rm <ip> [username]")
            sys.exit(1)

        ip = sys.argv[2]
        username = sys.argv[3] if len(sys.argv) > 3 else None
        n = creds_delete(ip=ip, username=username)
        if username:
            print(f"removed {n} row(s) for {username}@{ip}")
        else:
            print(f"removed {n} row(s) for {ip}")

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

        results = import_hydra(text, ip=ip)
        emit_import_results(results)
        if not results:
            print("", file=sys.stdout)
            print(RECON_CREDS_BANNER, file=sys.stdout)
            print("[i] no hydra credentials found in output", file=sys.stdout)

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
        # list artifacts; default = target IP ($IP), -l = all hosts
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
                print("usage: recon.py artifact-list [-l] [ip]")
                print("hint: target-set <ip>  or  artifact-list -l  for all hosts")
                sys.exit(1)

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

    elif cmd == "wordlist":
        sys.exit(run_wordlist_cli(sys.argv[2:]))

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

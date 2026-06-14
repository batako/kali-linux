"""Task plan (scout enqueue) and strike (run pending auth tasks)."""

from __future__ import annotations

import os
import re
import sys

from case_scope import case_name_from_env
from case_scope import recon_scope_ips
from db import finish_task
from db import get_execution
from db import list_tasks
from db import mark_task_running
from db import reset_task_pending
from db import upsert_task
from executor import run_command
from task_auth import resolve_auth_task_plans

_HYDRA_HIT_RE = re.compile(
    r"\[\d+\]\[(?:ssh|ftp|postgres|mysql)\].*?\blogin:\s*(\S+)\s+password:\s*(.*)",
    re.IGNORECASE | re.DOTALL,
)
_HYDRA_VALID_FOUND_RE = re.compile(
    r"(\d+)\s+valid\s+password\s+found",
    re.IGNORECASE,
)

AUTH_TASK_TYPES = ("auth-ftp-anon", "auth-pg-quick", "auth-my-quick", "auth-ssh-quick")

# Per-task hydra timeouts (seconds)
TASK_TIMEOUTS = {
    "auth-ftp-anon": 120,
    "auth-pg-quick": 180,
    "auth-my-quick": 180,
    "auth-ssh-quick": 120,
}


def _scout_no_plan() -> bool:
    if os.environ.get("SCOUT_NO_PLAN", "").strip().lower() in ("1", "true", "yes"):
        return True
    return False


def _format_port_row(port: int, service: str) -> str:
    svc = service or "-"
    return f"{port}/tcp  service={svc}"


def _hydra_valid_password_count(text: str) -> int | None:
    matches = _HYDRA_VALID_FOUND_RE.findall(text or "")
    if not matches:
        return None
    return int(matches[-1])


def _detect_outcome(exec_row) -> tuple[str, str]:
    status = (exec_row["status"] or "").lower()
    exit_code = exec_row["exit_code"]
    combined = (exec_row["stdout"] or "") + "\n" + (exec_row["stderr"] or "")

    if status == "timeout":
        return "error", "timeout"

    match = _HYDRA_HIT_RE.search(combined)
    if match:
        user, passwd = match.group(1), (match.group(2) or "").strip()
        return "hit", f"{user}:{passwd}"

    valid_count = _hydra_valid_password_count(combined)
    if valid_count is not None:
        if valid_count > 0:
            return "hit", f"{valid_count} valid password(s)"
        return "miss", "0 valid passwords"

    if status == "failed":
        return "error", f"exit={exit_code}"

    return "miss", "no credentials found"


def run_task_plan_phase(ip: str, *, dry_run: bool = False) -> int:
    if _scout_no_plan():
        print("[*] phase 2.5: task-plan skipped (SCOUT_NO_PLAN)")
        return 0

    plans = resolve_auth_task_plans(ip)
    print("")
    print("[*] phase 2.5: task-plan (auth-quick enqueue)")

    if not plans:
        print("[*] no auth-quick tasks for open ports")
        return 0

    case = case_name_from_env()
    created = updated = skipped = 0

    for plan in plans:
        print(f"[*] {_format_port_row(plan.port, plan.service)}")
        print(f"    -> {plan.task_type}")

        if dry_run:
            print(f"    $ {plan.command}")
            continue

        action, task_id = upsert_task(
            ip=plan.ip,
            port=plan.port,
            service=plan.service,
            task_type=plan.task_type,
            command=plan.command,
            case_name=case,
            source="scout-plan",
            meta=plan.meta,
        )
        if action == "created":
            created += 1
            print(f"    -> task {task_id} (new)")
        elif action == "updated":
            updated += 1
            print(f"    -> task {task_id} (updated)")
        else:
            skipped += 1
            print(f"    -> task {task_id} (skipped — done or running)")

    if not dry_run:
        print("")
        print(
            f"[*] task-plan: {created} new, {updated} updated, {skipped} skipped"
            " — run: strike"
        )
    return 0


def _scope_ips(ip: str) -> list[str]:
    return recon_scope_ips(ip) or [ip]


def format_task_list_lines(ip: str, *, all_case: bool = False) -> list[str]:
    case = case_name_from_env()
    if all_case and case:
        rows = list_tasks(case_name=case, limit=200)
    elif ip:
        rows = list_tasks(scope_ips=_scope_ips(ip), case_name=case, limit=200)
    else:
        rows = list_tasks(case_name=case, limit=200) if case else []

    if not rows:
        return ["(none — run scout or scout --plan)"]

    lines: list[str] = []
    for row in rows:
        tid = row["id"]
        port = row["port"]
        task_type = row["task_type"] or "-"
        status = row["status"] or "-"
        outcome = row["outcome"] or "-"
        summary = (row["result_summary"] or "").strip()
        hint = f"  {summary}" if summary else ""
        ev = row["execution_id"]
        ev_s = f"  ev={ev}" if ev else ""
        lines.append(
            f"  {tid}  {row['ip']}:{port}  {task_type}  {status}/{outcome}{ev_s}{hint}"
        )
    return lines


def format_task_report_lines(ip: str) -> list[str]:
    case = case_name_from_env()
    rows = list_tasks(scope_ips=_scope_ips(ip), case_name=case, limit=50)
    if not rows:
        return ["(none — scout enqueues auth-quick tasks)"]
    return format_task_list_lines(ip)


def run_strike(
    ip: str,
    *,
    dry_run: bool = False,
    force: bool = False,
    task_type_prefix: str = "auth-",
) -> int:
    case = case_name_from_env()
    scope = _scope_ips(ip)

    # Recover tasks left "running" after a crash (e.g. sqlite lock on finish_task).
    for row in list_tasks(
        scope_ips=scope,
        case_name=case,
        status="running",
        task_type_prefix=task_type_prefix or None,
        limit=100,
    ):
        reset_task_pending(int(row["id"]))

    pending = list_tasks(
        scope_ips=scope,
        case_name=case,
        status="pending",
        task_type_prefix=task_type_prefix or None,
        limit=100,
    )

    if force:
        done_rows = list_tasks(
            scope_ips=scope,
            case_name=case,
            status="done",
            task_type_prefix=task_type_prefix or None,
            limit=100,
        )
        for row in done_rows:
            reset_task_pending(int(row["id"]))
        pending = list_tasks(
            scope_ips=scope,
            case_name=case,
            status="pending",
            task_type_prefix=task_type_prefix or None,
            limit=100,
        )

    if not pending:
        print("[*] strike: no pending tasks")
        print("[i] run scout first, or: strike --force")
        return 0

    print("========================")
    if case:
        print(f"[STRIKE] case {case}  target {ip}")
    else:
        print(f"[STRIKE] {ip}")
    print("========================")
    print(f"[*] {len(pending)} pending task(s)")
    print("")

    rc = 0
    for row in pending:
        task_id = int(row["id"])
        task_type = row["task_type"] or "manual"
        command = (row["command"] or "").strip()
        target_ip = row["ip"]
        port = row["port"]

        print(f"[*] task {task_id}  {target_ip}:{port}  {task_type}")
        print(f"    $ {command}")

        if dry_run:
            print("")
            continue

        mark_task_running(task_id)
        timeout = TASK_TIMEOUTS.get(task_type, 300)
        try:
            exec_id = run_command(
                ip=target_ip,
                command=command,
                timeout_sec=timeout,
                task_id=task_id,
                task_type=task_type,
                stream=True,
            )
        except Exception as exc:
            finish_task(
                task_id,
                status="failed",
                outcome="error",
                result_summary=str(exc)[:200],
            )
            print(f"[-] task {task_id} failed: {exc}")
            rc = 1
            print("")
            continue

        exec_row = get_execution(exec_id)
        outcome, summary = _detect_outcome(exec_row)
        task_status = "done" if outcome in ("hit", "miss") else "failed"
        finish_task(
            task_id,
            status=task_status,
            outcome=outcome,
            execution_id=int(exec_id),
            result_summary=summary,
        )
        print(f"[+] task {task_id}  {task_status}/{outcome}  ev {exec_id}  {summary}")
        print("")

    return rc


def show_task_list(ip: str, *, all_case: bool = False) -> int:
    case = case_name_from_env()
    print("========================")
    if case:
        label = "all IPs" if all_case else f"target {ip}"
        print(f"[TASKS] case {case}  {label}")
    else:
        print(f"[TASKS] {ip or '(all)'}")
    print("========================")
    for line in format_task_list_lines(ip, all_case=all_case):
        print(line)
    print("")
    print("[i] run pending: strike  |  list: strike -l  |  force redo: strike --force")
    return 0

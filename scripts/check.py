from __future__ import annotations

import contextlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Optional

API = "https://bsbord.com/v1"
TOKEN = os.environ.get("BSCHEKER_TOKEN", "")
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ROOT_LIST = "whitelist"
PAUSE = 1.2
RETRIES = 3


def call(method: str, path: str, body: Optional[dict] = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = str(uuid.uuid4())
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)


def call_retrying(method: str, path: str, body: Optional[dict] = None) -> dict:
    for attempt in range(RETRIES):
        try:
            return call(method, path, body)
        except urllib.error.HTTPError as exc:
            payload = {}
            with contextlib.suppress(Exception):
                payload = json.load(exc)
            error = payload.get("error", {})
            code = error.get("code", str(exc.code))
            if exc.code in (429, 503) or code in ("busy", "request_in_progress"):
                delay = error.get("details", {}).get("retry_after") or 60
                if attempt == RETRIES - 1:
                    raise SystemExit(f"{code}: попытки исчерпаны") from exc
                print(f"  {code}, повтор через {delay} с", file=sys.stderr)
                time.sleep(delay)
                continue
            raise SystemExit(f"{code}: {error.get('message', exc.reason)}") from exc
    raise SystemExit("недостижимо")


def probe_body(domain: str, operators: list) -> dict:
    return {
        "target": domain,
        "operators": operators,
        "probes": {"icmp": False, "tcp": True, "sni": True},
        "sni_hosts": [domain],
        "dpi": "on",
    }


def expand(name: str, seen: Optional[set] = None) -> dict:
    """Точные домены (full:) и файлы, в которых они лежат."""
    seen = seen if seen is not None else set()
    found = defaultdict(set)
    if name in seen:
        return found
    seen.add(name)
    path = DATA_DIR / name
    if not path.is_file():
        raise SystemExit(f"нет списка {name}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("include:"):
            for domain, files in expand(line[len("include:"):].strip(), seen).items():
                found[domain] |= files
            continue
        value = line.split("@", 1)[0].strip()
        if not value.startswith("full:"):
            continue
        domain = value[len("full:"):].strip()
        if domain:
            found[domain].add(name)
    return found


def drop(domains: dict) -> None:
    by_file = defaultdict(set)
    for domain, files in domains.items():
        for name in files:
            by_file[name].add(domain)

    for name, unwanted in sorted(by_file.items()):
        path = DATA_DIR / name
        kept, removed = [], 0
        for raw in path.read_text(encoding="utf-8").splitlines():
            value = raw.split("#", 1)[0].split("@", 1)[0].strip()
            if value.startswith("full:") and value[len("full:"):].strip() in unwanted:
                removed += 1
                continue
            kept.append(raw)
        if removed:
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")
            print(f"{name}: удалено {removed}")


def main() -> None:
    if not TOKEN:
        raise SystemExit("нет BSCHEKER_TOKEN")

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    dry_run = "--dry-run" in sys.argv[1:]

    domains = defaultdict(set)
    for name in args or [ROOT_LIST]:
        for domain, files in expand(name).items():
            domains[domain] |= files
    checks = sorted(domains)
    if not checks:
        raise SystemExit("нечего проверять")

    operators = [o["op_key"] for o in call_retrying("GET", "/v1/operators")["operators"]
                 if o["channel_state"] == "DPI_ON"]
    if not operators:
        raise SystemExit("нет операторов с включённым белым списком")

    sample = checks[0]
    preview = call_retrying("POST", "/v1/probe/preview", probe_body(sample, operators))
    each = preview.get("cost_credits", 0)
    total = each * len(checks)
    balance = call_retrying("GET", "/v1/account").get("balance_total", 0)
    print(f"операторов: {len(operators)}, доменов: {len(checks)}")
    print(f"цена: {each} кредитов за домен, всего {total}, на счету {balance}")
    if not dry_run and total > balance:
        raise SystemExit("не хватит баланса")
    if not dry_run and input("продолжить? [y/N] ").strip().lower() != "y":
        raise SystemExit("отменено")
    print()

    failed = {}
    for number, domain in enumerate(checks, 1):
        answer = call_retrying("POST", "/v1/probe", probe_body(domain, operators))
        if answer.get("outcome") == "no_dpi_on":
            raise SystemExit("все каналы без белого списка")

        by_operator = answer["by_target"].get(domain, {}).get("by_operator", {})
        bad = sorted(op for op, result in by_operator.items() if not result["ok"])
        mark = "OK  " if not bad else "FAIL"
        print(f"[{number}/{len(checks)}] {mark} {domain:34} {len(by_operator) - len(bad)}"
              f"/{len(by_operator)}" + (f"  нет: {', '.join(bad)}" if bad else ""))
        if bad:
            failed[domain] = domains[domain]
        time.sleep(PAUSE)

    print()
    if not failed:
        print("все домены доступны у всех операторов")
        return
    print(f"не везде в белых списках: {len(failed)}")
    for domain in sorted(failed):
        print(f"  {domain}")
    print()
    if dry_run:
        print("--dry-run, файлы не изменены")
        return
    drop(failed)


if __name__ == "__main__":
    main()

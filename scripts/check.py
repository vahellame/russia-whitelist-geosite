from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

API = "https://bsbord.com/v1"
TOKEN = os.environ.get("BSCHEKER_TOKEN", "")
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ROOT_LIST = "whitelist"
BATCH = 10
PAUSE = 1.2
RETRIES = 3


def call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = str(uuid.uuid4())
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)


def call_retrying(method: str, path: str, body: dict | None = None) -> dict:
    for attempt in range(RETRIES):
        try:
            return call(method, path, body)
        except urllib.error.HTTPError as exc:
            payload = {}
            try:
                payload = json.load(exc)
            except Exception:
                pass
            error = payload.get("error", {})
            code = error.get("code", str(exc.code))
            if exc.code in (429, 503) or code in ("busy", "request_in_progress"):
                delay = error.get("details", {}).get("retry_after") or 60
                if attempt == RETRIES - 1:
                    raise SystemExit(f"{code}: попытки исчерпаны")
                print(f"  {code}, повтор через {delay} с", file=sys.stderr)
                time.sleep(delay)
                continue
            raise SystemExit(f"{code}: {error.get('message', exc.reason)}")
    raise SystemExit("недостижимо")


def expand(name: str, seen: set[str] | None = None) -> list[tuple[str, str]]:
    """Возвращает только точные домены (full:), остальные правила пропускаются."""
    seen = seen if seen is not None else set()
    if name in seen:
        return []
    seen.add(name)
    path = DATA_DIR / name
    if not path.is_file():
        raise SystemExit(f"нет списка {name}")
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("include:"):
            out += expand(line[len("include:"):].strip(), seen)
            continue
        value = line.split("@", 1)[0].strip()
        if not value.startswith("full:"):
            continue
        domain = value[len("full:"):].strip()
        if domain:
            out.append((name, domain))
    return out


def main() -> None:
    if not TOKEN:
        raise SystemExit("нет BSCHEKER_TOKEN")

    lists = sys.argv[1:] or [ROOT_LIST]
    seen_domains: dict[str, str] = {}
    for name in lists:
        for category, domain in expand(name):
            seen_domains.setdefault(domain, category)
    checks = sorted(seen_domains.items())
    if not checks:
        raise SystemExit("нечего проверять")

    operators = [o["op_key"] for o in call_retrying("GET", "/v1/operators")["operators"]
                 if o["channel_state"] == "DPI_ON"]
    if not operators:
        raise SystemExit("нет операторов с включённым белым списком")
    print(f"операторов: {len(operators)}, доменов: {len(checks)}\n")

    failures = []
    for start in range(0, len(checks), BATCH):
        chunk = checks[start:start + BATCH]
        answer = call_retrying("POST", "/v1/probe", {
            "targets": [domain for domain, _ in chunk],
            "operators": operators,
            "probes": {"icmp": False, "tcp": True, "sni": True},
            "sni_hosts": [domain for domain, _ in chunk],
            "dpi": "on",
        })
        if answer.get("outcome") == "no_dpi_on":
            raise SystemExit("все каналы без белого списка")

        for domain, category in chunk:
            by_operator = answer["by_target"].get(domain, {}).get("by_operator", {})
            ok = sorted(op for op, r in by_operator.items() if r["ok"])
            bad = sorted(op for op, r in by_operator.items() if not r["ok"])
            mark = "OK  " if not bad else ("FAIL" if not ok else "PART")
            print(f"{mark} {category:20} {domain:34} {len(ok)}/{len(by_operator)}"
                  + (f"  нет: {', '.join(bad)}" if bad else ""))
            if bad:
                failures.append((category, domain, bad))
        time.sleep(PAUSE)

    print()
    if failures:
        print(f"проблемных доменов: {len(failures)}")
        for category, domain, bad in failures:
            print(f"  {category}/{domain}: {', '.join(bad)}")
    else:
        print("все домены доступны у всех операторов")


if __name__ == "__main__":
    main()

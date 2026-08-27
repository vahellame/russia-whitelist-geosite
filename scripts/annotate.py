from __future__ import annotations

import ipaddress
import json
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CACHE = BASE_DIR / ".cache" / "prefixes.json"
CACHE_TTL = 24 * 3600
WORKERS = 16

PROVIDERS: dict[str, tuple[int, ...]] = {
    "cdnvideo": (57363, 204720),
    "curator": (51115,),
    "ddosguard": (57724,),
    "edgecenter": (210756,),
    "ngenix": (34879,),
    "servicepipe": (201706,),
    "stormwall": (43298,),
}


def announced(asn: int) -> list[str]:
    request = urllib.request.Request(RIPESTAT.format(asn=asn),
                                     headers={"User-Agent": "annotate/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.load(response)
    out = []
    for item in payload.get("data", {}).get("prefixes", []):
        prefix = item.get("prefix", "")
        if ":" in prefix:
            continue
        try:
            ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        out.append(prefix)
    return out


def prefixes() -> dict[str, list[ipaddress.IPv4Network]]:
    if CACHE.is_file() and time.time() - CACHE.stat().st_mtime < CACHE_TTL:
        raw = json.loads(CACHE.read_text(encoding="utf-8"))
    else:
        raw = {}
        for name, asns in PROVIDERS.items():
            collected = []
            for asn in asns:
                collected += announced(asn)
                time.sleep(1)
            raw[name] = sorted(set(collected))
            print(f"{name}: {len(raw[name])} префиксов", file=sys.stderr)
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return {name: [ipaddress.ip_network(p) for p in nets] for name, nets in raw.items()}


def resolve(domain: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def owners(addresses: list[str], nets: dict[str, list]) -> list[str]:
    found = set()
    for address in addresses:
        ip = ipaddress.ip_address(address)
        for name, networks in nets.items():
            if any(ip in network for network in networks):
                found.add(name)
    return sorted(found)


def split_line(line: str) -> tuple[str, str, str]:
    body, sep, comment = line.partition("#")
    rule = body.rstrip()
    value = rule.split("@", 1)[0].strip()
    return value, rule, (sep + comment) if sep else ""


def main() -> None:
    files = sys.argv[1:] or sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    nets = prefixes()

    for name in files:
        path = DATA_DIR / name
        if not path.is_file():
            raise SystemExit(f"нет списка {name}")
        lines = path.read_text(encoding="utf-8").splitlines()

        targets = []
        for index, line in enumerate(lines):
            value, _, _ = split_line(line)
            if value.startswith("full:"):
                targets.append((index, value[len("full:"):]))
        if not targets:
            continue

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            resolved = list(pool.map(lambda t: resolve(t[1]), targets))

        changed = 0
        for (index, domain), addresses in zip(targets, resolved):
            value, rule, comment = split_line(lines[index])
            attrs = owners(addresses, nets)
            updated = value + ("".join(f" @{a}" for a in attrs))
            if updated != rule:
                lines[index] = updated + comment
                changed += 1
                mark = " ".join(f"@{a}" for a in attrs) or "без защиты"
                print(f"{name:22} {domain:34} {mark}")
            if not addresses:
                print(f"{name:22} {domain:34} не резолвится", file=sys.stderr)

        if changed:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"{name}: обновлено строк {changed}\n")


if __name__ == "__main__":
    main()

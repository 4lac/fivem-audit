#!/usr/bin/env python3
"""
fivem-audit: passive security audit for FiveM servers.

  remote  : reads ONLY what the server publishes (info.json, dynamic.json,
            players.json) and checks whether a few common admin ports answer.
  local   : static scan of a resources folder for backdoor patterns.

Use remote mode only on servers you own or are explicitly authorized to audit.
No exploitation, no event probing, no third-party dependencies.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

VERSION = "0.3.0"
HERE = os.path.dirname(os.path.abspath(__file__))
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
C = {"critical": "\033[1;95m", "high": "\033[1;91m", "medium": "\033[1;93m",
     "low": "\033[1;94m", "info": "\033[0;90m", "ok": "\033[1;92m",
     "head": "\033[1;96m", "dim": "\033[0;90m", "bold": "\033[1m", "end": "\033[0m",
     "orange": "\033[38;5;208m", "star": "\033[1;93m", "white": "\033[1;97m"}
URL_RE = re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})", re.IGNORECASE)
SCAN_EXT = (".lua", ".js")
SKIP_DIRS = {"node_modules", "stream", ".git"}
WIDTH = 70


@dataclass
class Finding:
    severity: str
    rule: str
    msg: str
    where: str = ""
    advice: str = ""
    snippet: str = ""


@dataclass
class Section:
    title: str
    findings: list = field(default_factory=list)


def col(key, text, on):
    return f"{C[key]}{text}{C['end']}" if on else text


def load_rules(path):
    with open(path, "r", encoding="utf-8") as fh:
        rules = json.load(fh)
    for p in rules["code_patterns"]:
        p["re"] = re.compile(p["regex"], re.IGNORECASE)
    return rules


# --------------------------------------------------------------------------- #
# Remote helpers
# --------------------------------------------------------------------------- #
def http_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": f"fivem-audit/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def port_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_remote(target, rules, timeout, meta):
    host, _, port = target.partition(":")
    port = int(port or 30120)
    base = f"http://{host}:{port}"
    sections = []

    try:
        info = http_json(f"{base}/info.json", timeout)
    except (urllib.error.URLError, OSError, ValueError) as e:
        s = Section("Connectivity")
        s.findings.append(Finding("info", "NET-000",
            f"info.json not reachable ({e}).",
            advice="Server is offline, behind a proxy, or on a non-default port."))
        return [s]

    vars_ = info.get("vars", {})
    resources = info.get("resources", [])
    dyn = {}
    try:
        dyn = http_json(f"{base}/dynamic.json", timeout)
    except (urllib.error.URLError, OSError, ValueError):
        pass

    meta.update({
        "name": vars_.get("sv_projectName") or vars_.get("sv_hostname", "?"),
        "players": f"{dyn.get('clients', '?')}/{dyn.get('sv_maxclients', vars_.get('sv_maxClients', '?'))}",
        "mapname": dyn.get("mapname", "?"),
        "gametype": dyn.get("gametype", "?"),
        "server": info.get("server", "?"),
        "gamebuild": vars_.get("sv_enforceGameBuild", "-"),
        "onesync": vars_.get("onesync_enabled", "-"),
        "locale": vars_.get("locale", "-"),
        "txadmin": vars_.get("txAdmin-version", "-"),
        "resources": len(resources),
    })

    # 1. exposure
    s = Section("Exposure")
    s.findings.append(Finding("info", "EXP-001",
        "Real endpoint answers HTTP directly.",
        base, "If players reach it via the public list, the real IP is exposed. "
        "Use sv_forceIndirectListing true + a proxy."))
    try:
        players = http_json(f"{base}/players.json", timeout)
        s.findings.append(Finding("info", "PLY-001",
            f"players.json is public: {len(players)} online with identifiers.",
            f"{base}/players.json",
            "Expected for FiveM; just know player identifiers are visible to anyone."))
    except (urllib.error.URLError, OSError, ValueError):
        pass
    sections.append(s)

    # 2. config vars
    s = Section("Configuration")
    for key, rule in rules["risky_vars"].items():
        val = vars_.get(key)
        if val is None and rule.get("missing"):
            s.findings.append(Finding(rule["severity"], "VAR-001", rule["msg"], key, rule["advice"]))
        elif val is not None and str(val).lower() in rule.get("bad", []):
            s.findings.append(Finding(rule["severity"], "VAR-001", rule["msg"], f"{key}={val}", rule["advice"]))
    custom = {k: v for k, v in vars_.items()
              if not k.startswith(("sv_", "banner_", "txAdmin", "onesync", "gamename", "locale", "tags"))}
    if custom:
        s.findings.append(Finding("info", "VAR-002",
            "Custom public vars (anyone can read these):",
            ", ".join(f"{k}={v}" for k, v in custom.items()),
            "Avoid putting anything sensitive in sets/setr vars; they are public."))
    sections.append(s)

    # 3. resources
    s = Section("Resources")
    total = len(resources)
    suspects = [r for r in resources
                if any(tok.lower() in r.lower() for tok in rules["leaked_pack_suspects"])]
    for res in resources:
        rule = rules["risky_resources"].get(res)
        if rule:
            s.findings.append(Finding(rule[0], "RES-001", rule[1], res, rule[2]))
    if suspects:
        s.findings.append(Finding("medium", "RES-002",
            f"{len(suspects)} resource name(s) match known leaked-pack keywords.",
            ", ".join(suspects),
            "Name match is a SUSPICION, not proof - it catches legit resources too "
            "(e.g. a vehicle folder like 'bufsxun' can look suspicious by name alone). "
            "Verify each one manually: open it and check the actual code, scan it with "
            "local mode, or look the name up before acting."))
    s.findings.append(Finding("info", "RES-003",
        f"{total} resources loaded ({len(suspects)} flagged by name).",
        advice="Run local mode on the resources folder for a real code-level check."))
    sections.append(s)

    # 4. ports
    s = Section("Open ports")
    for p in rules["common_ports"]:
        if p["port"] == port:
            continue
        if port_open(host, p["port"], timeout):
            s.findings.append(Finding(p["severity"], "PRT-001",
                f"Port {p['port']} OPEN - {p['name']}.", f"{host}:{p['port']}", p["advice"]))
        else:
            s.findings.append(Finding("ok", "PRT-000",
                f"Port {p['port']} closed - {p['name']}.", f"{host}:{p['port']}"))
    sections.append(s)
    return sections


# --------------------------------------------------------------------------- #
# Local scan
# --------------------------------------------------------------------------- #
def scan_file(path, rel, rules):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for no, line in enumerate(lines, 1):
        for p in rules["code_patterns"]:
            if p["re"].search(line):
                out.append(Finding(p["severity"], p["id"], p["msg"],
                                   f"{rel}:{no}", p["advice"], line.strip()[:140]))
    text = "".join(lines)
    network_calls = ("PerformHttpRequest", "http.request",            # Lua
                     "fetch(", "https.request", "https.get", "axios")  # JavaScript
    if any(call in text for call in network_calls):
        allow = set(rules["allowlist_domains"])
        for no, line in enumerate(lines, 1):
            for dom in URL_RE.findall(line):
                d = dom.lower()
                if not any(d == a or d.endswith("." + a) for a in allow):
                    out.append(Finding("high", "NET-001",
                        f"HTTP request + non-allowlisted domain: {d}",
                        f"{rel}:{no}",
                        "Verify the domain is yours and no player data is sent.",
                        line.strip()[:140]))
    return out


def scan_local(root, rules, meta):
    s = Section("Code scan")
    count = 0
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(SCAN_EXT):
                full = os.path.join(dp, name)
                s.findings += scan_file(full, os.path.relpath(full, root), rules)
                count += 1
    meta["files"] = count
    if count == 0:
        s.findings.append(Finding("info", "LOC-000",
            "No .lua/.js files found - NOTHING was scanned.",
            advice="This is not a clean result. Point local mode at the real resources folder."))
    return [s]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
BANNER = r"""
  ███████╗██╗██╗   ██╗███████╗███╗   ███╗
  ██╔════╝██║██║   ██║██╔════╝████╗ ████║
  █████╗  ██║██║   ██║█████╗  ██╔████╔██║
  ██╔══╝  ██║╚██╗ ██╔╝██╔══╝  ██║╚██╔╝██║
  ██║     ██║ ╚████╔╝ ███████╗██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═══╝  ╚══════╝╚═╝     ╚═╝"""

# Wanted level = the most serious finding, not the sum of all findings
STARS_FOR = {"critical": 5, "high": 3, "medium": 2, "low": 1}
TAGS = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO", "ok": "OK"}


def wanted_level(findings):
    return max((STARS_FOR.get(f.severity, 0) for f in findings), default=0)


def hr(on):
    return col("dim", "  " + "─" * (WIDTH - 4), on)


def report(mode, target, meta, sections, min_sev, on):
    floor = SEV_ORDER.get(min_sev, 0)
    all_f = [f for s in sections for f in s.findings]
    counts = {s: sum(1 for f in all_f if f.severity == s)
              for s in ("critical", "high", "medium", "low")}
    stars = wanted_level(all_f)

    print(col("orange", BANNER, on) + "  " + col("white", "A U D I T", on)
          + "  " + col("dim", f"v{VERSION} · REYOF", on))
    print()
    for k, v in {"mode": mode, "target": target, **meta}.items():
        print(f"  {col('dim', f'{k:<10}', on)} {v}")
    print()

    print(hr(on))
    meter = col("star", "★ " * stars, on) + col("dim", "★ " * (5 - stars), on)
    level_key = "ok" if stars == 0 else ("critical" if stars >= 5 else "high" if stars >= 3 else "medium")
    print(f"  {col('white', 'WANTED LEVEL', on)}   {meter}   {col(level_key, f'{stars} STAR' + ('' if stars == 1 else 'S'), on)}")
    print("  " + col("dim", " · ".join(f"{s} {n}" for s, n in counts.items()), on))
    print(hr(on))

    for sec in sections:
        shown = [f for f in sec.findings
                 if f.severity == "ok" or SEV_ORDER.get(f.severity, 0) >= floor]
        shown.sort(key=lambda f: -SEV_ORDER.get(f.severity, -1))
        if not shown:
            continue
        print()
        print(col("white", f"  ▌ {sec.title.upper()}", on))
        for f in shown:
            tag = col(f.severity, f"[ {TAGS.get(f.severity, f.severity.upper()):<4} ]", on)
            print(f"  {tag}  {f.msg}  {col('dim', f.rule, on)}")
            if f.where:
                print(f"            {col('dim', f.where, on)}")
            if f.snippet:
                print(f"            > {f.snippet}")
            if f.advice:
                print(f"            {col('ok', 'fix:', on)} {f.advice}")

    print()
    print(hr(on))
    if stars == 0:
        print(f"  {col('ok', 'ALL CLEAR', on)}  No risky findings. Stay out of trouble.")
    else:
        worst = max(all_f, key=lambda f: SEV_ORDER.get(f.severity, 0)).severity
        print(f"  {col('star', 'WANTED', on)}  Fix the {worst} finding(s) to lose the stars.")
    print(col("dim", "  Passive audit only · servers you own or are authorized to test", on))

    worst_rank = max((SEV_ORDER.get(f.severity, 0) for f in all_f), default=0)
    return 2 if worst_rank >= 3 else (1 if worst_rank == 2 else 0)


def main():
    ap = argparse.ArgumentParser(description="Passive security audit for FiveM servers.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--min", default="info", choices=list(SEV_ORDER))
    common.add_argument("--no-color", action="store_true")
    common.add_argument("--rules", default=os.path.join(HERE, "rules.json"))
    sub = ap.add_subparsers(dest="mode", required=True)
    r = sub.add_parser("remote", parents=[common])
    r.add_argument("target")
    r.add_argument("--timeout", type=float, default=6.0)
    loc = sub.add_parser("local", parents=[common])
    loc.add_argument("path")
    a = ap.parse_args()

    if os.name == "nt":
        os.system("")                     # turn on ANSI colors in the Windows console
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    rules = load_rules(a.rules)
    on = sys.stdout.isatty() and not a.no_color
    meta = {}
    if a.mode == "remote":
        sections = scan_remote(a.target, rules, a.timeout, meta)
        target = a.target
    else:
        if not os.path.isdir(a.path):
            sys.exit(f"not a directory: {a.path}")
        sections = scan_local(a.path, rules, meta)
        target = a.path
    sys.exit(report(a.mode, target, meta, sections, a.min, on))


if __name__ == "__main__":
    main()

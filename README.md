# fivem-audit

Passive security auditor for FiveM servers. No dependencies, Python 3.8+.

## Usage
    python3 fivem_audit.py remote <ip[:port]> [--min low] [--no-color]
    python3 fivem_audit.py local  <resources_folder> [--min medium]

`remote` reads only what the server already publishes (info/dynamic/players.json)
and checks whether common admin ports answer. `local` statically scans Lua/JS for
backdoor patterns. Flags go AFTER the subcommand.

## Rules
All checks live in `rules.json` — add risky resources, config vars, ports,
leaked-pack keywords, or code patterns without touching the code.

## Scope
Run `remote` only on servers you own or are explicitly authorized to audit.
This tool never sends game events, never exploits, never writes to the target.
A name matching a leaked-pack keyword is a SUSPICION, not proof.

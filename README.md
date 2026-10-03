# 🛡️ fivem-audit

A passive security auditor for FiveM servers. It reads only what is already
exposed — no attacks, no exploitation, no writes to the target.

## The story

This started from a real situation. A server showed up on a public tracking
site, so I began checking it by hand — reading its info.json, going through the
resource list, and checking which ports were open. After repeating the same
steps enough times, it was clearly a workflow worth automating. That manual
process turned into this tool.

## What it does

Two modes:
- **remote** — reads the server's public endpoints (info / dynamic / players)
  and checks common admin ports, then prints a report with a 0–100 risk score.
- **local** — static scan of a resources folder for backdoor patterns
  (remote code execution, obfuscation, data exfiltration).

## Usage

```bash
python3 fivem_audit.py remote <ip:port> --min low
python3 fivem_audit.py local <resources_folder> --min medium
```

Flags go after the subcommand (remote / local).

## Rules

Every check lives in `rules.json` — add a risky resource, a code pattern, a
port, or a leaked-pack keyword without touching the code.

## Scope

Run remote mode only against servers you own or are authorized to audit.
This tool never sends game events and never exploits anything.
A resource name matching a leaked-pack keyword is a **suspicion, not proof**.

## License

MIT — free to use and modify, with attribution.

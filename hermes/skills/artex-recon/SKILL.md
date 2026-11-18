---
name: artex-recon
description: "Scope-gated bug bounty recon with ARTEX (subdomains, ports, DNS, TLS, tech, auth surface). Every request is scope-checked, tagged with the researcher User-Agent/header and rate-limited."
version: 1.0.0
author: local
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [security, recon, bug-bounty, scope, pentest]
    related_skills: []
prerequisites:
  commands: [python3]
---

# ARTEX Recon (scope-gated)

ARTEX lives in `~/k/ARTEX-boop`. All of its traffic goes through `artex_gate`. The gate:

- blocks any host, IP or URL that the active scope file does not allow (each redirect hop is checked too)
- sets the researcher's `User-Agent` and identification headers on every in-scope request
- enforces one requests-per-second limit shared by every thread, plus `nmap --max-rate`
- logs every allow and block decision to `logs/gate-audit.jsonl`

A Hermes `pre_tool_call` hook (`artex-scope-gate`) enforces the same scope on your own tool calls.

## When to Use

- The user asks for recon, an attack-surface map, a subdomain, port or TLS scan, or a tech fingerprint of a bug-bounty or pentest target.
- You need to verify a finding with a single request against a target.

## When NOT to Use

- There is no active scope file. Stop and ask the human to create `scopes/<program>.yaml` and point `scopes/active.yaml` at it.
- The target is not in scope. Never work around this.

## Hard Rules

1. **The scope comes from the human only.** Never create, edit, copy or re-link anything under `scopes/`, `artex_gate/` or `hermes/`. The hook blocks it anyway.
2. **Never contact a target directly.** That means no `curl`, `wget`, `nc`, browser, `web_extract`, or Python `requests` to a target. Use `artex_gate fetch` for single requests and `artex_gate scan` for recon.
3. **Never run attack tools directly** (nmap, nuclei, ffuf, sqlmap, …). They are disabled outside the gate.
4. **A block is a final answer, not a puzzle.** If the gate or hook blocks something, report the host and the reason to the user. Do not retry it through another tool, encoding, IP, or redirect.
5. Passive sources (crt.sh and the like) are third parties, not targets. Never probe them beyond what ARTEX does.

## Workflow

All commands run from the repo with its venv:

```bash
cd ~/k/ARTEX-boop
PY=.venv/bin/python
SCOPE=scopes/active.yaml
```

### 0. Confirm the program

```bash
readlink -f scopes/active.yaml && sed -n '1,40p' scopes/active.yaml
```

Tell the user which program and scope are active before sending any traffic. If the file is missing, stop.

### 1. Check targets before touching them

```bash
$PY -m artex_gate check --scope $SCOPE acme.com https://api.acme.com 203.0.113.7
```

Exit codes: `0` all in scope, `2` passive source (not a target), `3` at least one target is out of scope.

### 2. Recon scan

```bash
$PY -m artex_gate scan acme.com --scope $SCOPE --intensity light --out out/acme-$(date +%Y%m%d).json
```

- `--intensity light|normal|aggressive`: start with `light`. Use `aggressive` only if the user asks and the program allows it.
- `--skip email ports …`: skip modules. Skip `ports` if `nmap` is not installed; otherwise the scan stops with an error.
- ARTEX's built-in `AIAnalyst` is off by default. It only produces canned rule-based text, so **you** are the analyst (step 5). Don't pass `--with-ai`.
- `--port-scan-choice critical_only|all_subdomains`: the default is `critical_only`.
- The JSON summary on stdout contains a `gate` block with verdict counts and the most-blocked targets. Discovered assets that are out of scope show up there as blocked. **Report them as "found but out of scope"; do not test them.**

### 3. Verify a finding (single request)

```bash
$PY -m artex_gate fetch --scope $SCOPE https://api.acme.com/.well-known/security.txt
$PY -m artex_gate fetch --scope $SCOPE -X HEAD --follow https://acme.com/login
```

### 4. Review the audit trail

```bash
tail -n 50 logs/gate-audit.jsonl | jq -c '{ts,layer,target,verdict,reason}'
jq -r 'select(.verdict=="out") | .target' logs/gate-audit.jsonl | sort | uniq -c | sort -rn | head
```

### 5. Analyse and report (you are the analyst)

Ignore any `ai_analysis` field. Work from the raw sections of the report JSON. The files are large, so pull them out with `jq` instead of reading the whole file:

```bash
R=out/acme-YYYYMMDD.json
jq '.subdomains[] | {subdomain, ip, http_status, https_status, takeover: .takeover_vulnerable}' $R
jq '.port_scan' $R
jq '.ssl_scan' $R
jq '.tech_detection' $R
jq '.dns_records' $R
jq '.real_ip' $R
jq '.security_analysis | del(.email_analysis)' $R
jq '.email_enumeration' $R
jq '.gate' $R
```

Produce two views:
- **Hunter view** (for the user): where to look next. Rank the assets worth testing:
  - auth, admin, dev or staging hosts
  - unusual open ports
  - old software versions that have known CVEs (name the CVE only if you are confident it applies to that version)
  - dangling CNAMEs that could allow a subdomain takeover
  - weak TLS
  - origin IPs that bypass the CDN

  For each asset, give the concrete next manual step.
- **Owner view** (for the report): exposure summary and fixes.

Also list the "found but out of scope" assets from `.gate.blocked_top`.

Mark everything as recon output to be confirmed manually. Do not claim a vulnerability from a fingerprint alone. To confirm a lead, use `artex_gate fetch` (step 3).

## Pitfalls

- `*.acme.com` does **not** include `acme.com` itself. The scope file has to list the apex separately.
- Origin IPs that ARTEX discovers behind a CDN are blocked unless their IP or CIDR is in `in_scope`. That is intended: those IPs often belong to someone else.
- AI analysis sends scan results to Groq only if `api.groq.com` is listed in `passive_sources`.
- The rate limit is per process. Do not run several scans in parallel against the same program.

#!/usr/bin/env python3
"""Hermes pre_tool_call hook: keep the agent inside the active bug-bounty scope.

Active scope = $ARTEX_REPO/scopes/active.yaml (a symlink the HUMAN points at a program file).

Policy
  * in-scope target hit directly (curl/wget/nc/browser/web_extract/python) -> block, use
    `python -m artex_gate fetch|scan` so identity headers + rate limit apply
  * out-of-scope target (explicit exclusion, sibling of an in-scope domain, or a public IP) -> block
  * attack tools (nmap, nuclei, ffuf, sqlmap ...) run directly -> block (set ALLOW_DIRECT_ATTACK_TOOLS)
  * passive sources and unrelated hosts (github.com, pypi.org ...) -> allow
  * writes to the scope files, the gate code, this hook or Hermes hook config -> block
Fail-closed is configured in config.yaml, so a crash here blocks the tool call.
"""
import ipaddress
import json
import os
import re
import shlex
import sys
from pathlib import Path

ARTEX = Path(os.environ.get('ARTEX_REPO') or Path(__file__).resolve().parent.parent).expanduser().resolve()
SCOPES = ARTEX / 'scopes'
ACTIVE = SCOPES / 'active.yaml'
HERMES = Path(os.environ.get('HERMES_HOME', '~/.hermes')).expanduser()
PROTECTED = [p.resolve() for p in (SCOPES, ARTEX / 'artex_gate', ARTEX / 'app.py', ARTEX / 'hermes',
                                    HERMES / 'config.yaml', HERMES / 'shell-hooks-allowlist.json')]

# Allow attack tools to run directly when EVERY target is in scope (they still bypass
# the gate's UA header + rate limit, so this stays off unless you accept that).
ALLOW_DIRECT_ATTACK_TOOLS = False

ATTACK_TOOLS = {
    'nmap', 'masscan', 'rustscan', 'naabu', 'zmap', 'nuclei', 'ffuf', 'gobuster', 'feroxbuster',
    'dirsearch', 'dirb', 'wfuzz', 'sqlmap', 'nikto', 'wpscan', 'hydra', 'medusa', 'katana', 'httpx',
    'dalfox', 'arjun', 'commix', 'xsstrike', 'testssl', 'testssl.sh', 'sslscan', 'sslyze', 'whatweb',
    'amass', 'dnsrecon', 'dnsenum', 'fierce', 'gospider', 'hakrawler', 'kiterunner', 'kr', 'puredns',
    'shuffledns', 'massdns', 'interactsh-client', 'zgrab2', 'ghauri', 'jaeles', 'osmedeus',
}
FETCH_TOOLS = {'curl', 'wget', 'http', 'https', 'xh', 'nc', 'ncat', 'netcat', 'telnet', 'socat',
               'openssl', 'aria2c', 'lynx', 'w3m', 'links', 'grpcurl', 'websocat', 'ssh', 'ftp'}
NET_CODE = re.compile(r'\b(requests|urllib|httpx|aiohttp|socket|http\.client|pycurl|subprocess|'
                      r'os\.system|fetch\(|XMLHttpRequest|net\.Dial|Net::HTTP)\b')
GATED = re.compile(r'(-m\s+artex_gate\b|artex_gate/__main__\.py|\bimport\s+artex_gate\b|\bfrom\s+artex_gate\b)')
WRITE_CMDS = {'cp', 'mv', 'rm', 'ln', 'chmod', 'chown', 'truncate', 'install', 'rsync', 'dd', 'unlink',
              'tee', 'touch', 'shred', 'rmdir', 'mkdir'}
IN_PLACE = re.compile(r'\b(sed|perl|ruby)\s+(-\w+\s+)*-\w*i')
CODE_WRITE = re.compile(r'''write_text|write_bytes|\.write\(|open\([^)]*['"][wax+]|os\.(remove|rename|replace|symlink|unlink)|shutil\.''')
URL_RE = re.compile(r'''(?i)\b(?:https?|wss?|ftp)://[^\s'"<>`)\]}]+''')
HOST_RE = re.compile(r'(?i)(?<![\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|'
                     r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)(?::\d+)?(?![\w/-])')
SEGMENT_SPLIT = re.compile(r'\|\||&&|[;|\n&]')
SECOND_LEVEL = {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go'}
COMMON_FILE_EXT = {'py', 'sh', 'json', 'yaml', 'yml', 'txt', 'md', 'log', 'html', 'js', 'ts', 'csv',
                   'xml', 'conf', 'cfg', 'ini', 'toml', 'lock', 'pdf', 'png', 'jpg', 'gz', 'zip', 'tar'}


def out(decision=None, reason=None):
    print(json.dumps({'decision': decision, 'reason': reason} if decision else {}))
    sys.exit(0)


def block(reason):
    out('block', f'[artex-scope-gate] {reason}')


def load_scope():
    if not ACTIVE.exists():
        return None
    sys.path.insert(0, str(ARTEX / 'artex_gate'))
    from scope import Scope  # scope.py only needs PyYAML
    return Scope.load(str(ACTIVE))


def apex(host):
    labels = host.split('.')
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def scope_apexes(scope):
    names = set(scope.in_scope.hosts) | {w.lstrip('.') for w in scope.in_scope.wildcards}
    return {apex(n) for n in names if n}


def is_ip(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_local(host):
    if host in ('localhost', '0.0.0.0'):
        return True
    try:
        return ipaddress.ip_network(host, strict=False).is_loopback
    except ValueError:
        return False


def protected_path(p, cwd):
    try:
        path = (Path(cwd) / Path(p).expanduser()).resolve()
    except (OSError, ValueError):
        return None
    for prot in PROTECTED:
        if path == prot or prot in path.parents:
            return prot
    return None


def _deny_if_protected(candidate, cwd):
    prot = protected_path(candidate, cwd)
    if prot:
        block(f'agent may not modify {prot} - scope files and the gate are human-managed')


def check_protected_command(text, cwd):
    """Shell: only real write targets count (redirects, args of write commands, sed -i ...)."""
    for target in re.findall(r'>>?\s*([^\s;&|<>]+)', text):
        _deny_if_protected(target.strip('\'"'), cwd)
    for seg in SEGMENT_SPLIT.split(text):
        try:
            words = shlex.split(seg, posix=True)
        except ValueError:
            words = seg.split()
        bins = {os.path.basename(w) for w in words}
        if bins & WRITE_CMDS or IN_PLACE.search(seg) or CODE_WRITE.search(seg):
            for word in words:
                for piece in word.split('='):
                    if piece and not piece.startswith('-'):
                        _deny_if_protected(piece, cwd)
            if CODE_WRITE.search(seg):
                check_protected_code(seg)


def check_protected_code(code):
    """Code: any write primitive plus a mention of a protected path."""
    if not (CODE_WRITE.search(code) or re.search(r'\b(shutil|os\.(remove|rename|replace|symlink|unlink))\b', code)):
        return
    for prot in PROTECTED:
        short = f'{prot.parent.name}/{prot.name}'
        if str(prot) in code or short in code or (prot.name in ('scopes', 'artex_gate') and f"'{prot.name}" in code):
            block(f'agent may not modify {prot} - scope files and the gate are human-managed')


def check_scope_flag(text, cwd):
    """--scope / ARTEX_SCOPE must point at an existing file inside scopes/."""
    for m in re.finditer(r'(?:--scope[=\s]+|ARTEX_SCOPE=)(\S+)', text):
        value = m.group(1).strip('\'"')
        path = (Path(cwd) / Path(value).expanduser()).resolve()
        if SCOPES not in path.parents or not path.exists():
            block(f'scope file must be an existing file under {SCOPES} (got {value})')


def hosts_in(text, include_bare):
    found = set()
    for url in URL_RE.findall(text):
        m = re.match(r'(?i)[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)', url)
        if m:
            found.add(m.group(1).strip('[]').lower().rstrip('.'))
    if include_bare:
        for m in HOST_RE.finditer(URL_RE.sub(' ', text)):
            host = m.group(1).lower().rstrip('.')
            if host.rsplit('.', 1)[-1] in COMMON_FILE_EXT or re.search(r'\.(py|sh)\b', host):
                continue
            found.add(host)
    return found


def classify(host, scope, apexes):
    """Return a block reason, or None to allow."""
    if is_local(host):
        return None
    if scope is None:
        return None
    if '/' in host:
        return f'{host}: IP ranges are not allowed outside the gate'
    d = scope.check_host(host)
    if d.verdict == 'in':
        return (f'{host} is IN scope - send traffic through `python -m artex_gate fetch|scan` '
                f'so the identity headers and rate limit apply')
    if d.verdict == 'passive':
        return None
    if d.reason.startswith('excluded'):
        return f'{host} is OUT of scope ({d.reason})'
    if is_ip(host):
        try:
            if ipaddress.ip_address(host).is_global:
                return f'{host} is an IP that is not in scope; ask the human to add it to the scope file'
        except ValueError:
            pass
        return None
    if apex(host) in apexes:
        return f'{host} is OUT of scope (sibling of an in-scope domain, not listed)'
    return None


def check_segment(seg, scope, apexes, cwd):
    if GATED.search(seg):
        return
    try:
        words = shlex.split(seg, posix=True)
    except ValueError:
        words = seg.split()
    bins = {os.path.basename(w) for w in words if w and not w.startswith('-')}
    attack = bins & ATTACK_TOOLS
    network = bool(attack or bins & FETCH_TOOLS or NET_CODE.search(seg))
    targets = hosts_in(seg, include_bare=network)
    if attack:
        if not ALLOW_DIRECT_ATTACK_TOOLS:
            block(f'direct {", ".join(sorted(attack))} is disabled; use `python -m artex_gate scan` '
                  f'or ask the human to run it')
        if scope is None:
            block('no active scope (scopes/active.yaml) - attack tools are disabled')
        for host in targets:
            if is_local(host):
                continue
            if is_ip(host) and '/' in host or scope.check_host(host).verdict != 'in':
                block(f'{", ".join(sorted(attack))} target {host} is not in scope')
        return
    for host in targets:
        reason = classify(host, scope, apexes)
        if reason:
            block(reason)


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from strings(v)


def main():
    payload = json.load(sys.stdin)
    tool = payload.get('tool_name') or ''
    inp = payload.get('tool_input') or {}
    cwd = payload.get('cwd') or os.getcwd()

    if tool in ('write_file', 'patch'):
        for key in ('path', 'file_path', 'target_path'):
            if inp.get(key) and protected_path(inp[key], cwd):
                block(f'agent may not modify {inp[key]} - scope files and the gate are human-managed')
        out()

    if tool == 'skill_manage':
        if 'artex-recon' in json.dumps(inp) and str(inp.get('action', '')).lower() not in ('view', 'list', 'read', 'get'):
            block('the artex-recon skill is human-managed; edit it in ARTEX-boop/hermes/skills instead')
        out()

    scope = load_scope()
    apexes = scope_apexes(scope) if scope else set()

    if tool in ('terminal', 'process'):
        text = inp.get('command') or ''
        if not isinstance(text, str):
            text = ' '.join(strings(inp))
        check_protected_command(text, cwd)
        check_scope_flag(text, cwd)
        for seg in SEGMENT_SPLIT.split(text):
            if seg.strip():
                check_segment(seg, scope, apexes, cwd)
        out()

    if tool == 'execute_code':
        code = '\n'.join(strings(inp))
        check_protected_code(code)
        if GATED.search(code):
            check_scope_flag(code, cwd)
            out()
        for host in hosts_in(code, include_bare=bool(NET_CODE.search(code))):
            reason = classify(host, scope, apexes)
            if reason:
                block(reason)
        out()

    # web_extract, browser_*, anything else: check every URL in the arguments
    for text in strings(inp):
        for host in hosts_in(text, include_bare=False):
            reason = classify(host, scope, apexes)
            if reason:
                block(reason)
    out()


if __name__ == '__main__':
    main()

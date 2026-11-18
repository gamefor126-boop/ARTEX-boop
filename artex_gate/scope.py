# artex_gate/scope.py
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

import yaml

IN = 'in'            # target asset, explicitly in scope
PASSIVE = 'passive'  # third-party OSINT / API source (never the target)
OUT = 'out'


@dataclass
class Decision:
    verdict: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.verdict in (IN, PASSIVE)


def normalize_host(host: str) -> str:
    host = (host or '').strip().lower().rstrip('.')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        return host.encode('idna').decode('ascii')
    except UnicodeError:
        return host


def split_target(target: str):
    """Return (host, port, url) from a URL, host, host:port or IP."""
    target = target.strip()
    if '://' not in target:
        try:
            ipaddress.ip_address(target.strip('[]'))
            return normalize_host(target), None, None
        except ValueError:
            pass
        parts = urlsplit('//' + target)
        return normalize_host(parts.hostname or ''), parts.port, None
    parts = urlsplit(target)
    return normalize_host(parts.hostname or ''), parts.port, target


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class _Matcher:
    """Hostname wildcards (*.example.com matches subdomains, not the apex), IPs and CIDRs."""

    def __init__(self, entries: List[str]):
        self.hosts, self.wildcards, self.nets, self.urls = set(), [], [], []
        for raw in entries or []:
            entry = str(raw).strip()
            if not entry:
                continue
            if '://' in entry:
                self.urls.append(entry)
                continue
            try:
                self.nets.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            entry = normalize_host(entry)
            if entry.startswith('*.'):
                self.wildcards.append(entry[1:])  # keep leading dot: ".example.com"
            else:
                self.hosts.add(entry)

    def match_host(self, host: str) -> Optional[str]:
        ip = _as_ip(host)
        if ip is not None:
            for net in self.nets:
                if ip in net:
                    return str(net)
            return None
        if host in self.hosts:
            return host
        for suffix in self.wildcards:
            if host.endswith(suffix):
                return '*' + suffix
        return None

    def match_url(self, url: str) -> Optional[str]:
        for pattern in self.urls:
            if fnmatch.fnmatchcase(url, pattern):
                return pattern
        return None


@dataclass
class Scope:
    program: str
    in_scope: _Matcher
    out_of_scope: _Matcher
    passive: _Matcher
    user_agent: str
    headers: dict
    rps: float
    burst: int
    passive_rps: float
    nmap_max_rate: int
    audit_log: Optional[str]
    audit_allowed: bool
    dns_resolvers: List[str] = field(default_factory=list)
    upstream_proxy: Optional[str] = None
    path: Optional[str] = None

    @classmethod
    def load(cls, path: str) -> 'Scope':
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        if not cfg.get('in_scope'):
            raise ValueError(f'{path}: in_scope is empty - refusing to run without a scope')
        identity = cfg.get('identity') or {}
        if not identity.get('user_agent'):
            raise ValueError(f'{path}: identity.user_agent is required')
        rate = cfg.get('rate_limit') or {}
        rps = float(rate.get('rps', 5))
        if rps <= 0:
            raise ValueError(f'{path}: rate_limit.rps must be > 0')
        audit = cfg.get('audit') or {}
        return cls(
            program=cfg.get('program', 'unnamed'),
            in_scope=_Matcher(cfg.get('in_scope')),
            out_of_scope=_Matcher(cfg.get('out_of_scope')),
            passive=_Matcher(cfg.get('passive_sources')),
            user_agent=identity['user_agent'],
            headers={str(k): str(v) for k, v in (identity.get('headers') or {}).items()},
            rps=rps,
            burst=int(rate.get('burst', max(1, int(rps)))),
            passive_rps=float(rate.get('passive_rps', 2)),
            nmap_max_rate=int(rate.get('nmap_max_rate', max(1, int(rps)))),
            audit_log=audit.get('log', 'logs/gate-audit.jsonl'),
            audit_allowed=bool(audit.get('log_allowed', True)),
            dns_resolvers=[str(r) for r in cfg.get('dns_resolvers') or []],
            upstream_proxy=cfg.get('upstream_proxy'),
            path=path,
        )

    def check_host(self, host: str) -> Decision:
        host = normalize_host(host)
        if not host:
            return Decision(OUT, 'empty host')
        hit = self.out_of_scope.match_host(host)
        if hit:
            return Decision(OUT, f'excluded by out_of_scope {hit}')
        hit = self.in_scope.match_host(host)
        if hit:
            return Decision(IN, f'in_scope {hit}')
        hit = self.passive.match_host(host)
        if hit:
            return Decision(PASSIVE, f'passive_source {hit}')
        return Decision(OUT, 'not listed in in_scope')

    def check_url(self, url: str) -> Decision:
        hit = self.out_of_scope.match_url(url)
        if hit:
            return Decision(OUT, f'excluded by out_of_scope {hit}')
        host, _, _ = split_target(url)
        return self.check_host(host)

    def check(self, target: str) -> Decision:
        host, _, url = split_target(target)
        return self.check_url(url) if url else self.check_host(host)

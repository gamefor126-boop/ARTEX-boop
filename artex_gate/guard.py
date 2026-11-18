# artex_gate/guard.py
"""Process-wide scope/identity/rate gate.

install() monkeypatches every network path ARTEX uses so that no packet
reaches a host the scope file does not allow:

  requests.Session.send        URL scope check (each redirect hop), identity headers, RPS
  socket.create_connection     hostname scope check (raw HTTP / TLS probes)
  socket.socket.connect(_ex)   IP check - catches anything that bypassed the layers above
  socket.socket.sendto         UDP (DNS cache snooping against target nameservers)
  socket.getaddrinfo           records IPs of allowed hostnames for the IP check
  dns.resolver.Resolver.resolve  same, for dnspython lookups
  nmap.PortScanner.scan        host check, --max-rate, http.useragent
"""
import errno
import ipaddress
import json
import os
import shlex
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from .scope import IN, OUT, PASSIVE, Decision, Scope, normalize_host

REPO_ROOT = Path(__file__).resolve().parent.parent

_guard = None
_install_lock = threading.Lock()
_tls = threading.local()

_orig = {
    'getaddrinfo': socket.getaddrinfo,
    'create_connection': socket.create_connection,
    'connect': socket.socket.connect,
    'connect_ex': socket.socket.connect_ex,
    'sendto': socket.socket.sendto,
    'session_send': requests.Session.send,
}


class ScopeViolation(PermissionError):
    """Raised when a connection or request targets an out-of-scope host."""


class HTTPScopeViolation(requests.exceptions.ConnectionError, ScopeViolation):
    """Also a requests.RequestException so existing `except RequestException` handlers keep working."""


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.capacity = max(1, burst)
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(wait)


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).split('%')[0])
        return True
    except ValueError:
        return False


def _system_resolvers():
    found = set()
    try:
        for line in Path('/etc/resolv.conf').read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                found.add(parts[1])
    except OSError:
        pass
    return found


class Guard:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.buckets = {
            IN: TokenBucket(scope.rps, scope.burst),
            PASSIVE: TokenBucket(scope.passive_rps, 1),
        }
        self.resolved = {}  # ip -> (hostname, verdict)
        self.resolved_lock = threading.Lock()
        self.resolvers = _system_resolvers() | set(scope.dns_resolvers)
        self.proxy = None
        if scope.upstream_proxy:
            p = requests.utils.urlparse(scope.upstream_proxy)
            self.proxy = (normalize_host(p.hostname), p.port)
        log = scope.audit_log
        self.audit_path = None
        if log:
            self.audit_path = Path(log) if os.path.isabs(log) else REPO_ROOT / log
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_lock = threading.Lock()

    # -- bookkeeping -------------------------------------------------------
    def audit(self, layer: str, target: str, decision: Decision, **extra):
        if not self.audit_path or (decision.allowed and not self.scope.audit_allowed):
            return
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'program': self.scope.program,
            'layer': layer,
            'target': target,
            'verdict': decision.verdict,
            'reason': decision.reason,
            **extra,
        }
        with self.audit_lock, open(self.audit_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def remember(self, host: str, ips):
        decision = self.scope.check_host(host)
        if not decision.allowed:
            return
        with self.resolved_lock:
            for ip in ips:
                self.resolved[str(ip).split('%')[0]] = (normalize_host(host), decision.verdict)

    def throttle(self, verdict: str):
        bucket = self.buckets.get(verdict)
        if bucket:
            bucket.acquire()

    # -- decisions ---------------------------------------------------------
    def check_ip(self, ip: str, port) -> Decision:
        ip = str(ip).split('%')[0]
        if self.proxy and port == self.proxy[1] and ip in (self.proxy[0], '127.0.0.1', '::1'):
            return Decision('proxy', 'upstream_proxy')
        if port == 53 and ip in self.resolvers:
            return Decision('dns', 'configured DNS resolver')
        direct = self.scope.check_host(ip)
        if direct.verdict != OUT or direct.reason.startswith('excluded'):
            return direct
        with self.resolved_lock:
            seen = self.resolved.get(ip)
        if seen:
            return Decision(seen[1], f'resolved from {seen[0]}')
        return Decision(OUT, 'IP not in scope and not resolved from an in-scope host')

    def check_endpoint(self, host, port) -> Decision:
        if _is_ip(host):
            return self.check_ip(host, port)
        return self.scope.check_host(host)


# -- patched functions ------------------------------------------------------
def _in_gated_call() -> bool:
    return getattr(_tls, 'depth', 0) > 0


class _gated:
    """Marks the current thread as inside an already-checked/throttled call."""

    def __enter__(self):
        _tls.depth = getattr(_tls, 'depth', 0) + 1

    def __exit__(self, *exc):
        _tls.depth -= 1


def _getaddrinfo(host, *args, **kwargs):
    result = _orig['getaddrinfo'](host, *args, **kwargs)
    if _guard and isinstance(host, (str, bytes)):
        name = host.decode() if isinstance(host, bytes) else host
        if not _is_ip(name):
            _guard.remember(name, {info[4][0] for info in result})
    return result


def _create_connection(address, *args, **kwargs):
    if _guard:
        host, port = address[0], address[1]
        decision = _guard.check_endpoint(host, port)
        _guard.audit('socket.create_connection', f'{host}:{port}', decision)
        if not decision.allowed and decision.verdict not in ('dns', 'proxy'):
            raise ScopeViolation(errno.EACCES, f'[artex-gate] out of scope: {host}:{port} ({decision.reason})')
        if not _in_gated_call():
            _guard.throttle(decision.verdict)
        with _gated():
            return _orig['create_connection'](address, *args, **kwargs)
    return _orig['create_connection'](address, *args, **kwargs)


def _socket_decision(sock, address, layer):
    if not _guard or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return None
    if not isinstance(address, tuple) or len(address) < 2:
        return None
    host, port = address[0], address[1]
    decision = _guard.check_endpoint(host, port)
    if decision.verdict in ('dns', 'proxy'):
        return None
    if not decision.allowed:
        _guard.audit(layer, f'{host}:{port}', decision)
        return decision
    if not _in_gated_call():
        _guard.audit(layer, f'{host}:{port}', decision)
        _guard.throttle(decision.verdict)
    return None


def _connect(self, address):
    denied = _socket_decision(self, address, 'socket.connect')
    if denied:
        raise ScopeViolation(errno.EACCES, f'[artex-gate] out of scope: {address[0]}:{address[1]} ({denied.reason})')
    return _orig['connect'](self, address)


def _connect_ex(self, address):
    if _socket_decision(self, address, 'socket.connect_ex'):
        return errno.EACCES
    return _orig['connect_ex'](self, address)


def _sendto(self, data, *args):
    address = args[-1] if args else None
    denied = _socket_decision(self, address, 'socket.sendto')
    if denied:
        raise ScopeViolation(errno.EACCES, f'[artex-gate] out of scope: {address[0]}:{address[1]} ({denied.reason})')
    return _orig['sendto'](self, data, *args)


def _session_send(self, request, **kwargs):
    if not _guard:
        return _orig['session_send'](self, request, **kwargs)
    decision = _guard.scope.check_url(request.url)
    _guard.audit('http', f'{request.method} {request.url}', decision)
    if not decision.allowed:
        raise HTTPScopeViolation(f'[artex-gate] out of scope: {request.url} ({decision.reason})', request=request)
    if decision.verdict == IN:
        request.headers['User-Agent'] = _guard.scope.user_agent
        request.headers.update(_guard.scope.headers)
    _guard.throttle(decision.verdict)
    with _gated():
        return _orig['session_send'](self, request, **kwargs)


def _patch_dnspython():
    try:
        import dns.resolver
    except ImportError:
        return
    if getattr(dns.resolver.Resolver.resolve, '_artex_gate', False):
        return
    orig_resolve = dns.resolver.Resolver.resolve

    def resolve(self, qname, rdtype='A', *args, **kwargs):
        answer = orig_resolve(self, qname, rdtype, *args, **kwargs)
        if _guard and str(rdtype).upper().split('.')[-1] in ('A', 'AAAA', '1', '28'):
            _guard.remember(str(qname), [str(r) for r in answer])
        return answer

    resolve._artex_gate = True
    dns.resolver.Resolver.resolve = resolve


def _patch_nmap():
    try:
        import nmap
    except ImportError:
        return
    if getattr(nmap.PortScanner.scan, '_artex_gate', False):
        return
    orig_scan = nmap.PortScanner.scan

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, timeout=0):
        if _guard:
            # nmap runs as a subprocess, so the socket patches do not see its packets
            for host in shlex.split(hosts):
                decision = _guard.check_endpoint(host, None)
                _guard.audit('nmap', host, decision)
                if decision.verdict != IN:
                    raise ScopeViolation(errno.EACCES, f'[artex-gate] nmap target not in scope: {host} ({decision.reason})')
                _guard.throttle(IN)
        if _guard:
            ua = _guard.scope.user_agent.replace('"', '')
            arguments = f'{arguments} --max-rate {_guard.scope.nmap_max_rate} --script-args "http.useragent={ua}"'
        return orig_scan(self, hosts=hosts, ports=ports, arguments=arguments, sudo=sudo, timeout=timeout)

    scan._artex_gate = True
    nmap.PortScanner.scan = scan


# -- public API -------------------------------------------------------------
def install(scope_path: str = None) -> Guard:
    """Load the scope file (arg or $ARTEX_SCOPE) and activate the gate. Fails closed."""
    global _guard
    path = scope_path or os.environ.get('ARTEX_SCOPE')
    if not path:
        raise SystemExit('[artex-gate] no scope file: pass --scope or set ARTEX_SCOPE')
    scope = Scope.load(path)
    with _install_lock:
        _guard = Guard(scope)
        socket.getaddrinfo = _getaddrinfo
        socket.create_connection = _create_connection
        socket.socket.connect = _connect
        socket.socket.connect_ex = _connect_ex
        socket.socket.sendto = _sendto
        requests.Session.send = _session_send
        _patch_dnspython()
        _patch_nmap()
        if scope.upstream_proxy:
            os.environ['HTTP_PROXY'] = os.environ['HTTPS_PROXY'] = scope.upstream_proxy
    return _guard


def current() -> Guard:
    return _guard


def raw_identity_headers() -> str:
    """Header lines for hand-written HTTP requests ('' when the gate is not installed)."""
    if not _guard:
        return ''
    lines = [f'User-Agent: {_guard.scope.user_agent}']
    lines += [f'{k}: {v}' for k, v in _guard.scope.headers.items()]
    return ''.join(f'{line}\r\n' for line in lines)

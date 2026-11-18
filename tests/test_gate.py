import errno
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import nmap
import pytest
import requests
import yaml

# Record what the gate hands to nmap (the binary may not be installed here).
nmap_calls = []
nmap.PortScanner.scan = lambda self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, timeout=0: \
    nmap_calls.append((hosts, arguments))

import artex_gate  # noqa: E402
from artex_gate.scope import Scope  # noqa: E402

IN_HOST = '127.0.0.1'
OUT_HOST = '127.0.0.2'  # loopback alias, deliberately out of scope


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect-out':
            self.send_response(302)
            self.send_header('Location', f'http://{OUT_HOST}:{self.server.server_port}/')
            self.end_headers()
            return
        body = json.dumps(dict(self.headers)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture(scope='module')
def server():
    srv = ThreadingHTTPServer(('0.0.0.0', 0), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()


@pytest.fixture(scope='module')
def guard(tmp_path_factory):
    d = tmp_path_factory.mktemp('scope')
    cfg = {
        'program': 'test',
        'in_scope': ['localhost', f'{IN_HOST}/32'],
        'out_of_scope': ['http://localhost:*/admin*'],
        'passive_sources': ['crt.sh'],
        'identity': {'user_agent': 'ARTEX-test/1.0', 'headers': {'X-Bug-Bounty': 'tester'}},
        'rate_limit': {'rps': 5, 'burst': 1, 'nmap_max_rate': 7},
        'audit': {'log': str(d / 'audit.jsonl')},
    }
    path = d / 'scope.yaml'
    path.write_text(yaml.safe_dump(cfg))
    return artex_gate.install(str(path))


# -- scope matching ---------------------------------------------------------
def test_scope_rules(tmp_path):
    p = tmp_path / 's.yaml'
    p.write_text(yaml.safe_dump({
        'in_scope': ['example.com', '*.example.com', '203.0.113.0/24'],
        'out_of_scope': ['*.corp.example.com', 'status.example.com', 'https://www.example.com/admin*'],
        'passive_sources': ['crt.sh'],
        'identity': {'user_agent': 'x'},
    }))
    s = Scope.load(str(p))
    assert s.check('example.com').verdict == 'in'
    assert s.check('https://a.b.example.com/x').verdict == 'in'
    assert s.check('EXAMPLE.COM.').verdict == 'in'
    assert s.check('notexample.com').verdict == 'out'
    assert s.check('example.com.evil.net').verdict == 'out'
    assert s.check('vpn.corp.example.com').verdict == 'out'
    assert s.check('status.example.com:443').verdict == 'out'
    assert s.check('https://www.example.com/admin/users').verdict == 'out'
    assert s.check('https://www.example.com/app').verdict == 'in'
    assert s.check('203.0.113.9').verdict == 'in'
    assert s.check('203.0.114.9').verdict == 'out'
    assert s.check('https://crt.sh/?q=x').verdict == 'passive'


def test_scope_requires_in_scope_and_ua(tmp_path):
    p = tmp_path / 's.yaml'
    p.write_text(yaml.safe_dump({'in_scope': [], 'identity': {'user_agent': 'x'}}))
    with pytest.raises(ValueError):
        Scope.load(str(p))
    p.write_text(yaml.safe_dump({'in_scope': ['a.com']}))
    with pytest.raises(ValueError):
        Scope.load(str(p))


def test_violation_is_caught_by_existing_handlers():
    assert issubclass(artex_gate.HTTPScopeViolation, requests.RequestException)
    assert issubclass(artex_gate.HTTPScopeViolation, OSError)


# -- runtime enforcement ----------------------------------------------------
def test_in_scope_request_gets_identity_headers(guard, server):
    r = requests.get(f'http://{IN_HOST}:{server}/', headers={'User-Agent': 'random-ua'})
    seen = r.json()
    assert seen['User-Agent'] == 'ARTEX-test/1.0'
    assert seen['X-Bug-Bounty'] == 'tester'


def test_out_of_scope_request_blocked(guard, server):
    with pytest.raises(artex_gate.HTTPScopeViolation):
        requests.get(f'http://{OUT_HOST}:{server}/')


def test_out_of_scope_url_glob_blocked(guard, server):
    with pytest.raises(artex_gate.HTTPScopeViolation):
        requests.get(f'http://localhost:{server}/admin/panel')


def test_redirect_hop_to_out_of_scope_blocked(guard, server):
    with pytest.raises(artex_gate.HTTPScopeViolation):
        requests.get(f'http://{IN_HOST}:{server}/redirect-out')


def test_raw_sockets_blocked(guard, server):
    with pytest.raises(artex_gate.ScopeViolation):
        socket.create_connection((OUT_HOST, server), timeout=2)
    s = socket.socket()
    try:
        with pytest.raises(artex_gate.ScopeViolation):
            s.connect((OUT_HOST, server))
        assert s.connect_ex((OUT_HOST, server)) == errno.EACCES
    finally:
        s.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(artex_gate.ScopeViolation):
            u.sendto(b'x', (OUT_HOST, 53))
    finally:
        u.close()


def test_raw_http_carries_identity(guard, server):
    with socket.create_connection((IN_HOST, server), timeout=2) as c:
        c.sendall(f'GET / HTTP/1.1\r\nHost: x\r\n{artex_gate.raw_identity_headers()}Connection: close\r\n\r\n'.encode())
        data = b''
        while chunk := c.recv(4096):
            data += chunk
    assert b'ARTEX-test/1.0' in data and b'tester' in data


def test_hostname_resolved_ip_allowed(guard, server):
    # localhost is in scope by name; its resolved IP is then allowed at the socket layer
    assert requests.get(f'http://localhost:{server}/').status_code == 200


def test_rate_limit_is_global_across_threads(guard, server):
    n = 10
    start = time.monotonic()
    threads = [threading.Thread(target=requests.get, args=(f'http://{IN_HOST}:{server}/',)) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    # burst 1 at 5 rps -> n requests need at least (n-1)/5 seconds
    assert elapsed >= (n - 1) / 5 - 0.1


def test_nmap_targets_gated_and_rate_limited(guard):
    with pytest.raises(artex_gate.ScopeViolation):
        nmap.PortScanner.scan(None, hosts=OUT_HOST, ports='80')
    with pytest.raises(artex_gate.ScopeViolation):
        nmap.PortScanner.scan(None, hosts='127.0.0.0/24', ports='80')
    nmap.PortScanner.scan(None, hosts=IN_HOST, ports='80', arguments='-sT')
    hosts, args = nmap_calls[-1]
    assert hosts == IN_HOST and '--max-rate 7' in args and 'http.useragent=ARTEX-test/1.0' in args


def test_audit_log_records_blocks(guard):
    lines = [json.loads(line) for line in open(guard.audit_path)]
    assert any(e['verdict'] == 'out' and OUT_HOST in e['target'] for e in lines)
    assert any(e['verdict'] == 'in' for e in lines)

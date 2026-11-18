# artex_gate/__main__.py
"""Gated entry points for ARTEX (used directly or by the Hermes `artex-recon` skill).

  python -m artex_gate check  --scope scopes/acme.yaml https://a.acme.com 10.0.0.5
  python -m artex_gate fetch  --scope scopes/acme.yaml https://a.acme.com/robots.txt
  python -m artex_gate scan   --scope scopes/acme.yaml acme.com --intensity light --out out/acme.json
  python -m artex_gate serve  --scope scopes/acme.yaml          # Flask UI on 127.0.0.1:5000

Exit codes: 0 ok / all in scope, 2 passive-only target, 3 out of scope, 1 other error.
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from .guard import REPO_ROOT, install
from .scope import IN, OUT, Scope

MODULES = ['subdomains', 'email', 'ports', 'dns', 'real_ip', 'ssl', 'tech', 'ai']


def _load_app():
    sys.path.insert(0, str(REPO_ROOT))
    import app as artex_app
    return artex_app


def cmd_check(args):
    scope = Scope.load(args.scope)
    worst = 0
    rows = []
    for target in args.targets:
        d = scope.check(target)
        rows.append({'target': target, 'verdict': d.verdict, 'reason': d.reason})
        worst = max(worst, {IN: 0, OUT: 3}.get(d.verdict, 2))
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['verdict'].upper():8} {r['target']}  ({r['reason']})")
    return worst


def cmd_fetch(args):
    guard = install(args.scope)
    d = guard.scope.check(args.url)
    if d.verdict != IN:
        print(f'[artex-gate] refused: {args.url} is {d.verdict} ({d.reason})', file=sys.stderr)
        return 3 if d.verdict == OUT else 2
    import requests
    headers = dict(h.split(':', 1) for h in args.header) if args.header else {}
    resp = requests.request(args.method, args.url, headers={k.strip(): v.strip() for k, v in headers.items()},
                            timeout=args.timeout, verify=not args.insecure, allow_redirects=args.follow)
    print(f'HTTP {resp.status_code} {resp.reason}  {resp.url}')
    for k, v in resp.headers.items():
        print(f'{k}: {v}')
    if args.method.upper() != 'HEAD':
        print()
        print(resp.text[:args.max_body])
    return 0


def cmd_scan(args):
    guard = install(args.scope)
    d = guard.scope.check_host(args.domain)
    if d.verdict != IN:
        print(f'[artex-gate] refused: root domain {args.domain} is {d.verdict} ({d.reason})', file=sys.stderr)
        return 3 if d.verdict == OUT else 2
    artex_app = _load_app()
    options = {m: m not in args.skip for m in MODULES}
    # AIAnalyst only emits canned rule-based text; the calling agent does the analysis
    options['ai'] = args.with_ai and 'ai' not in args.skip
    options['intensity'] = args.intensity
    options['port_scan_choice'] = args.port_scan_choice
    client = artex_app.app.test_client()
    resp = client.post('/start_scan', json={'domain': args.domain, 'options': options})
    if resp.status_code != 200:
        print(f'[artex-gate] start_scan failed: {resp.status_code} {resp.get_data(as_text=True)}', file=sys.stderr)
        return 1
    scan_id = resp.get_json()['scan_id']
    last = None
    while artex_app.scan_status[scan_id]['status'] == 'running':
        task = artex_app.scan_status[scan_id]['current_task']
        if task != last:
            print(f"[{artex_app.scan_status[scan_id]['progress']:3}%] {task}", file=sys.stderr)
            last = task
        time.sleep(1)
    status = artex_app.scan_status[scan_id]
    result = artex_app.scan_results[scan_id]
    result['gate'] = _audit_summary(guard)
    out = Path(args.out) if args.out else REPO_ROOT / 'out' / f'{args.domain}-{scan_id[:8]}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print(json.dumps({'scan_id': scan_id, 'status': status['status'], 'error': status.get('error'),
                      'duration': status.get('duration'), 'report': str(out), 'gate': result['gate']}, indent=2))
    return 0 if status['status'] == 'completed' else 1


def _audit_summary(guard):
    if not guard.audit_path or not guard.audit_path.exists():
        return {}
    verdicts, blocked = Counter(), Counter()
    with open(guard.audit_path) as f:
        for line in f:
            e = json.loads(line)
            if e.get('program') != guard.scope.program:
                continue
            verdicts[e['verdict']] += 1
            if e['verdict'] == OUT:
                blocked[e['target']] += 1
    return {'audit_log': str(guard.audit_path), 'verdicts': dict(verdicts),
            'blocked_top': blocked.most_common(15)}


def cmd_serve(args):
    install(args.scope)
    artex_app = _load_app()
    artex_app.app.run(debug=False, host='127.0.0.1', port=args.port)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='artex_gate', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)

    c = sub.add_parser('check', help='classify targets as in/passive/out of scope')
    c.add_argument('targets', nargs='+')
    c.add_argument('--json', action='store_true')

    f = sub.add_parser('fetch', help='single gated HTTP request to an in-scope URL')
    f.add_argument('url')
    f.add_argument('-X', '--method', default='GET')
    f.add_argument('-H', '--header', action='append', help='extra header "Name: value"')
    f.add_argument('--follow', action='store_true', help='follow redirects (each hop is scope-checked)')
    f.add_argument('--insecure', action='store_true')
    f.add_argument('--timeout', type=float, default=10)
    f.add_argument('--max-body', type=int, default=4000)

    s = sub.add_parser('scan', help='run the full ARTEX pipeline behind the gate')
    s.add_argument('domain')
    s.add_argument('--intensity', choices=['light', 'normal', 'aggressive'], default='light')
    s.add_argument('--skip', nargs='*', default=[], choices=MODULES)
    s.add_argument('--port-scan-choice', choices=['all_subdomains', 'critical_only'], default='critical_only')
    s.add_argument('--with-ai', action='store_true', help="also run ARTEX's built-in AIAnalyst (off by default)")
    s.add_argument('--out')

    v = sub.add_parser('serve', help='run the ARTEX web UI behind the gate (127.0.0.1 only)')
    v.add_argument('--port', type=int, default=5000)

    for sp in (c, f, s, v):
        sp.add_argument('--scope', required=False, help='scope YAML (default: $ARTEX_SCOPE)')

    args = p.parse_args(argv)
    if not args.scope:
        import os
        args.scope = os.environ.get('ARTEX_SCOPE')
        if not args.scope:
            p.error('--scope or ARTEX_SCOPE is required')
    try:
        return {'check': cmd_check, 'fetch': cmd_fetch, 'scan': cmd_scan, 'serve': cmd_serve}[args.cmd](args)
    except ValueError as e:
        print(f'[artex-gate] {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

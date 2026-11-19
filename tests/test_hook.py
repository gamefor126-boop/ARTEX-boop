import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / 'hermes' / 'artex-scope-gate.py'


@pytest.fixture
def repo(tmp_path):
    (tmp_path / 'artex_gate').symlink_to(REPO / 'artex_gate')
    scopes = tmp_path / 'scopes'
    scopes.mkdir()
    (scopes / 'acme.yaml').write_text(yaml.safe_dump({
        'program': 'acme',
        'in_scope': ['acme.com', '*.acme.com', '203.0.113.0/24'],
        'out_of_scope': ['*.corp.acme.com'],
        'passive_sources': ['crt.sh'],
        'identity': {'user_agent': 'x'},
    }))
    (scopes / 'active.yaml').symlink_to('acme.yaml')
    return tmp_path


def run(repo, tool, tool_input, cwd=None):
    payload = {'hook_event_name': 'pre_tool_call', 'tool_name': tool, 'tool_input': tool_input,
               'cwd': str(cwd or repo)}
    env = {**os.environ, 'ARTEX_REPO': str(repo)}
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True,
                       text=True, env=env, timeout=20)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def blocked(result):
    return result.get('decision') == 'block'


@pytest.mark.parametrize('cmd', [
    'curl -s https://api.acme.com/',                       # in scope but bypasses gate
    'curl https://vpn.corp.acme.com/',                     # explicit exclusion
    'curl https://random.acme.com.evil.net/ && curl https://shop.acme.com',
    'wget -q -O- http://203.0.113.5/',                     # in-scope IP, still direct
    'curl http://8.8.4.4/',                                # public IP not in scope
    'nmap -sV api.acme.com',                               # attack tool
    'which nmap && nmap -sV api.acme.com',
    'cd /tmp && nuclei -u https://example.org',            # attack tool, any target
    'python -m artex_gate scan acme.com --scope /tmp/evil.yaml',
    'ARTEX_SCOPE=/tmp/evil.yaml python app.py',
    'echo "in_scope: [\'*\']" > scopes/active.yaml',
    'sed -i s/acme/evil/ scopes/acme.yaml',
    'ln -sf /tmp/evil.yaml scopes/active.yaml',
    'rm -rf artex_gate',
    "python3 -c \"import requests; requests.get('https://shop.acme.com')\"",
])
def test_terminal_blocked(repo, cmd):
    assert blocked(run(repo, 'terminal', {'command': cmd})), cmd


@pytest.mark.parametrize('cmd', [
    '.venv/bin/python -m artex_gate scan acme.com --scope scopes/active.yaml --intensity light 2>&1 | tail -20',
    '.venv/bin/python -m artex_gate fetch --scope scopes/active.yaml https://api.acme.com/robots.txt',
    'cat scopes/active.yaml',
    'curl -sL https://github.com/projectdiscovery/nuclei/releases',
    'curl "https://crt.sh/?q=%.acme.com&output=json"',
    'curl http://localhost:5000/health',
    'curl https://notacme.com/',
    'pip install requests',
    'jq . out/acme.com-1234.json',
    'which nmap nuclei',
    'command -v ffuf || echo missing',
])
def test_terminal_allowed(repo, cmd):
    assert not blocked(run(repo, 'terminal', {'command': cmd})), cmd


def test_write_file_to_scope_blocked(repo):
    assert blocked(run(repo, 'write_file', {'path': 'scopes/new.yaml', 'content': 'x'}))
    assert blocked(run(repo, 'patch', {'path': str(repo / 'artex_gate' / 'guard.py')}))
    assert not blocked(run(repo, 'write_file', {'path': 'notes/acme.md', 'content': 'x'}))


def test_web_and_browser_tools(repo):
    assert blocked(run(repo, 'web_extract', {'urls': ['https://api.acme.com/docs']}))
    assert blocked(run(repo, 'browser_cdp', {'url': 'https://vpn.corp.acme.com'}))
    assert not blocked(run(repo, 'web_extract', {'urls': ['https://docs.python.org/3/']}))


def test_execute_code(repo):
    assert blocked(run(repo, 'execute_code', {'code': "import requests\nrequests.get('https://shop.acme.com')"}))
    assert blocked(run(repo, 'execute_code', {'code': "open('scopes/active.yaml','w').write('x')"}))
    assert not blocked(run(repo, 'execute_code', {'code': "print('report for acme.com')"}))
    assert not blocked(run(repo, 'execute_code', {
        'code': "import artex_gate\nartex_gate.install('scopes/active.yaml')\nimport requests\nrequests.get('https://shop.acme.com')"}))


def test_skill_is_protected(repo):
    assert blocked(run(repo, 'skill_manage', {'action': 'edit', 'name': 'artex-recon'}))
    assert not blocked(run(repo, 'skill_manage', {'action': 'view', 'name': 'artex-recon'}))


def test_no_active_scope(repo):
    (repo / 'scopes' / 'active.yaml').unlink()
    assert blocked(run(repo, 'terminal', {'command': 'nmap example.org'}))
    assert not blocked(run(repo, 'terminal', {'command': 'curl https://github.com'}))


def test_symlinked_program_scope(repo, tmp_path_factory):
    prog = tmp_path_factory.mktemp('bb') / 'scope.yaml'
    prog.write_text((repo / 'scopes' / 'acme.yaml').read_text())
    (repo / 'scopes' / 'ext.yaml').symlink_to(prog)
    ok = '.venv/bin/python -m artex_gate scan acme.com --scope scopes/ext.yaml'
    assert not blocked(run(repo, 'terminal', {'command': ok}))
    assert blocked(run(repo, 'terminal', {'command': f'python -m artex_gate scan acme.com --scope {prog}'}))
    assert blocked(run(repo, 'write_file', {'path': str(prog), 'content': 'x'}))
    assert blocked(run(repo, 'terminal', {'command': f'sed -i s/a/b/ {prog}'}))


def test_relative_paths_with_gateway_cwd(repo, tmp_path_factory):
    # Regression: Hermes sends cwd=<gateway dir> (~/.hermes) while tools resolve relative
    # paths against the session workspace; a relative scope path must still be caught.
    gw = tmp_path_factory.mktemp('hermes_home')
    assert blocked(run(repo, 'patch', {'path': 'scopes/active.yaml', 'old_string': 'a', 'new_string': 'b'}, cwd=gw))
    assert blocked(run(repo, 'patch', {'mode': 'patch', 'patch': '*** Begin Patch\n*** Update File: scopes/acme.yaml\n@@\n-a\n+b\n*** End Patch'}, cwd=gw))
    assert blocked(run(repo, 'terminal', {'command': 'echo x >> scopes/acme.yaml', 'workdir': str(repo)}, cwd=gw))
    ok = '.venv/bin/python -m artex_gate check --scope scopes/active.yaml acme.com'
    assert not blocked(run(repo, 'terminal', {'command': ok, 'workdir': str(repo)}, cwd=gw))
    assert not blocked(run(repo, 'terminal', {'command': f'cd {repo} && {ok}'}, cwd=gw))
    assert not blocked(run(repo, 'patch', {'path': 'notes.md', 'old_string': 'a', 'new_string': 'b'}, cwd=gw))

#!/usr/bin/env bash
# Install the artex-recon skill and the artex-scope-gate pre_tool_call hook into Hermes.
# Re-runnable. Usage: hermes/install.sh [--approve]   (--approve adds the hook to the
# shell-hook allowlist so the non-interactive gateway loads it without a TTY prompt)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
HOOK_PATH="$HERMES_HOME/agent-hooks/artex-scope-gate.py"
# Hermes runs hooks with its own python, which lacks PyYAML - use the ARTEX venv
HOOK_CMD="$REPO/.venv/bin/python $HOOK_PATH"
CONFIG="$HERMES_HOME/config.yaml"

mkdir -p "$HERMES_HOME/skills/security/artex-recon" "$HERMES_HOME/agent-hooks"
cp "$REPO/hermes/skills/artex-recon/SKILL.md" "$HERMES_HOME/skills/security/artex-recon/SKILL.md"
chmod +x "$REPO/hermes/artex-scope-gate.py"
ln -sfn "$REPO/hermes/artex-scope-gate.py" "$HOOK_PATH"
echo "skill  -> $HERMES_HOME/skills/security/artex-recon/SKILL.md"
echo "hook   -> $HOOK_PATH"

if grep -qF "command: \"$HOOK_CMD\"" "$CONFIG"; then
  echo "config -> hook already configured in $CONFIG"
elif grep -q 'artex-scope-gate.py' "$CONFIG"; then
  cp "$CONFIG" "$CONFIG.bak-artex-$(date -u +%Y%m%dT%H%M%SZ)"
  sed -i "s|command: \".*artex-scope-gate.py\"|command: \"$HOOK_CMD\"|" "$CONFIG"
  echo "config -> updated hook command in $CONFIG"
elif grep -qE '^hooks:' "$CONFIG"; then
  echo "config -> $CONFIG already has a hooks: block; add this entry under pre_tool_call manually:"
  printf '    - matcher: "%s"\n      command: "%s"\n      timeout: 15\n      fail_closed: true\n' \
    'terminal|process|execute_code|web_extract|browser_.*|write_file|patch|skill_manage' "$HOOK_CMD"
else
  cp "$CONFIG" "$CONFIG.bak-artex-$(date -u +%Y%m%dT%H%M%SZ)"
  cat >> "$CONFIG" <<EOF

# --- artex-scope-gate (installed by ARTEX-boop/hermes/install.sh) ---
hooks:
  pre_tool_call:
    - matcher: "terminal|process|execute_code|web_extract|browser_.*|write_file|patch|skill_manage"
      command: "$HOOK_CMD"
      timeout: 15
      fail_closed: true
EOF
  echo "config -> appended hooks: block to $CONFIG (backup saved next to it)"
fi

if [[ "${1:-}" == "--approve" ]]; then
  python3 - "$HERMES_HOME/shell-hooks-allowlist.json" "$HOOK_CMD" <<'PY'
import json, sys
from pathlib import Path
path, cmd = Path(sys.argv[1]), sys.argv[2]
data = json.loads(path.read_text()) if path.exists() else {}
approvals = data.setdefault('approvals', [])
if not any(a.get('event') == 'pre_tool_call' and a.get('command') == cmd for a in approvals):
    approvals.append({'event': 'pre_tool_call', 'command': cmd})
path.write_text(json.dumps(data, indent=2) + '\n')
print(f'allow  -> {path}')
PY
fi

[[ -e "$REPO/scopes/active.yaml" ]] || echo "NOTE: no active scope yet: cp scopes/example.yaml scopes/<program>.yaml && ln -s <program>.yaml scopes/active.yaml"

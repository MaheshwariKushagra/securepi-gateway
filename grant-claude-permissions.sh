#!/bin/bash
# Grants Claude Code standing permission for the SecurePi gateway workflow:
# SSH/SCP to the gateway (192.168.2.5) and the local git credential-helper
# setup, so deploys and status checks don't need approval every time.
#
# This edits ~/.claude/settings.json, which applies to ALL Claude Code
# projects and sessions on this Mac, not just this one - review the rules
# below before running.
#
# Safe to re-run: merges into the existing file without duplicating entries
# or touching any other settings already there (e.g. your default model).

set -euo pipefail

SETTINGS="$HOME/.claude/settings.json"
mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"

python3 - "$SETTINGS" <<'PYEOF'
import json
import sys

path = sys.argv[1]
with open(path) as f:
    settings = json.load(f)

settings.setdefault("permissions", {}).setdefault("allow", [])
rules = settings["permissions"]["allow"]

new_rules = [
    # SSH/SCP to the gateway - status checks, and deploying updated app
    # files under /opt/securepi/ via a staged copy + sudo cp.
    "Bash(ssh maheshwari@192.168.2.5:*)",
    "Bash(scp:*)",
    # Persisting the GitHub token in macOS Keychain via git's own
    # credential helper, instead of re-pasting it for every push.
    "Bash(git credential-osxkeychain:*)",
    "Bash(git config --local credential.helper:*)",
]

added = [r for r in new_rules if r not in rules]
rules.extend(added)

with open(path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")

if added:
    print("Added permission rules:")
    for r in added:
        print("  -", r)
else:
    print("All rules were already present - nothing changed.")
PYEOF

echo
echo "Updated: $SETTINGS"
echo "Start a new Claude Code session for the change to take effect."

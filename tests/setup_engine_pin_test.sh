#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
setup="$repo_root/src/opnsense/scripts/OPNsense/Zapret/setup.sh"
service="$repo_root/src/opnsense/scripts/OPNsense/Zapret/zapret_service.sh"

# The setup script must use the reviewed zapret2 release/commit.
grep -qF 'ZAPRET2_TAG="v1.0.6"' "$setup"
grep -qF 'ZAPRET2_COMMIT="221d7dff24bfec0cd5ac0a5070b8acef2008af3d"' "$setup"
grep -qF 'resolved_commit=$(git -C "$ZAPRET_DIR" rev-parse HEAD)' "$setup"
grep -qF 'if [ "$resolved_commit" != "$ZAPRET2_COMMIT" ]; then' "$setup"

# A fresh initialization must not recursively delete the existing zapret
# directory: it may hold user settings, hostlists, or IPSet files.
if grep -qF 'rm -rf "$ZAPRET_DIR"' "$setup"; then
    echo "setup removes the user-owned zapret directory" >&2
    exit 1
fi
grep -qF 'cp -Rn "$_clone_tmp"/. "$ZAPRET_DIR"/' "$setup"
grep -qF 'existing files conflict with tracked zapret2 engine files' "$setup"

# Ensure the ordinary service path does not disable PF or install the old
# unowned catch-all rule. These are important regression guards.
if grep -Eq 'pfctl[[:space:]]+-[de]([[:space:]]|$)' "$service"; then
    echo "service still disables or re-enables PF" >&2
    exit 1
fi
if grep -qF '65534 allow ip from any to any' "$service"; then
    echo "service still installs the unowned catch-all IPFW rule" >&2
    exit 1
fi

echo "setup pin/preservation tests: ok"

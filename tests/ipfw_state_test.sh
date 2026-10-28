#!/bin/sh
# Unit tests for reversible IPFW/pfil state handling. No real firewall commands.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HELPER="$ROOT/src/opnsense/scripts/OPNsense/Zapret/ipfw_state.sh"
TEST_TMP=/tmp
TEST_ROOT="$TEST_TMP/os-zapret2-ipfw-state-$$"
mkdir -p "$TEST_ROOT/bin"
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
export FAKE_ROOT="$TEST_ROOT"

cat > "$TEST_ROOT/bin/sysctl" <<'EOS'
#!/bin/sh
state="$FAKE_ROOT/sysctls"
if [ "$1" = "-n" ]; then
    grep -F "$2=" "$state" | cut -d= -f2-
    exit 0
fi
key=$(printf '%s\n' "$1" | cut -d= -f1)
value=$(printf '%s\n' "$1" | cut -d= -f2-)
tmp="$state.tmp"
grep -F -v "$key=" "$state" > "$tmp" || true
printf '%s=%s\n' "$key" "$value" >> "$tmp"
mv "$tmp" "$state"
EOS

cat > "$TEST_ROOT/bin/ipfw" <<'EOS'
#!/bin/sh
rules="$FAKE_ROOT/rules"
if [ "$1" = "list" ]; then
    [ "${FAIL_IPFW_LIST:-0}" = "1" ] && exit 1
    if [ "$#" -eq 1 ]; then cat "$rules"; exit 0; fi
    grep -E "^$2 " "$rules" || exit 0
    exit 0
fi
[ "$1" = "-q" ] && shift
case "$1" in
    add)
        shift
        rule="$1"
        shift
        printf '%s %s\n' "$rule" "$*" >> "$rules"
        ;;
    delete)
        shift
        rule="$1"
        grep -v -E "^$rule " "$rules" > "$rules.tmp" || true
        mv "$rules.tmp" "$rules"
        ;;
    *) echo "unexpected fake ipfw invocation: $*" >&2; exit 2 ;;
esac
EOS

cat > "$TEST_ROOT/bin/pfilctl" <<'EOS'
#!/bin/sh
state4="$FAKE_ROOT/order4"
state6="$FAKE_ROOT/order6"
if [ "$1" = "heads" ]; then
    printf 'inet IPv4\n'
    case "$(cat "$state4")" in
        before) printf 'Out pf:default-out\nOut ipfw:default\n' ;;
        after) printf 'Out ipfw:default\nOut pf:default-out\n' ;;
        absent) printf 'Out pf:default-out\n' ;;
    esac
    printf 'inet6 IPv6\n'
    case "$(cat "$state6")" in
        before) printf 'Out pf:default-out6\nOut ipfw:default6\n' ;;
        after) printf 'Out ipfw:default6\nOut pf:default-out6\n' ;;
        absent) printf 'Out pf:default-out6\n' ;;
    esac
    exit 0
fi
action="$1"
shift
placement=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) shift ;;
        -a) placement=before; shift ;;
        *) break ;;
    esac
done
hook="$1"
head="$2"
[ "$head" = "inet" ] && state="$state4" || state="$state6"
if [ "$action" = "unlink" ]; then
    printf 'absent\n' > "$state"
elif [ "$action" = "link" ]; then
    [ -n "$placement" ] || placement=after
    printf '%s\n' "$placement" > "$state"
else
    echo "unexpected fake pfilctl invocation: $action $*" >&2
    exit 2
fi
EOS
chmod +x "$TEST_ROOT/bin/sysctl" "$TEST_ROOT/bin/ipfw" "$TEST_ROOT/bin/pfilctl"
export PATH="$TEST_ROOT/bin:$PATH"

cat > "$FAKE_ROOT/sysctls" <<'EOS'
net.inet.ip.fw.enable=0
net.inet.ip.fw.one_pass=0
net.inet.ip.fw.default_to_accept=0
net.inet6.ip6.fw.enable=0
EOS
printf '65535 deny ip from any to any\n' > "$FAKE_ROOT/rules"
printf 'absent\n' > "$FAKE_ROOT/order4"
printf 'absent\n' > "$FAKE_ROOT/order6"

IPFW_STATE_FILE="$FAKE_ROOT/state"
IPFW_PASS4_MARKER="$FAKE_ROOT/pass4-owned"
IPFW_PASS6_MARKER="$FAKE_ROOT/pass6-owned"
IPFW_PASS4_RULE=65530
IPFW_PASS6_RULE=65531
IPFW_BIN="$TEST_ROOT/bin/ipfw"
SYSCTL_BIN="$TEST_ROOT/bin/sysctl"
PFILCTL_BIN="$TEST_ROOT/bin/pfilctl"
IPFW_MODULE_WAS_LOADED=1
RULE_BASE=19000
RULE_MAX=19010
SUPERVISOR_PIDFILE="$FAKE_ROOT/supervisor"
. "$HELPER"

# Disabled baseline: install temporary dual-stack pass-through, configure
# pfil without touching PF, then restore sysctls/rules to their exact baseline.
ipfw_state_capture
ipfw_state_ensure_passthrough
grep -q '^65530 allow ip from any to any$' "$FAKE_ROOT/rules"
grep -q '^65531 allow ip6 from any to any$' "$FAKE_ROOT/rules"
ipfw_state_configure
[ "$(cat "$FAKE_ROOT/order4")" = "before" ]
[ "$(cat "$FAKE_ROOT/order6")" = "before" ]
grep -q '^net.inet.ip.fw.enable=1$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet6.ip6.fw.enable=1$' "$FAKE_ROOT/sysctls"
ipfw_state_restore
! grep -q '^65530 ' "$FAKE_ROOT/rules"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
grep -q '^net.inet.ip.fw.enable=0$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet.ip.fw.one_pass=0$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet6.ip6.fw.enable=0$' "$FAKE_ROOT/sysctls"
[ ! -e "$IPFW_STATE_FILE" ]
[ "$(cat "$FAKE_ROOT/order4")" = "absent" ]
[ "$(cat "$FAKE_ROOT/order6")" = "absent" ]

# Failure to read the active ruleset must fail closed without installing passes.
ipfw_state_capture
export FAIL_IPFW_LIST=1
if ipfw_state_ensure_passthrough; then
    echo "expected refusal when ipfw list fails" >&2
    exit 1
fi
unset FAIL_IPFW_LIST
! grep -q '^65530 ' "$FAKE_ROOT/rules"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
ipfw_state_restore

# A disabled IPFW ruleset with pre-existing user rules must not be activated.
printf '65535 deny ip from any to any\n123 deny ip from any to any\n' > "$FAKE_ROOT/rules"
ipfw_state_capture
if ipfw_state_ensure_passthrough; then
    echo "expected refusal to activate a non-empty disabled IPFW ruleset" >&2
    exit 1
fi
! grep -q '^65530 ' "$FAKE_ROOT/rules"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
ipfw_state_restore

# When IPFW was already enabled, don't install catch-all pass rules; restore
# the original hook order and existing sysctl values after the temporary move.
cat > "$FAKE_ROOT/sysctls" <<'EOS'
net.inet.ip.fw.enable=1
net.inet.ip.fw.one_pass=0
net.inet.ip.fw.default_to_accept=0
net.inet6.ip6.fw.enable=1
EOS
printf '65535 deny ip from any to any\n123 deny ip from any to any\n' > "$FAKE_ROOT/rules"
printf 'after\n' > "$FAKE_ROOT/order4"
printf 'after\n' > "$FAKE_ROOT/order6"
ipfw_state_capture
ipfw_state_ensure_passthrough
! grep -q '^65530 ' "$FAKE_ROOT/rules"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
ipfw_state_configure
[ "$(cat "$FAKE_ROOT/order4")" = "before" ]
ipfw_state_restore
[ "$(cat "$FAKE_ROOT/order4")" = "after" ]
[ "$(cat "$FAKE_ROOT/order6")" = "after" ]
grep -q '^net.inet.ip.fw.enable=1$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet.ip.fw.one_pass=0$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet6.ip6.fw.enable=1$' "$FAKE_ROOT/sysctls"
grep -q '^123 deny ip from any to any$' "$FAKE_ROOT/rules"

# IPv4 IPFW may already be active while IPv6 IPFW is disabled. Do not enable
# IPv6 and accidentally activate dormant administrator rules.
cat > "$FAKE_ROOT/sysctls" <<'EOS'
net.inet.ip.fw.enable=1
net.inet.ip.fw.one_pass=0
net.inet.ip.fw.default_to_accept=0
net.inet6.ip6.fw.enable=0
EOS
printf '65535 deny ip from any to any\n123 deny ip6 from any to any\n' > "$FAKE_ROOT/rules"
printf 'after\n' > "$FAKE_ROOT/order4"
printf 'absent\n' > "$FAKE_ROOT/order6"
IPFW_MODULE_WAS_LOADED=1
ipfw_state_capture
ipfw_state_ensure_passthrough
if ipfw_state_configure; then
    echo "expected refusal to enable IPv6 IPFW while unrelated rules exist" >&2
    exit 1
fi
grep -q '^net.inet.ip.fw.enable=1$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet6.ip6.fw.enable=0$' "$FAKE_ROOT/sysctls"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
ipfw_state_restore
grep -q '^123 deny ip6 from any to any$' "$FAKE_ROOT/rules"

# When IPFW was not loaded before service start, keep the post-load default
# one_pass value stable, then disable v4/v6 IPFW and remove our temporary rules.
cat > "$FAKE_ROOT/sysctls" <<'EOS'
net.inet.ip.fw.enable=0
net.inet.ip.fw.one_pass=0
net.inet.ip.fw.default_to_accept=0
net.inet6.ip6.fw.enable=0
EOS
printf '65535 deny ip from any to any\n' > "$FAKE_ROOT/rules"
printf 'absent\n' > "$FAKE_ROOT/order4"
printf 'absent\n' > "$FAKE_ROOT/order6"
IPFW_MODULE_WAS_LOADED=0
ipfw_state_capture
ipfw_state_ensure_passthrough
ipfw_state_configure
ipfw_state_restore
grep -q '^net.inet.ip.fw.enable=0$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet.ip.fw.one_pass=0$' "$FAKE_ROOT/sysctls"
grep -q '^net.inet6.ip6.fw.enable=0$' "$FAKE_ROOT/sysctls"
! grep -q '^65530 ' "$FAKE_ROOT/rules"
! grep -q '^65531 ' "$FAKE_ROOT/rules"
[ ! -e "$IPFW_STATE_FILE" ]

echo "IPFW state rollback tests: ok"

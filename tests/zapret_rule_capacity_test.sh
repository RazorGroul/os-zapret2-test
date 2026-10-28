#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
service="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/zapret_service.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/zapret-rule-capacity.XXXXXX")
ipfw_log="${test_root}/ipfw.log"
fake_ipfw="${test_root}/ipfw"

cleanup()
{
    rm -rf "${test_root}"
}
trap cleanup EXIT INT TERM HUP

cat > "${fake_ipfw}" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "${ipfw_log}"
exit 0
EOF
chmod +x "${fake_ipfw}"

RULE_BASE=19000
RULE_MAX=19010
helpers=$(sed -n '/^validate_strategy_arguments()/,/^start_service()/p' \
    "${service}" | sed '$d' | sed "s#/sbin/ipfw#${fake_ipfw}#g")
eval "${helpers}"

# This suite isolates UDP/ipfw behavior; full IPSet validation is exercised by
# tests/ipset_validation_test.sh.
validate_ipset_configuration()
{
    IPSET_ARGS=""
    return 0
}

# install_ipfw_rules normally clears its reserved range; the fake log has no
# external rules, so make cleanup a no-op for these isolated command tests.
remove_ipfw_rules()
{
    :
}

SOURCE_NETS=""
DIVERT_PORT=989
UDP_PORTS=""
UDP_FILTER_L7=""
UDP_ARGS=""
YOUTUBE_TCP_ENABLED="0"
YOUTUBE_TCP_ARGS=""
YOUTUBE_QUIC_ENABLED="0"
YOUTUBE_QUIC_ARGS=""
DISCORD_TCP_ENABLED="0"
DISCORD_TCP_ARGS=""
YOUTUBE_HOSTLIST="${test_root}/youtube-hostlist.txt"
DISCORD_HOSTLIST="${test_root}/discord-hostlist.txt"
printf '%s\n' 'youtube.com' > "${YOUTUBE_HOSTLIST}"
printf '%s\n' 'discord.com' > "${DISCORD_HOSTLIST}"

# Validate TCP ports independently of the firewall: reject malformed and
# out-of-range values, normalize leading zeroes, and deduplicate repeats.
PORTS="080,443,443"
validate_tcp_ports
test "${PORTS}" = "80,443"
for invalid_ports in "0" "65536" "80,,443" "80," "abc"; do
    PORTS="${invalid_ports}"
    if validate_tcp_ports >/dev/null 2>&1; then
        echo "invalid TCP port list unexpectedly accepted: ${invalid_ports}" >&2
        exit 1
    fi
done
PORTS="80,443"

# The managed YouTube TCP profile must cause TCP/443 to be intercepted even
# when the generic Ports field contains only port 80.
PORTS="80"
YOUTUBE_TCP_ENABLED="1"
YOUTUBE_TCP_ARGS="--payload=tls_client_hello --lua-desync=fake:repeats=2 --out-range=-d10"
validate_ipfw_rule_capacity
test "${TCP_INTERCEPT_PORTS}" = "80,443"
YOUTUBE_TCP_ENABLED="0"
YOUTUBE_TCP_ARGS=""
PORTS="80,443"

# A YouTube-only QUIC strategy still needs the shared UDP/443 divert rule even
# when the generic QUIC strategy is left empty.
PORTS="80"
YOUTUBE_QUIC_ENABLED="1"
YOUTUBE_QUIC_ARGS="--payload=quic_initial --lua-desync=fake:repeats=2"
QUIC_ARGS=""
validate_ipfw_rule_capacity
install_ipfw_rules igc0
grep -qF 'add 19001 divert 989 udp from any to any 443 out not diverted not sockarg xmit igc0' "${ipfw_log}"
YOUTUBE_QUIC_ENABLED="0"
YOUTUBE_QUIC_ARGS=""
PORTS="80,443"
: > "${ipfw_log}"

# Managed TCP profiles add interception ports without requiring manual edits
# to the generic TCP port list.
PORTS="80,443"
DISCORD_TCP_ENABLED="1"
DISCORD_TCP_ARGS="--payload=tls_client_hello --lua-desync=fake:repeats=2"
QUIC_ARGS=""
validate_ipfw_rule_capacity
test "${TCP_INTERCEPT_PORTS}" = "80,443,2053,2083,2087,2096,8443"
install_ipfw_rules igc0
grep -qF 'add 19002 divert 989 tcp from any to any 2053 out not diverted not sockarg xmit igc0' "${ipfw_log}"
grep -qF 'add 19006 divert 989 tcp from any to any 8443 out not diverted not sockarg xmit igc0' "${ipfw_log}"
DISCORD_TCP_ENABLED="0"
DISCORD_TCP_ARGS=""
: > "${ipfw_log}"

PORTS="1,2,3,4,5,6,7,8,9,10,11"
QUIC_ARGS=""
validate_ipfw_rule_capacity

PORTS="1,2,3,4,5,6,7,8,9,10"
QUIC_ARGS="--payload=quic_initial"
install_ipfw_rules igc0

test "$(grep -c ' add ' "${ipfw_log}")" -eq 11
grep -qF 'add 19010 divert 989 udp' "${ipfw_log}"

: > "${ipfw_log}"
PORTS="1,2,3,4,5,6,7,8,9,10,11"
QUIC_ARGS="--payload=quic_initial"
if install_ipfw_rules igc0 2>/dev/null; then
    echo 'oversized TCP plus QUIC rule layout was accepted' >&2
    exit 1
fi
test ! -s "${ipfw_log}"

PORTS="1,2,3,4,5,6,7,8,9,10,11,12"
QUIC_ARGS=""
if validate_ipfw_rule_capacity 2>/dev/null; then
    echo 'oversized TCP rule layout was accepted' >&2
    exit 1
fi

# A custom UDP profile consumes one firewall rule regardless of the number
# of comma-separated UDP ports/ranges. Inputs are whitespace/zero normalized.
PORTS="1,2,3,4,5,6,7,8,9"
QUIC_ARGS="--payload=quic_initial"
UDP_PORTS=" 019294 - 019344, 50000-50100 "
UDP_FILTER_L7="Discord,STUN"
UDP_ARGS="--payload=stun --lua-desync=fake:repeats=6"
install_ipfw_rules igc0
grep -qF 'add 19010 divert 989 udp from any to any 19294-19344,50000-50100 out not diverted not sockarg xmit igc0' "${ipfw_log}"
test "${UDP_PORTS}" = "19294-19344,50000-50100"
test "${UDP_FILTER_L7}" = "discord,stun"

# Source Networks must produce both the client subnet rule and the separate
# firewall-originated rule, with the same normalized UDP ports.
: > "${ipfw_log}"
SOURCE_NETS="192.168.1.0/24"
PORTS="80,443"
QUIC_ARGS=""
UDP_PORTS="19294-19344,50000-50100"
UDP_FILTER_L7="discord,stun"
UDP_ARGS="--payload=stun,discord_ip_discovery --lua-desync=fake:repeats=2"
install_ipfw_rules igc0
grep -qF 'add 19002 divert 989 udp from 192.168.1.0/24 to any 19294-19344,50000-50100 out not diverted not sockarg xmit igc0' "${ipfw_log}"
grep -qF 'add 19002 divert 989 udp from me to any 19294-19344,50000-50100 out not diverted not sockarg xmit igc0' "${ipfw_log}"
SOURCE_NETS=""

# Reserved rule-range exhaustion accounts for TCP, QUIC and custom UDP.
: > "${ipfw_log}"
PORTS="1,2,3,4,5,6,7,8,9,10"
QUIC_ARGS="--payload=quic_initial"
UDP_PORTS="19294-19344"
UDP_FILTER_L7="discord,stun"
UDP_ARGS="--payload=stun --lua-desync=fake:repeats=6"
if install_ipfw_rules igc0 2>/dev/null; then
    echo 'oversized TCP + QUIC + custom UDP layout was accepted' >&2
    exit 1
fi
test ! -s "${ipfw_log}"

expect_udp_invalid() {
    UDP_PORTS="$1"
    UDP_FILTER_L7="$2"
    UDP_ARGS="$3"
    QUIC_ARGS="$4"
    if validate_udp_configuration 2>/dev/null; then
        echo "invalid UDP settings unexpectedly accepted: ports=$1 l7=$2 args=$3 quic=$4" >&2
        exit 1
    fi
}
expect_udp_invalid "0" "discord,stun" "--lua-desync=fake" ""
expect_udp_invalid "65536" "discord,stun" "--lua-desync=fake" ""
expect_udp_invalid "19344-19294" "discord,stun" "--lua-desync=fake" ""
expect_udp_invalid "19294,,19344" "discord,stun" "--lua-desync=fake" ""
expect_udp_invalid "443" "quic" "--lua-desync=fake" "--payload=quic_initial"
expect_udp_invalid "19294-19344" "madeup" "--lua-desync=fake" ""
expect_udp_invalid "19294-19344" "discord,stun" "--lua-desync=fake;touch" ""
expect_udp_invalid "" "discord,stun" "--lua-desync=fake" ""
expect_udp_invalid "19294-19344" "discord,stun" "" ""

# FreeBSD ipfw limits a single comma-separated port list to 30 entries.
long_list="1"
i=2
while [ "$i" -le 31 ]; do
    long_list="${long_list},${i}"
    i=$((i + 1))
done
expect_udp_invalid "$long_list" "discord" "--lua-desync=fake" ""

# Non-QUIC UDP traffic has no reliable hostname to match. Ensure hostname
# hostlists are attached only to a pure QUIC UDP profile; IPSet filters remain
# available for all profiles to scope traffic by destination address.
grep -qF 'local udp_hostlist_args=""' "${service}"
grep -qF 'if [ "${UDP_FILTER_L7}" = "quic" ]; then' "${service}"
grep -qF 'udp_hostlist_args="${hostlist_noauto_args}"' "${service}"
if grep -qF '*,discord,*) udp_hostlist_args=' "${service}"; then
    echo 'Discord UDP profile must not use hostname hostlist filtering' >&2
    exit 1
fi
grep -qF 'args="${args} --new --filter-udp=${UDP_PORTS} --filter-l7=${UDP_FILTER_L7}${udp_hostlist_args}${IPSET_ARGS} ${UDP_ARGS}"' "${service}"

# Numeric range checks must reject extremely long values before test(1)
# attempts integer comparisons that could overflow the target shell.
huge=9
i=1
while [ "${i}" -lt 300 ]; do
    huge="${huge}9"
    i=$((i + 1))
done
expect_udp_invalid "${huge}" "discord,stun" "--lua-desync=fake" ""
PORTS="${huge}"
if validate_tcp_ports >/dev/null 2>&1; then
    echo 'oversized TCP port number unexpectedly passed validation' >&2
    exit 1
fi
PORTS="80,443"

# Invalid additional UDP settings must be rejected before any ipfw rule is added.
: > "${ipfw_log}"
PORTS="80,443"
QUIC_ARGS=""
UDP_PORTS="19294-19344"
UDP_FILTER_L7="discord,stun"
UDP_ARGS="--lua-desync=fake;touch"
if install_ipfw_rules igc0 2>/dev/null; then
    echo 'unsafe UDP strategy was accepted for rule installation' >&2
    exit 1
fi
test ! -s "${ipfw_log}"

echo 'zapret ipfw and UDP profile tests: ok'

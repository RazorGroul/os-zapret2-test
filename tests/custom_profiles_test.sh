#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
service="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/zapret_service.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/zapret-custom-profiles.XXXXXX")

cleanup()
{
    rm -rf "${test_root}"
}
trap cleanup EXIT INT TERM HUP

JQ_BIN=$(command -v jq 2>/dev/null || true)
if [ -z "${JQ_BIN}" ]; then
    echo "jq is required for custom profile tests" >&2
    exit 1
fi

# Load only pure validation/build helpers; do not run the real service or ipfw.
helpers=$(sed -n '/^validate_strategy_arguments()/,/^start_service()/p' "${service}" | sed '$d')
eval "${helpers}"

ZAPRET_DIR="${test_root}/zapret"
CUSTOM_PROFILES_FILE="${ZAPRET_DIR}/custom-profiles.json"
CUSTOM_PROFILE_LIST_DIR="${ZAPRET_DIR}/custom-hostlists"
HOSTLIST_EXCLUDE="${ZAPRET_DIR}/hostlist-exclude.txt"
IPSET_VALIDATOR="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/validate_ipset.awk"
IPSET_ARGS=""
IPSET_INCLUDE_ENABLED="0"
IPSET_EXCLUDE_ENABLED="0"
IPSET_INCLUDE_FILE="ipset-all.txt"
IPSET_EXCLUDE_FILE="ipset-exclude-default.txt"
PORTS="80,443"
UDP_PORTS=""
UDP_FILTER_L7=""
UDP_ARGS=""
QUIC_ARGS=""
HTTP_ARGS=""
HTTPS_ARGS=""
YOUTUBE_TCP_ENABLED="0"
YOUTUBE_QUIC_ENABLED="0"
DISCORD_TCP_ENABLED="0"
mkdir -p "${ZAPRET_DIR}"
printf '%s\n' "bank.example" > "${HOSTLIST_EXCLUDE}"

cat > "${CUSTOM_PROFILES_FILE}" <<'JSON'
[
  {
    "enabled": true,
    "name": "discord-voice",
    "order": 10,
    "transport": "udp",
    "ports": "019294 - 019344,50000-50100",
    "l7": ["discord", "stun"],
    "domains": [],
    "exclude_domains": [],
    "ipset": "inherit",
    "strategy": "--payload=stun,discord_ip_discovery --lua-desync=fake:blob=fake_default_quic:repeats=6"
  },
  {
    "enabled": true,
    "name": "custom-tls",
    "order": 20,
    "transport": "tcp",
    "ports": "08443-08444,443",
    "l7": ["tls"],
    "domains": ["example.com", "^exact.example"],
    "exclude_domains": ["private.example"],
    "ipset": "none",
    "strategy": "--payload=tls_client_hello --lua-desync=fake:repeats=2"
  },
  {
    "enabled": true,
    "name": "custom-quic",
    "order": 30,
    "transport": "udp",
    "ports": "443",
    "l7": ["quic"],
    "domains": ["video.example"],
    "exclude_domains": ["private-video.example"],
    "ipset": "inherit",
    "strategy": "--payload=quic_initial --lua-desync=fake:repeats=2"
  }
]
JSON

validate_custom_profiles
test "${CUSTOM_PROFILE_COUNT}" -eq 3
test "${CUSTOM_TCP_PORTS}" = "8443-8444,443"
test "${CUSTOM_UDP_PORTS}" = "19294-19344,50000-50100,443"

prepare_custom_profile_hostlists
voice_domains="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-discord-voice-domains.txt"
voice_excludes="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-discord-voice-exclude.txt"
tls_domains="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-custom-tls-domains.txt"
tls_excludes="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-custom-tls-exclude.txt"
quic_domains="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-custom-quic-domains.txt"
quic_excludes="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-custom-quic-exclude.txt"

test ! -e "${voice_domains}"
test ! -e "${voice_excludes}"
test -s "${tls_domains}"
grep -qF 'example.com' "${tls_domains}"
grep -qF '^exact.example' "${tls_domains}"
test -s "${tls_excludes}"
grep -qF 'bank.example' "${tls_excludes}"
grep -qF 'private.example' "${tls_excludes}"
test -s "${quic_domains}"
grep -qF 'video.example' "${quic_domains}"
grep -qF 'private-video.example' "${quic_excludes}"

TCP_INTERCEPT_PORTS=$(build_tcp_intercept_ports)
test "${TCP_INTERCEPT_PORTS}" = "80,443,8443-8444"
UDP_INTERCEPT_PORTS=$(build_udp_intercept_ports)
test "${UDP_INTERCEPT_PORTS}" = "19294-19344,50000-50100,443"

build_custom_profile_args
case "${CUSTOM_PROFILE_ARGS}" in
    *"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun"*) ;;
    *) echo "missing ordered Discord voice profile args" >&2; exit 1 ;;
esac
case "${CUSTOM_PROFILE_ARGS}" in
    *"--new --filter-tcp=8443-8444,443 --filter-l7=tls --hostlist=${tls_domains}"*) ;;
    *) echo "missing ordered TCP profile or its hostname list" >&2; exit 1 ;;
esac
case "${CUSTOM_PROFILE_ARGS}" in
    *"--new --filter-udp=443 --filter-l7=quic --hostlist=${quic_domains}"*) ;;
    *) echo "missing ordered QUIC profile or its hostname list" >&2; exit 1 ;;
esac
case "${CUSTOM_PROFILE_ARGS}" in
    *";"*|*"touch "*|*"--new;") echo "unsafe text reached the constructed argument string" >&2; exit 1 ;;
esac

# Integrate custom ports with capacity calculation. The UDP union is handled
# by one divert rule, while TCP ports continue to consume per-port rule slots.
validate_ipset_configuration()
{
    IPSET_ARGS=""
    return 0
}
RULE_BASE=19000
RULE_MAX=19010
DIVERT_PORT=989
SOURCE_NETS=""
validate_ipfw_rule_capacity
test "${TCP_INTERCEPT_PORTS}" = "80,443,8443-8444"
test "${UDP_INTERCEPT_PORTS}" = "19294-19344,50000-50100,443"

# A missing ipset selector defaults to inherit for less verbose JSON.
cat > "${CUSTOM_PROFILES_FILE}" <<'JSON'
[
  {"enabled":true,"name":"minimal","order":1,"transport":"tcp","ports":"8443","l7":["tls"],"strategy":"--payload=tls_client_hello --lua-desync=fake:repeats=1"}
]
JSON
validate_custom_profiles
build_custom_profile_args
case "${CUSTOM_PROFILE_ARGS}" in *"--filter-tcp=8443 --filter-l7=tls"*) ;; *) exit 1 ;; esac

expect_invalid()
{
    printf '%s\n' "$1" > "${CUSTOM_PROFILES_FILE}"
    if validate_custom_profiles >/dev/null 2>&1; then
        echo "invalid custom profile JSON was accepted: $1" >&2
        exit 1
    fi
}

expect_invalid 'not-json'
expect_invalid '[{"enabled":true,"name":"../escape","order":1,"transport":"tcp","ports":"443","l7":["tls"],"strategy":"--payload=tls --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"dup","order":1,"transport":"tcp","ports":"443","l7":["tls"],"strategy":"--payload=tls --lua-desync=fake"},{"enabled":true,"name":"dup","order":2,"transport":"tcp","ports":"8443","l7":["tls"],"strategy":"--payload=tls --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"order-a","order":1,"transport":"tcp","ports":"443","l7":["tls"],"strategy":"--payload=tls --lua-desync=fake"},{"enabled":true,"name":"order-b","order":1,"transport":"tcp","ports":"8443","l7":["tls"],"strategy":"--payload=tls --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"bad-l7","order":1,"transport":"udp","ports":"19344-19294","l7":["madeup"],"strategy":"--payload=quic --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"bad-range","order":1,"transport":"udp","ports":"19344-19294","l7":["discord"],"strategy":"--payload=stun --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"unsafe","order":1,"transport":"udp","ports":"19294-19344","l7":["discord"],"strategy":"--payload=stun;touch /tmp/x --lua-desync=fake"}]'
expect_invalid '[{"enabled":true,"name":"hostless-udp","order":1,"transport":"udp","ports":"19294-19344","l7":["discord","stun"],"domains":["voice.example"],"strategy":"--payload=stun --lua-desync=fake"}]'

huge=9
i=1
while [ "${i}" -lt 300 ]; do
    huge="${huge}9"
    i=$((i + 1))
done
printf '[{"enabled":true,"name":"huge-port","order":1,"transport":"udp","ports":"%s","l7":["discord"],"strategy":"--payload=stun --lua-desync=fake"}]\n' "${huge}" > "${CUSTOM_PROFILES_FILE}"
if validate_custom_profiles >/dev/null 2>&1; then
    echo "custom profile accepted an oversized numeric port" >&2
    exit 1
fi

cleanup_custom_profile_lists
test ! -d "${CUSTOM_PROFILE_LIST_DIR}"

echo "custom profile validation/build tests: ok"

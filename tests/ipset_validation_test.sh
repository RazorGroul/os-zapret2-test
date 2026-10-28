#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
service="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/zapret_service.sh"
validator="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/validate_ipset.awk"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/zapret-ipset-validation.XXXXXX")

cleanup()
{
    rm -rf "${test_root}"
}
trap cleanup EXIT INT TERM HUP

cat > "${test_root}/valid-include.txt" <<'EOF'
# sample include ranges
192.0.2.0/24
2001:db8::/32
::1
EOF

cat > "${test_root}/valid-exclude.txt" <<'EOF'
10.0.0.0/8
172.16.0.0/12
fc00::/7
fe80::/10
EOF

cat > "${test_root}/invalid.txt" <<'EOF'
192.168.1.0/24
999.1.1.1/24
EOF

awk -f "${validator}" "${test_root}/valid-include.txt"
awk -f "${validator}" "${test_root}/valid-exclude.txt"
if awk -f "${validator}" "${test_root}/invalid.txt" >/dev/null 2>&1; then
    echo 'malformed CIDR file unexpectedly passed validation' >&2
    exit 1
fi
: > "${test_root}/empty.txt"
if awk -f "${validator}" "${test_root}/empty.txt" >/dev/null 2>&1; then
    echo 'empty IPSet file unexpectedly passed validation' >&2
    exit 1
fi

helpers=$(sed -n '/^validate_ipset_filename()/,/^validate_udp_configuration()/p' "${service}" \
    | sed '$d' \
    | sed "s#/usr/local/opnsense/scripts/OPNsense/Zapret/validate_ipset.awk#${validator}#")
eval "${helpers}"

ZAPRET_DIR="${test_root}"
IPSET_VALIDATOR="${validator}"
IPSET_INCLUDE_ENABLED="1"
IPSET_INCLUDE_FILE="valid-include.txt"
IPSET_EXCLUDE_ENABLED="1"
IPSET_EXCLUDE_FILE="valid-exclude.txt"
validate_ipset_configuration

case "${IPSET_ARGS}" in
    *"--ipset=${test_root}/valid-include.txt"*) ;;
    *) echo 'include IPSet argument was not generated' >&2; exit 1 ;;
esac
case "${IPSET_ARGS}" in
    *"--ipset-exclude=${test_root}/valid-exclude.txt"*) ;;
    *) echo 'exclude IPSet argument was not generated' >&2; exit 1 ;;
esac

IPSET_INCLUDE_ENABLED="0"
IPSET_EXCLUDE_ENABLED="0"
validate_ipset_configuration
test -z "${IPSET_ARGS}"

IPSET_INCLUDE_ENABLED="1"
IPSET_INCLUDE_FILE="../invalid.txt"
if validate_ipset_configuration >/dev/null 2>&1; then
    echo 'path traversal in IPSet filename unexpectedly passed validation' >&2
    exit 1
fi

IPSET_INCLUDE_FILE="invalid.txt"
if validate_ipset_configuration >/dev/null 2>&1; then
    echo 'invalid IPSet file unexpectedly passed service validation' >&2
    exit 1
fi

IPSET_INCLUDE_FILE="missing.txt"
if validate_ipset_configuration >/dev/null 2>&1; then
    echo 'missing IPSet file unexpectedly passed service validation' >&2
    exit 1
fi

echo 'zapret IPSet validation tests: ok'

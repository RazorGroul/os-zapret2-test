#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
validator="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/validate_config.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/zapret-config-safety.XXXXXX")
marker="${test_root}/command-ran"

cleanup()
{
    rm -rf "${test_root}"
}
trap cleanup EXIT INT TERM HUP

safe_source()
{
    /bin/sh "${validator}" "$1" || return 1
    . "$1"
}

cat > "${test_root}/valid.conf" <<'EOF'
# generated configuration
ZAPRET_ENABLED="1"
ZAPRET_ENABLED="1"
WAN_IF="igc0"
DIVERT_PORT="989"
PORTS="80,443"
SOURCE_NETS="192.168.1.0/24"
HTTP_ARGS="--payload=http_req --lua-desync=fake"
HTTPS_ARGS="--payload=tls_client_hello --lua-desync=fake"
QUIC_ARGS=""
UDP_PORTS=""
UDP_FILTER_L7=""
UDP_ARGS=""
YOUTUBE_TCP_ENABLED="0"
YOUTUBE_TCP_ARGS=""
YOUTUBE_QUIC_ENABLED="0"
YOUTUBE_QUIC_ARGS=""
DISCORD_TCP_ENABLED="0"
DISCORD_TCP_ARGS=""
IPSET_INCLUDE_ENABLED="0"
IPSET_INCLUDE_FILE="ipset-all.txt"
IPSET_EXCLUDE_ENABLED="0"
IPSET_EXCLUDE_FILE="ipset-exclude-default.txt"
EXTRA_ARGS="--custom-path=/usr/local/etc/zapret2"
HOSTLIST_MODE="all"
HOSTLIST_USE_LEGACY_DOMAINS="0"
HOSTLIST_USE_LEGACY_EXCLUDES="0"
EOF

safe_source "${test_root}/valid.conf"
test "${WAN_IF}" = "igc0"
test "${HTTP_ARGS}" = "--payload=http_req --lua-desync=fake"

expect_rejected()
{
    config_path="$1"
    if /bin/sh "${validator}" "${config_path}" >/dev/null 2>&1; then
        echo "unsafe config was accepted: ${config_path}" >&2
        exit 1
    fi
    if safe_source "${config_path}" >/dev/null 2>&1; then
        echo "unsafe config was sourced: ${config_path}" >&2
        exit 1
    fi
    test ! -e "${marker}"
}

printf 'HTTP_ARGS="$(touch %s)"\n' "${marker}" > "${test_root}/dollar.conf"
expect_rejected "${test_root}/dollar.conf"

printf 'EXTRA_ARGS="`touch %s`"\n' "${marker}" > "${test_root}/backtick.conf"
expect_rejected "${test_root}/backtick.conf"

printf '%s\n' 'HTTP_ARGS="escaped\value"' > "${test_root}/backslash.conf"
expect_rejected "${test_root}/backslash.conf"

printf '%s\n' 'EXTRA_ARGS="--test=*"' > "${test_root}/glob-star.conf"
expect_rejected "${test_root}/glob-star.conf"

printf '%s\n' 'EXTRA_ARGS="--test=?"' > "${test_root}/glob-question.conf"
expect_rejected "${test_root}/glob-question.conf"

printf '%s\n' 'EXTRA_ARGS="--test=[abc]"' > "${test_root}/glob-bracket.conf"
expect_rejected "${test_root}/glob-bracket.conf"

printf 'HTTP_ARGS=""; touch %s; #"\n' "${marker}" > "${test_root}/quote-injection.conf"
expect_rejected "${test_root}/quote-injection.conf"

printf '%s\n' 'EVIL="not-a-plugin-setting"' > "${test_root}/unknown.conf"
expect_rejected "${test_root}/unknown.conf"

printf '%s\n' 'WAN_IF="igc0"' 'WAN_IF="igc1"' > "${test_root}/duplicate.conf"
expect_rejected "${test_root}/duplicate.conf"

grep -v '^HOSTLIST_MODE=' "${test_root}/valid.conf" > "${test_root}/missing-required.conf"
expect_rejected "${test_root}/missing-required.conf"

printf 'HTTP_ARGS="first line\nsecond line"\n' > "${test_root}/multiline.conf"
expect_rejected "${test_root}/multiline.conf"

: > "${test_root}/empty.conf"
expect_rejected "${test_root}/empty.conf"

# Generated config files have a hard size cap to avoid pathological source
# parsing or huge shell argument strings coming from a GUI field.
{
    printf 'EXTRA_ARGS="'
    printf '%65550s' '' | tr ' ' 'x'
    printf '"\n'
} > "${test_root}/oversized.conf"
expect_rejected "${test_root}/oversized.conf"

echo "zapret shell config safety tests: ok"

#!/bin/sh
# Validate the plugin-generated shell assignment file before any script sources it.
# Values remain double-quoted shell strings, so reject characters that can escape
# quoting or trigger parameter/command expansion. Unknown/duplicate names are not
# part of the generated config format and are rejected as well.

set -eu

CONFIG_FILE="${1:-}"
if [ -z "${CONFIG_FILE}" ] || [ ! -f "${CONFIG_FILE}" ] || [ -L "${CONFIG_FILE}" ]; then
    echo "zapret config validator: expected a regular config file" >&2
    exit 1
fi

config_bytes=$(wc -c < "${CONFIG_FILE}" | tr -d '[:space:]')
case "${config_bytes}" in
    ""|*[!0123456789]*)
        echo "zapret config validator: could not determine configuration size" >&2
        exit 1
        ;;
esac
if [ "${config_bytes}" -gt 65536 ]; then
    echo "zapret config validator: configuration exceeds 64 KiB safety limit" >&2
    exit 1
fi

LC_ALL=C awk '
function fail(message) {
    printf "zapret config validator: %s\n", message > "/dev/stderr"
    error = 1
    exit 1
}
function allowed(name) {
    return name ~ /^(ZAPRET_ENABLED|WAN_IF|DIVERT_PORT|PORTS|SOURCE_NETS|HTTP_ARGS|HTTPS_ARGS|QUIC_ARGS|UDP_PORTS|UDP_FILTER_L7|UDP_ARGS|YOUTUBE_TCP_ENABLED|YOUTUBE_TCP_ARGS|YOUTUBE_QUIC_ENABLED|YOUTUBE_QUIC_ARGS|DISCORD_TCP_ENABLED|DISCORD_TCP_ARGS|IPSET_INCLUDE_ENABLED|IPSET_INCLUDE_FILE|IPSET_EXCLUDE_ENABLED|IPSET_EXCLUDE_FILE|EXTRA_ARGS|HOSTLIST_MODE|HOSTLIST_USE_LEGACY_DOMAINS|HOSTLIST_USE_LEGACY_EXCLUDES)$/
}
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
{
    if ($0 !~ /^[A-Z_][A-Z0-9_]*="[^"]*"$/) {
        fail("invalid assignment syntax on line " NR)
    }

    eq = index($0, "=")
    name = substr($0, 1, eq - 1)
    value = substr($0, eq + 2, length($0) - eq - 2)

    if (!allowed(name)) {
        fail("unknown config variable " name)
    }
    if (name in seen) {
        fail("duplicate config variable " name)
    }
    # The template wraps values in double quotes. Inside those quotes, dollar
    # signs, backticks and backslashes can change shell evaluation; a double
    # quote or newline already fails the assignment grammar above.
    if (index(value, "$") || index(value, sprintf("%c", 96)) || index(value, sprintf("%c", 92))) {
        fail("unsafe shell expansion character in " name)
    }

    seen[name] = 1
    valid = 1
}
END {
    if (!valid && !error) exit 1
}
' "${CONFIG_FILE}"

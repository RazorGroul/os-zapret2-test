#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
script="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/test_domain.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/strategy-test-wan.XXXXXX")
state_dir="${test_root}/state"
log_dir="${test_root}/log"
bin_dir="${test_root}/bin"
ipfw_log="${test_root}/ipfw.log"

cleanup()
{
    rm -rf "${test_root}"
}
trap cleanup EXIT INT TERM HUP

mkdir -p "${state_dir}" "${log_dir}" "${bin_dir}" "${test_root}/zapret"

cat > "${test_root}/zapret/zapret.conf" <<'EOF'
WAN_IF="opt11"
EOF

cat > "${bin_dir}/drill" <<'EOF'
#!/bin/sh
cat <<'OUT'
;; ANSWER SECTION:
example.com. 60 IN A 192.0.2.10
;; AUTHORITY SECTION:
OUT
EOF

cat > "${bin_dir}/curl" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${bin_dir}/ifconfig" <<'EOF'
#!/bin/sh
[ "$1" = "opt11" ]
EOF

cat > "${bin_dir}/ipfw" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${IPFW_LOG}"
case "$*" in
    "list 18990")
        exit 0
        ;;
esac
exit 0
EOF

chmod +x "${bin_dir}/drill" "${bin_dir}/curl" \
    "${bin_dir}/ifconfig" "${bin_dir}/ipfw"

PATH="${bin_dir}:${PATH}" \
IPFW_LOG="${ipfw_log}" \
ZAPRET_DIR="${test_root}/zapret" \
ZAPRET_CONFIG_VALIDATOR="${repo_root}/src/opnsense/scripts/OPNsense/Zapret/validate_config.sh" \
DRILL="${bin_dir}/drill" \
CURL="${bin_dir}/curl" \
IPFW="${bin_dir}/ipfw" \
STRATEGY_TEST_STATE_DIR="${state_dir}" \
STRATEGY_TEST_LOG_DIR="${log_dir}" \
STRATEGY_TEST_ATTEMPTS=1 \
    /bin/sh "${script}" example.com >/dev/null

grep -qF 'add 18990 allow tcp from me to 192.0.2.10 443 out xmit opt11' \
    "${ipfw_log}"

if grep -qE 'xmit[[:space:]]+wan([[:space:]]|$)' "${ipfw_log}"; then
    echo 'strategy test ignored configured WAN interface' >&2
    exit 1
fi

echo 'strategy test WAN selection: ok'

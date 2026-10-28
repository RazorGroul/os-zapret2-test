#!/bin/sh

# test_domain.sh — test one HTTPS strategy against every IPv4 address
# returned for a domain. With a supplied strategy, an isolated dvtws2 instance
# handles only firewall-originated traffic to those addresses. With no
# strategy, a temporary allow rule bypasses the configured dvtws2 service.
#
# Usage: test_domain.sh <domain> [base64-encoded-strategy]
# An empty strategy tests direct connectivity without DPI bypass.

LC_ALL=C
export LC_ALL

ZAPRET_DIR="${ZAPRET_DIR:-/usr/local/etc/zapret2}"
CONFIG="${ZAPRET_CONFIG:-${ZAPRET_DIR}/zapret.conf}"
CONFIG_VALIDATOR="${ZAPRET_CONFIG_VALIDATOR:-/usr/local/opnsense/scripts/OPNsense/Zapret/validate_config.sh}"
DVTWS_BIN="${DVTWS_BIN:-${ZAPRET_DIR}/binaries/my/dvtws2}"
LUA_LIB="${LUA_LIB:-${ZAPRET_DIR}/lua/zapret-lib.lua}"
LUA_ANTIDPI="${LUA_ANTIDPI:-${ZAPRET_DIR}/lua/zapret-antidpi.lua}"
DRILL="${DRILL:-/usr/local/bin/drill}"
CURL="${CURL:-/usr/local/bin/curl}"
IPFW="${IPFW:-/sbin/ipfw}"
DAEMON="${DAEMON:-/usr/sbin/daemon}"
XARGS="${XARGS:-/usr/bin/xargs}"
BASE64="${BASE64:-/usr/bin/base64}"
STATE_DIR="${STRATEGY_TEST_STATE_DIR:-/var/run}"
LOG_DIR="${STRATEGY_TEST_LOG_DIR:-/var/log/zapret}"
ATTEMPTS="${STRATEGY_TEST_ATTEMPTS:-10}"
MAX_IPS=64
TEMP_RULE=18990
TEMP_PORT=1989
LOCK_DIR="${STATE_DIR}/zapret-strategy-test.lock"
TEMP_PIDFILE="${STATE_DIR}/zapret-strategy-test-dvtws.pid"
BLOCKCHECK_PIDFILE="${STATE_DIR}/zapret-blockcheck.pid"
SERVICE_PIDFILE="${STATE_DIR}/dvtws2.pid"

DOMAIN="$1"
STRATEGY_ENCODED="${2:-}"
RUN_DIR=""
LOG_FILE=""
DVTWS_LOG=""
WORKER_PIDS=""
TEMP_DVTWS_STARTED=0
TEMP_RULE_INSTALLED=0
LOCK_HELD=0

cleanup()
{
    for worker_pid in ${WORKER_PIDS}; do
        kill "${worker_pid}" 2>/dev/null || true
    done

    if [ "${TEMP_RULE_INSTALLED}" = "1" ]; then
        "${IPFW}" -q delete "${TEMP_RULE}" 2>/dev/null || true
    fi

    if [ "${TEMP_DVTWS_STARTED}" = "1" ] && [ -f "${TEMP_PIDFILE}" ]; then
        temp_pid=$(cat "${TEMP_PIDFILE}" 2>/dev/null)
        case "${temp_pid}" in
            ''|*[!0-9]*)
                ;;
            *)
                kill "${temp_pid}" 2>/dev/null || true
                ;;
        esac
    fi

    rm -f "${TEMP_PIDFILE}"
    if [ -n "${RUN_DIR}" ] && [ -d "${RUN_DIR}" ]; then
        rm -f "${RUN_DIR}"/*
        rmdir "${RUN_DIR}" 2>/dev/null || true
    fi

    if [ "${LOCK_HELD}" = "1" ]; then
        rm -f "${LOCK_DIR}/pid"
        rmdir "${LOCK_DIR}" 2>/dev/null || true
    fi
}

acquire_lock()
{
    if mkdir "${LOCK_DIR}" 2>/dev/null; then
        LOCK_HELD=1
        printf '%s\n' "$$" > "${LOCK_DIR}/pid"
        return 0
    fi

    lock_owner=$(cat "${LOCK_DIR}/pid" 2>/dev/null)
    case "${lock_owner}" in
        ''|*[!0-9]*)
            ;;
        *)
            if kill -0 "${lock_owner}" 2>/dev/null; then
                lock_command=$(ps -o command= -p "${lock_owner}" 2>/dev/null)
                case "${lock_command}" in
                    *test_domain.sh*)
                        return 1
                        ;;
                esac
            fi
            ;;
    esac

    rm -f "${LOCK_DIR}/pid"
    rmdir "${LOCK_DIR}" 2>/dev/null || return 1
    mkdir "${LOCK_DIR}" 2>/dev/null || return 1
    LOCK_HELD=1
    printf '%s\n' "$$" > "${LOCK_DIR}/pid"
}

trap cleanup EXIT
trap 'exit 1' INT TERM HUP

emit_error()
{
    message="$1"

    if [ -n "${LOG_FILE}" ]; then
        printf '\n=== ERROR ===\n%s\n' "${message}" >> "${LOG_FILE}"
        cleanup
        trap - EXIT
        cat "${LOG_FILE}"
    else
        printf 'ERROR: %s\n' "${message}"
    fi

    exit 1
}

valid_pidfile_process()
{
    pidfile="$1"
    command_pattern="$2"

    [ -f "${pidfile}" ] || return 1
    checked_pid=$(cat "${pidfile}" 2>/dev/null)

    case "${checked_pid}" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    kill -0 "${checked_pid}" 2>/dev/null || return 1
    checked_command=$(ps -o command= -p "${checked_pid}" 2>/dev/null)

    case "${checked_command}" in
        *"${command_pattern}"*)
            return 0
            ;;
    esac

    return 1
}

resolve_interface()
{
    iface="$1"

    if ifconfig "${iface}" >/dev/null 2>&1; then
        printf '%s\n' "${iface}"
        return
    fi

    if [ -x /usr/local/bin/jq ]; then
        resolved=$(/usr/local/sbin/pluginctl -4 "${iface}" 2>/dev/null \
            | /usr/local/bin/jq -r --arg if "${iface}" '.[$if][0].device // empty')
        if [ -n "${resolved}" ]; then
            printf '%s\n' "${resolved}"
            return
        fi
    fi

    printf '%s\n' "${iface}"
}

decode_strategy()
{
    if [ -z "${STRATEGY_ENCODED}" ]; then
        STRATEGY=""
        STRATEGY_SOURCE="direct connection (no strategy)"
        return
    fi

    if [ "${#STRATEGY_ENCODED}" -gt 8192 ] || \
       ! printf '%s' "${STRATEGY_ENCODED}" | grep -qE '^[A-Za-z0-9+/=]+$'; then
        emit_error "Invalid encoded strategy."
    fi

    if ! STRATEGY=$(printf '%s' "${STRATEGY_ENCODED}" | "${BASE64}" -d 2>/dev/null); then
        emit_error "Could not decode strategy."
    fi
    STRATEGY_SOURCE="supplied strategy"
}

validate_strategy()
{
    [ -n "${STRATEGY}" ] || return 0
    [ "${#STRATEGY}" -le 4096 ] || emit_error "Strategy is longer than 4096 characters."

    strategy_lines=$(printf '%s\n' "${STRATEGY}" | wc -l | tr -d '[:space:]')
    [ "${strategy_lines}" = "1" ] || emit_error "Strategy must be a single line."

    if LC_ALL=C printf '%s' "${STRATEGY}" | grep -q '[[:cntrl:]]'; then
        emit_error "Strategy contains control characters."
    fi

    case "${STRATEGY}" in
        --*)
            ;;
        *)
            emit_error "Strategy must contain dvtws2 arguments beginning with --."
            ;;
    esac

    # These options own the isolated test process or can escape its target-IP
    # scope. Profiles copied from blockcheck do not need them.
    if printf '%s\n' "${STRATEGY}" | grep -qE '(^|[[:space:]])--(port|sockarg|user|daemon|pidfile|filter-[^=[:space:]]*|hostlist[^=[:space:]]*|new)(=|[[:space:]]|$)'; then
        emit_error "Strategy contains an option managed by the test runner."
    fi

    if printf '%s\n' "${STRATEGY}" | grep -qE '(^|[[:space:]])--lua-(init|desync)=@'; then
        emit_error "Loading an external Lua file is not allowed in a strategy test."
    fi
}

test_ip()
{
    test_address="$1"
    output_file="$2"
    attempt=1
    passed=0

    while [ "${attempt}" -le "${ATTEMPTS}" ]; do
        if "${CURL}" -4 -sk \
            --connect-timeout 5 \
            --max-time 5 \
            --resolve "${DOMAIN}:443:${test_address}" \
            -o /dev/null \
            "https://${DOMAIN}/" >/dev/null 2>&1; then
            passed=$((passed + 1))
        fi

        attempt=$((attempt + 1))
    done

    printf '%d\n' "${passed}" > "${output_file}"
}

if [ -z "${DOMAIN}" ]; then
    emit_error "No domain specified."
fi

if ! printf '%s\n' "${DOMAIN}" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z]{2,}$'; then
    emit_error "Invalid domain format."
fi

if [ ! -r "${CONFIG}" ]; then
    emit_error "Zapret configuration not found; save plugin settings first."
fi
if [ ! -r "${CONFIG_VALIDATOR}" ] || ! /bin/sh "${CONFIG_VALIDATOR}" "${CONFIG}"; then
    emit_error "Zapret configuration is invalid or contains unsafe shell syntax; save the plugin settings again after updating the package."
fi

. "${CONFIG}"

if [ -z "${WAN_IF:-}" ]; then
    emit_error "WAN interface is not configured; save plugin settings first."
fi

case "${ATTEMPTS}" in
    ''|*[!0-9]*|0)
        emit_error "Invalid attempt count."
        ;;
esac

if ! acquire_lock; then
    emit_error "Another strategy test is already running."
fi

if valid_pidfile_process "${BLOCKCHECK_PIDFILE}" "blockcheck.sh"; then
    emit_error "Blockcheck is running; stop it before testing a specific strategy."
fi

mkdir -p "${LOG_DIR}"
timestamp=$(date '+%Y%m%d-%H%M%S')
LOG_FILE="${LOG_DIR}/strategy-test-${timestamp}-${DOMAIN}.log"
RUN_DIR=$(mktemp -d "${STATE_DIR}/zapret-strategy-test.XXXXXX") || \
    emit_error "Could not create strategy test state directory."
DVTWS_LOG="${RUN_DIR}/dvtws.log"

decode_strategy
validate_strategy

DNS_RESULT=$("${DRILL}" "${DOMAIN}" A 2>/dev/null | awk '
    /^;; ANSWER SECTION/ {in_ans=1; next}
    /^;;/ {in_ans=0}
    in_ans && $4=="A" {print $5}
' | sort -u)

[ -n "${DNS_RESULT}" ] || emit_error "No IPv4 addresses returned for ${DOMAIN}."
address_count=$(printf '%s\n' "${DNS_RESULT}" | wc -l | tr -d '[:space:]')
[ "${address_count}" -le "${MAX_IPS}" ] || \
    emit_error "DNS returned ${address_count} IPv4 addresses; safety limit is ${MAX_IPS}."

{
    echo "=== Zapret HTTPS Strategy Stability Test ==="
    echo "Domain: ${DOMAIN}"
    echo "Strategy source: ${STRATEGY_SOURCE}"
    if [ -n "${STRATEGY}" ]; then
        echo "Strategy: ${STRATEGY}"
    else
        echo "Strategy: none (direct)"
    fi
    echo "Attempts per IP: ${ATTEMPTS}"
} > "${LOG_FILE}"

if [ "${STRATEGY_TEST_SKIP_DVTWS:-0}" != "1" ]; then
    [ -x "${IPFW}" ] || emit_error "ipfw not found at ${IPFW}."

    # Rule 18990 and divert port 1989 are reserved for this diagnostic.
    existing_rule=$("${IPFW}" list "${TEMP_RULE}" 2>/dev/null || true)
    if [ -n "${existing_rule}" ]; then
        if printf '%s\n' "${existing_rule}" | \
           grep -qE "(divert ${TEMP_PORT}|allow) tcp from me"; then
            "${IPFW}" -q delete "${TEMP_RULE}" 2>/dev/null || true
        else
            emit_error "ipfw rule ${TEMP_RULE} is already used by another service."
        fi
    fi

    wan_device=$(resolve_interface "${WAN_IF}")
    [ -n "${wan_device}" ] || \
        emit_error "Could not resolve WAN interface ${WAN_IF}."

    if [ -n "${STRATEGY}" ]; then
        [ -x "${DVTWS_BIN}" ] || emit_error "dvtws2 binary not found at ${DVTWS_BIN}."
        [ -x "${DAEMON}" ] || emit_error "daemon utility not found at ${DAEMON}."

        if ! valid_pidfile_process "${SERVICE_PIDFILE}" "${DVTWS_BIN}"; then
            emit_error "Zapret service must be running before an isolated strategy test."
        fi

        # Recover a temporary process left by an uncleanly terminated earlier
        # test. A live lock owned by a real test was rejected above.
        if valid_pidfile_process "${TEMP_PIDFILE}" "--port=${TEMP_PORT}"; then
            stale_pid=$(cat "${TEMP_PIDFILE}" 2>/dev/null)
            kill "${stale_pid}" 2>/dev/null || true
            sleep 0.2
        fi
        rm -f "${TEMP_PIDFILE}"

        # xargs performs quote-aware argument splitting without invoking a
        # shell, so copied blockcheck strategies remain usable safely.
        if ! printf '%s\n' "${STRATEGY}" | "${XARGS}" \
            "${DAEMON}" -p "${TEMP_PIDFILE}" -o "${DVTWS_LOG}" -f \
            "${DVTWS_BIN}" \
            "--port=${TEMP_PORT}" \
            "--lua-init=@${LUA_LIB}" \
            "--lua-init=@${LUA_ANTIDPI}" \
            "--sockarg=0x200" \
            "--user=nobody" \
            "--filter-tcp=443"; then
            emit_error "Could not launch the temporary dvtws2 instance."
        fi

        launch_wait=0
        while [ "${launch_wait}" -lt 30 ]; do
            if valid_pidfile_process "${TEMP_PIDFILE}" "--port=${TEMP_PORT}"; then
                TEMP_DVTWS_STARTED=1
                break
            fi
            sleep 0.1
            launch_wait=$((launch_wait + 1))
        done

        [ "${TEMP_DVTWS_STARTED}" = "1" ] || {
            [ -s "${DVTWS_LOG}" ] && cat "${DVTWS_LOG}" >> "${LOG_FILE}"
            emit_error "Temporary dvtws2 exited during startup; check the strategy arguments."
        }
    fi

    for test_address in ${DNS_RESULT}; do
        if [ -n "${STRATEGY}" ]; then
            rule_action="divert ${TEMP_PORT}"
            rule_guard="not diverted not sockarg"
        else
            rule_action="allow"
            rule_guard=""
        fi

        if ! "${IPFW}" -q add "${TEMP_RULE}" ${rule_action} tcp \
            from me to "${test_address}" 443 out ${rule_guard} \
            xmit "${wan_device}"; then
            emit_error "Could not install temporary ipfw rule for ${test_address}."
        fi
        TEMP_RULE_INSTALLED=1
    done
fi

for test_address in ${DNS_RESULT}; do
    safe_address=$(printf '%s' "${test_address}" | tr -c '0-9A-Za-z.-' '_')
    test_ip "${test_address}" "${RUN_DIR}/result-${safe_address}" &
    WORKER_PIDS="${WORKER_PIDS} $!"
done

for worker_pid in ${WORKER_PIDS}; do
    wait "${worker_pid}" 2>/dev/null || true
done
WORKER_PIDS=""

total_passed=0
total_attempts=$((address_count * ATTEMPTS))

{
    echo ""
    echo "=== Results ==="
} >> "${LOG_FILE}"

for test_address in ${DNS_RESULT}; do
    safe_address=$(printf '%s' "${test_address}" | tr -c '0-9A-Za-z.-' '_')
    result_file="${RUN_DIR}/result-${safe_address}"
    passed=$(cat "${result_file}" 2>/dev/null || echo 0)
    case "${passed}" in
        ''|*[!0-9]*)
            passed=0
            ;;
    esac
    printf '%s - %d/%d successful\n' \
        "${test_address}" "${passed}" "${ATTEMPTS}" >> "${LOG_FILE}"
    total_passed=$((total_passed + passed))
done

if [ "${total_passed}" -eq "${total_attempts}" ]; then
    verdict="STABLE"
elif [ "${total_passed}" -eq 0 ]; then
    verdict="FAILED"
else
    verdict="UNSTABLE"
fi

success_percent=$((total_passed * 100 / total_attempts))
{
    echo ""
    echo "=== Overall Result: ${verdict} ==="
    echo "Successful TLS requests: ${total_passed}/${total_attempts} (${success_percent}%)"
    echo "Log file: ${LOG_FILE}"
} >> "${LOG_FILE}"

cleanup
trap - EXIT
cat "${LOG_FILE}"
exit 0

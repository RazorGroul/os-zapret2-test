#!/bin/sh

# blockcheck.sh — Non-interactive driver for upstream zapret2's blockcheck2.sh
#
# Runs blockcheck2 against a single domain, feeds its interactive prompts
# from stdin, captures the output, and returns the SUMMARY section as JSON.
# Used by the Diagnostics > Blockcheck page in the OPNsense GUI.
#
# Usage: blockcheck.sh <domain>
#
# Output (always JSON):
#   { "status": "ok",      "domain": "...", "summary": "<text>",
#     "winning": [...]  }
#   { "status": "error",   "message": "..." }

ZAPRET_DIR="/usr/local/etc/zapret2"
BLOCKCHECK="${ZAPRET_DIR}/blockcheck2.sh"
CONFIG="${ZAPRET_DIR}/zapret.conf"
CONFIG_VALIDATOR="/usr/local/opnsense/scripts/OPNsense/Zapret/validate_config.sh"
WINNER_PARSER="/usr/local/opnsense/scripts/OPNsense/Zapret/blockcheck_winners.awk"
JQ="/usr/local/bin/jq"

DOMAIN="${1:-}"

# Hard upper bound for a detached blockcheck run. The job controller is
# asynchronous, so configd's short action timeout cannot stop a hung upstream
# process for us. Callers may override this with BLOCKCHECK_TIMEOUT.
TIMEOUT="${BLOCKCHECK_TIMEOUT:-1500}"

MODE="${2:-all}"

case "${MODE}" in
    tls13)
        BC_HTTP=0
        BC_TLS12=0
        BC_TLS13=1
        BC_HTTP3=0
        ;;
    tls12)
        BC_HTTP=0
        BC_TLS12=1
        BC_TLS13=0
        BC_HTTP3=0
        ;;
    http)
        BC_HTTP=1
        BC_TLS12=0
        BC_TLS13=0
        BC_HTTP3=0
        ;;
    http3)
        BC_HTTP=0
        BC_TLS12=0
        BC_TLS13=0
        BC_HTTP3=1
        ;;
    all)
        BC_HTTP=1
        BC_TLS12=1
        BC_TLS13=1
        BC_HTTP3=1
        ;;
    *)
        BC_HTTP=1
        BC_TLS12=1
        BC_TLS13=1
        BC_HTTP3=1
        ;;
esac

# Wall-clock timestamps for the JSON output. ISO-8601 UTC for human
# readability; epoch for cheap duration math. We capture STARTED at
# script entry (before any work) and FINISHED right before the JSON
# is emitted, so duration_seconds reflects the full wrapper runtime
# including the configd-stop, ipfw-setup, blockcheck2, and the trap
# cleanup that runs before exit (well, mostly — trap fires AFTER
# this jq emits, but the duration is captured already).
STARTED_EPOCH=$(date -u +%s)
STARTED_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Emit an error JSON. Always includes timing so the caller can
# distinguish "instant validation rejection" (duration ~0s) from
# "blockcheck ran for 25 min then timed out" (duration ~1500s).
emit_error() {
    finished_epoch=$(date -u +%s)
    finished_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    duration=$((finished_epoch - STARTED_EPOCH))
    "${JQ}" -nc \
        --arg msg "$1" \
        --arg started "${STARTED_ISO}" \
        --arg finished "${finished_iso}" \
        --argjson duration "${duration}" \
        '{status:"error", message:$msg, started:$started, finished:$finished, duration_seconds:$duration}'
}

# Argument validation
if [ ! -x "${JQ}" ]; then
    echo '{"status":"error","message":"jq is not installed — run setup.sh first"}'
    exit 0
fi

case "${TIMEOUT}" in
    ''|*[!0-9]*)
        emit_error "invalid BLOCKCHECK_TIMEOUT"
        exit 0
        ;;
esac
if [ -z "${DOMAIN}" ]; then
    emit_error "no domain specified"
    exit 0
fi
if ! echo "${DOMAIN}" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9.\-]+[a-zA-Z]{2,}$'; then
    emit_error "invalid domain format"
    exit 0
fi
if [ ! -x "${BLOCKCHECK}" ]; then
    emit_error "blockcheck2.sh not found — run setup.sh first"
    exit 0
fi
if [ ! -f "${CONFIG}" ]; then
    emit_error "zapret config not found — save plugin settings first"
    exit 0
fi
if [ ! -r "${WINNER_PARSER}" ]; then
    emit_error "blockcheck winner parser not found — reinstall the plugin"
    exit 0
fi

# Validate the generated file before sourcing any GUI-controlled values.
if [ ! -r "${CONFIG_VALIDATOR}" ] || ! /bin/sh "${CONFIG_VALIDATOR}" "${CONFIG}"; then
    emit_error "zapret config is invalid or contains unsafe shell syntax; save the plugin settings again after updating the package"
    exit 0
fi

# Resolve WAN device from plugin config
. "${CONFIG}"
WAN_DEV=""
if [ -x "${JQ}" ]; then
    WAN_DEV=$(/usr/local/sbin/pluginctl -4 "${WAN_IF}" 2>/dev/null \
        | "${JQ}" -r --arg if "${WAN_IF}" '.[$if][0].device // empty')
fi
[ -z "${WAN_DEV}" ] && WAN_DEV="${WAN_IF}"

# blockcheck2 wants ipfw enabled to install its own divert rules. Save
# the previous state so the trap can restore exactly what we found.
#
# Safety story (two distinct hazards, both must be handled):
#
#  (1) ipfw default-deny. OPNsense uses pf, so ipfw normally has no
#      rules. `kldload ipfw` loads the module with implicit rule
#      65535 = deny ip from any to any. The instant we
#      `sysctl ...enable=1` the box drops every packet. We add a
#      baseline `allow ip from any to any` at slot 65000 BEFORE
#      enabling. blockcheck2 picks per-PID divert rule numbers via
#      `IPFW_RULE_NUM = ($$ % IPFW_RULE_MAX) + 1` (range 1..999), so
#      its divert rules match first; 65000 just catches everything
#      else and stops the default-deny from killing the network.
#
#  (2) blockcheck2 disables pf. Inside `pktws_ipt_prepare()` the
#      upstream script does `pf_is_avail && pfctl -qd` so its ipfw
#      divert rules don't conflict with pf. On OPNsense disabling pf
#      kills NAT, stateful filtering, and every existing TCP session
#      — SSH dies, configd's connection drops, the box appears
#      wedged. blockcheck2 itself re-enables pf in its `_unprepare`
#      cleanup, but only if we let it finish. If we get killed first,
#      the trap below re-enables pf and reloads OPNsense's ruleset.
WAS_IPFW_LOADED=0
/sbin/kldstat -q -m ipfw && WAS_IPFW_LOADED=1
WAS_IPDIVERT_LOADED=0
/sbin/kldstat -q -m ipdivert && WAS_IPDIVERT_LOADED=1
PREV_IPFW=$(/sbin/sysctl -n net.inet.ip.fw.enable 2>/dev/null || echo 0)
PREV_IPFW6=$(/sbin/sysctl -n net.inet6.ip6.fw.enable 2>/dev/null || echo 0)
ADDED_BASELINE_RULE=0
BLOCKCHECK_TMP=""
FIREWALL_TOUCHED=0
WAS_RUNNING=0
ZAPRET_CHILD_PID=""
ZAPRET_SUPERVISOR_PID=""
ZAPRET_PIDFILE="/var/run/dvtws2.pid"
ZAPRET_SUPERVISOR_PIDFILE="/var/run/dvtws2-supervisor.pid"

process_matches()
{
    process_pid="$1"
    first_marker="$2"
    second_marker="${3:-}"

    case "${process_pid}" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    kill -0 "${process_pid}" 2>/dev/null || return 1
    process_command=$(ps -o command= -p "${process_pid}" 2>/dev/null)

    if [ -n "${second_marker}" ]; then
        case "${process_command}" in
            *"${first_marker}"*"${second_marker}"*)
                return 0
                ;;
        esac
    else
        case "${process_command}" in
            *"${first_marker}"*)
                return 0
                ;;
        esac
    fi

    return 1
}

read_managed_pid()
{
    pidfile="$1"
    first_marker="$2"
    second_marker="${3:-}"
    CHECKED_PID=""

    [ -f "${pidfile}" ] || return 1
    checked_pid=$(cat "${pidfile}" 2>/dev/null)

    case "${checked_pid}" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    kill -0 "${checked_pid}" 2>/dev/null || return 1
    if ! process_matches "${checked_pid}" "${first_marker}" "${second_marker}"; then
        return 2
    fi

    CHECKED_PID="${checked_pid}"
    return 0
}

zapret_processes_running()
{
    process_matches "${ZAPRET_CHILD_PID}" dvtws2 ||
        process_matches "${ZAPRET_SUPERVISOR_PID}" daemon zapret2 ||
        /usr/bin/pgrep -x dvtws2 >/dev/null 2>&1 ||
        /usr/bin/pgrep -f '^daemon: zapret2' >/dev/null 2>&1
}

blockcheck_packet_io_denied()
{
    # Do not treat the public-DNS probe's `ping: sendto` warning as a
    # dvtws2 failure. Only match errors emitted while a divert packet is
    # being generated or reinjected into the local PF/IPFW stack.
    grep -Eq '^(rawsend_sendto_divert: sendto \([0-9]+\)|rawsend: sendto_divert|reinject sendto): (Permission denied|Operation not permitted)' "$1"
}

# cleanup() runs unconditionally on exit (normal exit, SIGTERM from
# configd timeout, SSH disconnect, ^C). Without this trap, a kill
# midway through blockcheck2 would leave ipfw enabled AND pf disabled
# — both fatal. blockcheck2 itself calls `pfctl -qd` to disable pf
# before each test (so its ipfw divert rules don't fight with pf
# rules), and only re-enables pf in its own cleanup which won't run
# if we get killed first. Disabling pf on OPNsense kills NAT,
# stateful filtering, and every existing TCP session.
#
# The trap is the only thing standing between the user and a wedged
# firewall. We re-enable pf, reload OPNsense's full ruleset (which
# rebuilds NAT and per-interface state), and restore ipfw to the
# state we found it in.
cleanup() {
    trap - INT TERM HUP

    if [ "${FIREWALL_TOUCHED}" = "1" ]; then
        # Re-enable pf and rebuild the OPNsense ruleset. `pfctl -e` is a
        # no-op if pf is already enabled. `pfctl -f /tmp/rules.debug`
        # reloads the last-generated OPNsense ruleset; if for any reason
        # that file is gone, fall back to `configctl filter reload` which
        # regenerates it from config.xml.
        /sbin/pfctl -e >/dev/null 2>&1
        if [ -f /tmp/rules.debug ]; then
            /sbin/pfctl -f /tmp/rules.debug >/dev/null 2>&1
        else
            /usr/local/sbin/configctl filter reload >/dev/null 2>&1
        fi

        # ipfw teardown
        /sbin/sysctl net.inet.ip.fw.enable=${PREV_IPFW} >/dev/null 2>&1
        /sbin/sysctl net.inet6.ip6.fw.enable=${PREV_IPFW6} >/dev/null 2>&1
        [ "${ADDED_BASELINE_RULE}" = "1" ] && /sbin/ipfw -q delete 65000 2>/dev/null
        [ "${WAS_IPDIVERT_LOADED}" = "0" ] && /sbin/kldunload ipdivert 2>/dev/null
        [ "${WAS_IPFW_LOADED}" = "0" ] && /sbin/kldunload ipfw 2>/dev/null
    fi

    # Bring zapret back if it was running
    [ -n "${BLOCKCHECK_TMP}" ] && rm -f "${BLOCKCHECK_TMP}"
    [ "${WAS_RUNNING}" = "1" ] && /usr/local/sbin/configctl zapret start >/dev/null 2>&1
    # Note: we deliberately do NOT delete ${LOG} here. It lives at
    # /var/log/zapret/blockcheck-*.log and is part of the persistent
    # archive (rotated by the next run, not by us).
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# blockcheck2 refuses to run reliably while another DPI bypass is active.
# Validate both daemon(8) pidfiles so a stale PID cannot make us stop an
# unrelated process, and so the supervisor cannot respawn dvtws2 mid-scan.
read_managed_pid "${ZAPRET_PIDFILE}" dvtws2
child_state=$?
[ "${child_state}" -eq 0 ] && ZAPRET_CHILD_PID="${CHECKED_PID}"

read_managed_pid "${ZAPRET_SUPERVISOR_PIDFILE}" daemon zapret2
supervisor_state=$?
[ "${supervisor_state}" -eq 0 ] && ZAPRET_SUPERVISOR_PID="${CHECKED_PID}"

if [ "${child_state}" -eq 2 ] || [ "${supervisor_state}" -eq 2 ]; then
    emit_error "zapret pidfile points to an unexpected process"
    exit 0
fi

if [ "${child_state}" -ne 0 ] && [ "${supervisor_state}" -ne 0 ]; then
    if zapret_processes_running; then
        emit_error "unmanaged zapret process is running"
        exit 0
    fi
fi

if [ "${child_state}" -eq 0 ] || [ "${supervisor_state}" -eq 0 ]; then
    WAS_RUNNING=1

    if ! /usr/local/sbin/configctl zapret stop >/dev/null 2>&1; then
        emit_error "could not stop zapret before blockcheck"
        exit 0
    fi

    stop_wait=0
    while [ "${stop_wait}" -lt 50 ] && zapret_processes_running; do
        sleep 0.1
        stop_wait=$((stop_wait + 1))
    done

    if zapret_processes_running; then
        emit_error "zapret processes did not stop before blockcheck"
        exit 0
    fi
fi

FIREWALL_TOUCHED=1

if ! /sbin/kldstat -q -m ipdivert && ! /sbin/kldload ipdivert; then
    emit_error "could not load ipdivert kernel module"
    exit 0
fi
if ! /sbin/kldstat -q -m ipfw && ! /sbin/kldload ipfw; then
    emit_error "could not load ipfw kernel module"
    exit 0
fi

# Add a temporary baseline allow before enabling ipfw only when the kernel's
# default policy is deny. Never reuse or delete an existing rule 65000: it may
# belong to another OPNsense component.
DEFAULT_TO_ACCEPT=$(/sbin/sysctl -n net.inet.ip.fw.default_to_accept 2>/dev/null || echo 0)
if [ "${DEFAULT_TO_ACCEPT}" != "1" ]; then
    if /sbin/ipfw -q list 65000 >/dev/null 2>&1; then
        emit_error "cannot prepare ipfw: rule 65000 is already in use"
        exit 0
    fi
    if ! /sbin/ipfw -q add 65000 allow ip from any to any 2>/dev/null; then
        emit_error "could not install temporary ipfw safety rule"
        exit 0
    fi
    if ! /sbin/ipfw -q list 65000 2>/dev/null | grep -q 'allow ip from any to any'; then
        emit_error "temporary ipfw safety rule could not be verified"
        exit 0
    fi
    ADDED_BASELINE_RULE=1
fi

if ! /sbin/sysctl net.inet.ip.fw.enable=1 >/dev/null 2>&1; then
    emit_error "could not enable IPv4 ipfw"
    exit 0
fi
if ! /sbin/sysctl net.inet6.ip6.fw.enable=1 >/dev/null 2>&1; then
    emit_error "could not enable IPv6 ipfw"
    exit 0
fi

# OPNsense must keep pf enabled while blockcheck runs.
# Put ipfw ahead of pf in the pfil chain, then run a temporary copy of
# upstream blockcheck2.sh with its per-test "pfctl -qd" disabled.
BLOCKCHECK_RUN="${BLOCKCHECK}"

if [ -f /usr/local/opnsense/version/core ]; then
    if ! /sbin/pfctl -d >/dev/null 2>&1; then
        emit_error "could not detach pf before pfil reordering"
        exit 0
    fi
    if ! /sbin/pfctl -e >/dev/null 2>&1; then
        emit_error "could not re-enable pf after pfil reordering"
        exit 0
    fi

    PF_DISABLE_COUNT=$(grep -cF 'pf_is_avail && pfctl -qd' "${BLOCKCHECK}" 2>/dev/null || true)
    DVTWS_START_COUNT=$(grep -cF '"$DVTWS2" --port=$IPFW_DIVERT_PORT ' "${BLOCKCHECK}" 2>/dev/null || true)
    OUTBOUND_RULE_COUNT=$(grep -cF 'IPFW_ADD divert $IPFW_DIVERT_PORT $1 from me to $ip $2 proto ip${IPV} out not diverted' "${BLOCKCHECK}" 2>/dev/null || true)
    INBOUND_RULE_COUNT=$(grep -cF 'IPFW_ADD divert $IPFW_DIVERT_PORT tcp from $ip $1 to me proto ip${IPV} tcpflags syn,ack in not diverted' "${BLOCKCHECK}" 2>/dev/null || true)

    if [ "${PF_DISABLE_COUNT}" -ne 1 ] ||
       [ "${DVTWS_START_COUNT}" -ne 1 ] ||
       [ "${OUTBOUND_RULE_COUNT}" -ne 1 ] ||
       [ "${INBOUND_RULE_COUNT}" -ne 1 ]; then
        emit_error "unsupported blockcheck2.sh format (patch targets: pf=${PF_DISABLE_COUNT}, dvtws=${DVTWS_START_COUNT}, outbound=${OUTBOUND_RULE_COUNT}, inbound=${INBOUND_RULE_COUNT})"
        exit 0
    fi

    BLOCKCHECK_TMP=$(/usr/bin/mktemp -t blockcheck2-opnsense.XXXXXX) || {
        emit_error "could not create temporary OPNsense blockcheck wrapper"
        exit 0
    }

    sed \
        -e 's/pf_is_avail && pfctl -qd/: # OPNsense: keep pf enabled/' \
        -e 's|"$DVTWS2" --port=$IPFW_DIVERT_PORT |"$DVTWS2" --port=$IPFW_DIVERT_PORT --sockarg=0x200 --user=nobody |' \
        -e 's|IPFW_ADD divert $IPFW_DIVERT_PORT $1 from me to $ip $2 proto ip${IPV} out not diverted|IPFW_ADD divert $IPFW_DIVERT_PORT $1 from me to $ip $2 proto ip${IPV} out not diverted not sockarg xmit $IFACE_WAN|' \
        -e 's|IPFW_ADD divert $IPFW_DIVERT_PORT tcp from $ip $1 to me proto ip${IPV} tcpflags syn,ack in not diverted|: # OPNsense: do not divert inbound SYN+ACK|' \
        "${BLOCKCHECK}" > "${BLOCKCHECK_TMP}" || {
        emit_error "could not prepare OPNsense blockcheck wrapper"
        exit 0
    }

    PF_PATCH_COUNT=$(grep -cF ': # OPNsense: keep pf enabled' "${BLOCKCHECK_TMP}" 2>/dev/null || true)
    DVTWS_PATCH_COUNT=$(grep -cF '"$DVTWS2" --port=$IPFW_DIVERT_PORT --sockarg=0x200 --user=nobody ' "${BLOCKCHECK_TMP}" 2>/dev/null || true)
    OUTBOUND_PATCH_COUNT=$(grep -cF 'out not diverted not sockarg xmit $IFACE_WAN' "${BLOCKCHECK_TMP}" 2>/dev/null || true)
    INBOUND_PATCH_COUNT=$(grep -cF ': # OPNsense: do not divert inbound SYN+ACK' "${BLOCKCHECK_TMP}" 2>/dev/null || true)

    if [ "${PF_PATCH_COUNT}" -ne 1 ] ||
       [ "${DVTWS_PATCH_COUNT}" -ne 1 ] ||
       [ "${OUTBOUND_PATCH_COUNT}" -ne 1 ] ||
       [ "${INBOUND_PATCH_COUNT}" -ne 1 ]; then
        emit_error "could not verify patched blockcheck2.sh"
        exit 0
    fi

    chmod 700 "${BLOCKCHECK_TMP}"
    BLOCKCHECK_RUN="${BLOCKCHECK_TMP}"
fi

# Persistent per-run log so the user can review the full blockcheck2
# output after the fact (the JSON-embedded log field is truncated to
# the last 2000 bytes for transport size). Filename pattern includes
# timestamp + domain so `ls -t` shows runs in order, and the file
# itself survives the cleanup trap (unlike the old mktemp approach).
LOG_DIR=/var/log/zapret
mkdir -p "${LOG_DIR}" 2>/dev/null
# Sanitize domain for filesystem safety. Limited to chars our regex
# already allows + a colon-collapse, so this is paranoia not necessity.
# Use printf (not echo) so we don't pick up a trailing newline that
# `tr` would convert to a stray "_" in the filename.
LOG_DOMAIN=$(printf '%s' "${DOMAIN}" | tr -c 'a-zA-Z0-9.-' '_')
LOG="${LOG_DIR}/blockcheck-$(date -u +%Y%m%d-%H%M%S)-${LOG_DOMAIN}.log"
: > "${LOG}" 2>/dev/null || {
    emit_error "could not create log file at ${LOG}"
    exit 0
}

# Prune old logs — keep most recent 50 runs to bound disk usage.
# A typical run is 50-500KB; 50 runs ≈ 25MB. tail -n +51 selects the
# 51st onward (oldest), xargs deletes them. Failures are silent.
ls -1t "${LOG_DIR}"/blockcheck-*.log 2>/dev/null | tail -n +51 | xargs rm -f 2>/dev/null

# blockcheck2 has a BATCH=1 env mode that suppresses every interactive
# prompt; combined with DOMAINS/IPVS/ENABLE_*/REPEATS/PARALLEL/SCANLEVEL
# vars, the whole flow is fully non-interactive (no stdin piping needed).
#
# We also set DOMAINS_DEFAULT to the user's domain. blockcheck2 has a
# hard-coded `DOMAINS_DEFAULT=rutracker.org` and falls back to it if
# DOMAINS is empty for any reason. Keeping the default in sync with the
# requested domain means the user can never silently get rutracker
# results when they asked for something else.
cd "${ZAPRET_DIR}"

ZAPRET_BASE="${ZAPRET_DIR}"
BATCH=1
IFACE_WAN="${WAN_DEV}"
DOMAINS="${DOMAIN}"
DOMAINS_DEFAULT="${DOMAIN}"
IPVS=4
ENABLE_HTTP="${BC_HTTP}"
ENABLE_HTTPS_TLS12="${BC_TLS12}"
ENABLE_HTTPS_TLS13="${BC_TLS13}"
ENABLE_HTTP3="${BC_HTTP3}"
REPEATS=1
PARALLEL=0
SCANLEVEL=standard

# Prefer the private HTTP/3-capable curl shipped with the plugin.
# Fall back to the OPNsense system curl if it is unavailable.
CURL_H3="/usr/local/libexec/zapret2/curl-h3/bin/curl"

if [ -x "${CURL_H3}" ]; then
    CURL="${CURL_H3}"
elif [ -x /usr/local/bin/curl ]; then
    CURL="/usr/local/bin/curl"
else
    CURL="curl"
fi

# curl-impersonate does not have an OPNsense CA path compiled in.
# Reuse the firewall's own current CA bundle instead of shipping one.
if [ -f /usr/local/share/certs/ca-root-nss.crt ]; then
    CURL_CA_BUNDLE="/usr/local/share/certs/ca-root-nss.crt"
elif [ -f /etc/ssl/cert.pem ]; then
    CURL_CA_BUNDLE="/etc/ssl/cert.pem"
else
    CURL_CA_BUNDLE=""
fi

export ZAPRET_BASE BATCH IFACE_WAN DOMAINS DOMAINS_DEFAULT IPVS
export ENABLE_HTTP ENABLE_HTTPS_TLS12 ENABLE_HTTPS_TLS13 ENABLE_HTTP3
export REPEATS PARALLEL SCANLEVEL CURL

if [ -n "${CURL_CA_BUNDLE}" ]; then
    export CURL_CA_BUNDLE
fi

/usr/bin/timeout -k 30 -s TERM "${TIMEOUT}" \
    /bin/sh "${BLOCKCHECK_RUN}" >"${LOG}" 2>&1
EXIT=$?

PACKET_IO_DENIED=0
blockcheck_packet_io_denied "${LOG}" && PACKET_IO_DENIED=1

# ipfw teardown, log cleanup, and zapret restart all happen in the
# trap handler installed above — no manual cleanup needed here.

FINISHED_EPOCH=$(date -u +%s)
FINISHED_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DURATION=$((FINISHED_EPOCH - STARTED_EPOCH))

# Prefer the final SUMMARY produced by current or older blockcheck2.
SUMMARY=$(awk '/^[-*] SUMMARY/,0' "${LOG}" 2>/dev/null)

PARTIAL=0

if [ -z "${SUMMARY}" ]; then
    PARTIAL=1

    # blockcheck2 confirms each individual test with a terminal AVAILABLE
    # marker before it eventually prints SUMMARY. The parser keeps that
    # marker tied to its own candidate and clears failed candidates, so an
    # unrelated later success cannot become a false winner.
    CONFIRMED_WINNERS=$(awk -f "${WINNER_PARSER}" "${LOG}" 2>/dev/null | head -30)

    SUMMARY="- SUMMARY (partial - blockcheck did not finish, exit=${EXIT})"

    [ -n "${CONFIRMED_WINNERS}" ] && SUMMARY="${SUMMARY}
${CONFIRMED_WINNERS}"

fi

# Current SUMMARY format:
#   curl_test_http3 ipv4 example.com : dvtws2 --payload=...
# or a connection that already works without bypass.
WINNING=$(printf '%s\n' "${SUMMARY}" \
    | grep -E '^[[:space:]]*curl_test_.* : (dvtws2 --|working without bypass)' \
    | sed -E 's/^[[:space:]]*//' \
    | awk '!seen[$0]++' \
    | head -30)

if [ "${PACKET_IO_DENIED}" = "1" ] && [ -z "${WINNING}" ]; then
    "${JQ}" -nc \
        --arg msg "local PF/IPFW stack denied dvtws2 packet injection; blockcheck results are invalid (exit=${EXIT})" \
        --arg domain "${DOMAIN}" \
        --arg summary "${SUMMARY}" \
        --arg started "${STARTED_ISO}" \
        --arg finished "${FINISHED_ISO}" \
        --argjson duration "${DURATION}" \
        --arg log_file "${LOG}" \
        --rawfile log "${LOG}" \
        '{status:"error", message:$msg, domain:$domain, started:$started, finished:$finished, duration_seconds:$duration, log_file:$log_file, summary:$summary, log:$log[-2000:]}'
    exit 0
fi

if [ "${PARTIAL}" = "1" ] && [ -z "${WINNING}" ]; then
    "${JQ}" -nc \
        --arg msg "blockcheck did not produce a summary or any confirmed winners (exit=${EXIT})" \
        --arg started "${STARTED_ISO}" \
        --arg finished "${FINISHED_ISO}" \
        --argjson duration "${DURATION}" \
        --arg log_file "${LOG}" \
        --rawfile log "${LOG}" \
        '{status:"error", message:$msg, started:$started, finished:$finished, duration_seconds:$duration, log_file:$log_file, log:$log[-2000:]}'
    exit 0
fi

"${JQ}" -nc \
    --arg domain "${DOMAIN}" \
    --arg summary "${SUMMARY}" \
    --arg winning "${WINNING}" \
    --arg started "${STARTED_ISO}" \
    --arg finished "${FINISHED_ISO}" \
    --argjson duration "${DURATION}" \
    --arg log_file "${LOG}" \
    --argjson partial "${PARTIAL}" \
    '{status:"ok", domain:$domain, partial:($partial==1), started:$started, finished:$finished, duration_seconds:$duration, log_file:$log_file, summary:$summary, winning:($winning|split("\n")|map(select(length > 0)))}'

exit 0

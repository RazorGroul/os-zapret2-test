#!/bin/sh

# zapret_service.sh — Service management for zapret2 on OPNsense
# Called by configd via actions_zapret.conf.
#
# Architecture — ipfw divert + sockarg loop-guard (inherited from
# v1.1.0 which ran flawlessly for 3 weeks on bare-metal PPPoE and was
# verified to work for NAT'd LAN clients):
#
#   - `ipfw divert $DIVERT_PORT tcp from any to any $port out not sockarg
#     xmit $wan_dev` for each configured port (80, 443). Only matches
#     outbound on WAN and only when the packet DOESN'T already carry the
#     sockarg tag (so reinjected packets from dvtws2 sail past).
#   - dvtws2 is started with `--sockarg=0x200`, which makes it mark every
#     reinjected packet with that tag. Combined with `not sockarg` above,
#     this is the clean loop-prevention pair.
#   - daemon(8) -r supervision auto-respawns dvtws2 within ~1s on crash.
#   - safety watchdog probes a control URL every minute; 3 consecutive
#     failures → stop the service so a bad strategy can't kill household
#     internet for long.
#
# Why NOT pf divert-to (the v1.6.x approach): empirically broken for
# NAT'd LAN-client traffic on both virtio and bare-metal+PPPoE. See
# memory/feedback_v110_ipfw_works_pf_divert_broken.md for the diagnosis.

ZAPRET_DIR="/usr/local/etc/zapret2"
CONFIG="${ZAPRET_DIR}/zapret.conf"
PIDFILE="/var/run/dvtws2.pid"
SUPERVISOR_PIDFILE="/var/run/dvtws2-supervisor.pid"
WATCHDOG_PIDFILE="/var/run/zapret-watchdog.pid"
WATCHDOG_SUPERVISOR_PIDFILE="/var/run/zapret-watchdog-supervisor.pid"
WATCHDOG_LOOP="/usr/local/opnsense/scripts/OPNsense/Zapret/watchdog_loop.sh"
DVTWS_BIN="${ZAPRET_DIR}/binaries/my/dvtws2"
HOSTLIST="${ZAPRET_DIR}/hostlist.txt"
HOSTLIST_EXCLUDE="${ZAPRET_DIR}/hostlist-exclude.txt"
YOUTUBE_HOSTLIST="${ZAPRET_DIR}/hostlist-youtube.txt"
DISCORD_HOSTLIST="${ZAPRET_DIR}/hostlist-discord.txt"
AUTOHOSTLIST="${ZAPRET_DIR}/autohostlist.txt"
IPSET_VALIDATOR="/usr/local/opnsense/scripts/OPNsense/Zapret/validate_ipset.awk"
CUSTOM_PROFILES_FILE="${ZAPRET_DIR}/custom-profiles.json"
CUSTOM_PROFILE_LIST_DIR="${ZAPRET_DIR}/custom-hostlists"
JQ_BIN="/usr/local/bin/jq"
[ -x "${JQ_BIN}" ] || JQ_BIN=$(command -v jq 2>/dev/null || true)
LUA_LIB="${ZAPRET_DIR}/lua/zapret-lib.lua"
LUA_ANTIDPI="${ZAPRET_DIR}/lua/zapret-antidpi.lua"

# ipfw rule numbers we own. Range 19000-19010 — high enough to avoid
# OPNsense's own rules, low enough to fire before the default-accept at
# 65534. One rule number is used per TCP port; all enabled UDP profiles
# share one aggregated UDP port-list rule.
RULE_BASE=19000
RULE_MAX=$((RULE_BASE + 10))

load_config() {
    if [ ! -f "${CONFIG}" ]; then
        echo "zapret is not running (configuration file not found — save settings first)"
        exit 1
    fi
    . "${CONFIG}"
}

resolve_interface() {
    local iface="$1"

    # Direct match first (raw device names like pppoe2, igc0)
    if ifconfig "${iface}" > /dev/null 2>&1; then
        echo "${iface}"
        return
    fi

    # Map an OPNsense logical interface (opt11, wan, lan, …) to its kernel
    # device. pluginctl -4 emits JSON like:
    #   {"opt11":[{"address":"...","device":"pppoe2", ...}]}
    local dev=""
    if [ -x /usr/local/bin/jq ]; then
        dev=$(/usr/local/sbin/pluginctl -4 "${iface}" 2>/dev/null \
            | /usr/local/bin/jq -r --arg if "${iface}" '.[$if][0].device // empty')
    fi
    if [ -n "${dev}" ]; then
        echo "${dev}"
        return
    fi

    # Last resort: hand the original string back to the caller.
    echo "${iface}"
}

remove_ipfw_rules() {
    # Delete anything in our reserved rule range. Silent if the rule
    # doesn't exist. Run on stop AND before adding on start (so a crashed
    # previous invocation doesn't leave stale rules around).
    local r=${RULE_BASE}
    while [ ${r} -le ${RULE_MAX} ]; do
        /sbin/ipfw -q delete ${r} 2>/dev/null
        r=$((r + 1))
    done
}

ensure_ipfw_default_accept() {
    # ipfw's default ruleset ends at 65535 with "deny ip from any to any"
    # UNLESS the kernel was built with IPFIREWALL_DEFAULT_TO_ACCEPT or
    # the sysctl is 1. On OPNsense neither is guaranteed, so we add an
    # explicit accept-all at 65534 (just inside the default-deny) the
    # first time we enable ipfw. Without this, loading the ipfw module
    # instantly drops every packet the box is handling.
    local default_accept=$(/sbin/sysctl -n net.inet.ip.fw.default_to_accept 2>/dev/null)
    if [ "${default_accept}" != "1" ]; then
        /sbin/ipfw -q add 65534 allow ip from any to any 2>/dev/null || true
    fi
}

configure_ipfw_reinject() {
    # Make ipfw's divert fire BEFORE pf on the outbound IPv4 path, so pf
    # builds correct state for dvtws2's reinjected/desynced packets instead
    # of dropping their return traffic. THE ORDER OF THESE STEPS MATTERS —
    # it was verified live on OPNsense 26.1 / FreeBSD 14 (bare-metal PPPoE):
    #
    #   - With pf ahead of ipfw, the blocked site's reinjected ClientHello
    #     goes out but the server's SYN-ACK is dropped by pf (no matching
    #     state) and the connection hangs — even general HTTPS breaks.
    #   - With ipfw ahead of pf, divert fires AND traffic completes: blocked
    #     domain bypasses, untouched domains keep working.
    #
    # The legacy `net.inet.ip.pfil.outbound=ipfw,pf` knob USED to set this
    # order but DOES NOT EXIST on FreeBSD 14 (the OID is gone), so it can't
    # be relied on. The working mechanism is pfil hook (re)registration order:
    #
    # 1) Enable ipfw FIRST. Enabling links ipfw's hook into the `inet` pfil
    #    head — but it appends AFTER pf (pf registered at boot). `kldload`
    #    alone is not enough: on OPNsense ipfw is usually already resident
    #    (e.g. blockcheck loads it then restores enable=0 on exit), so the
    #    `kldstat || kldload` guard short-circuits and enable stays 0 — then
    #    the divert rules are installed but ipfw evaluates NOTHING. Set it
    #    explicitly, and set it here so the hook is linked before step 2.
    /sbin/sysctl net.inet.ip.fw.one_pass=1 >/dev/null 2>&1
    /sbin/sysctl net.inet.ip.fw.enable=1   >/dev/null 2>&1

    # 2) THEN bounce pf. Disabling unlinks pf's hooks; re-enabling appends
    #    them to the BACK of the chain — i.e. AFTER ipfw, which is now
    #    already linked. Result on the outbound `inet` head:
    #        ipfw:default   (runs first → divert)
    #        pf:default-out (runs second → NAT/state on the final packets)
    #    Doing this bounce BEFORE enabling ipfw (as a previous revision did)
    #    leaves ipfw behind pf and silently breaks the bypass.
    /sbin/pfctl -d >/dev/null 2>&1
    /sbin/pfctl -e >/dev/null 2>&1
}

validate_ipset_filename() {
    local filename="$1"

    case "${filename}" in
        ""|.|..|*..*|*[!a-zA-Z0-9_.-]*)
            echo "invalid IPSet filename; use a simple filename without directories or '..': ${filename}" >&2
            return 1
            ;;
    esac
    return 0
}

validate_ipset_file() {
    local file="$1"
    local bytes=""

    if [ ! -f "${file}" ] || [ ! -r "${file}" ]; then
        echo "enabled IPSet file is missing or unreadable: ${file}" >&2
        return 1
    fi

    bytes=$(wc -c < "${file}" | tr -d '[:space:]')
    case "${bytes}" in ''|*[!0-9]*) echo "could not determine IPSet file size: ${file}" >&2; return 1 ;; esac
    if [ "${bytes}" -gt 10485760 ]; then
        echo "IPSet file exceeds the 10 MiB safety limit: ${file}" >&2
        return 1
    fi

    if [ ! -r "${IPSET_VALIDATOR}" ] || ! awk -f "${IPSET_VALIDATOR}" "${file}"; then
        echo "IPSet file failed IPv4/IPv6 CIDR validation: ${file}" >&2
        return 1
    fi
    return 0
}

validate_ipset_configuration() {
    IPSET_ARGS=""
    local include_enabled="${IPSET_INCLUDE_ENABLED:-0}"
    local exclude_enabled="${IPSET_EXCLUDE_ENABLED:-0}"
    local include_file="${IPSET_INCLUDE_FILE:-ipset-all.txt}"
    local exclude_file="${IPSET_EXCLUDE_FILE:-ipset-exclude-default.txt}"
    local file=""

    case "${include_enabled}" in 0|"") ;; 1) ;; *) echo "invalid IPSet include toggle value" >&2; return 1 ;; esac
    case "${exclude_enabled}" in 0|"") ;; 1) ;; *) echo "invalid IPSet exclude toggle value" >&2; return 1 ;; esac

    if [ "${include_enabled}" = "1" ]; then
        validate_ipset_filename "${include_file}" || return 1
        file="${ZAPRET_DIR}/${include_file}"
        validate_ipset_file "${file}" || return 1
        IPSET_ARGS="${IPSET_ARGS} --ipset=${file}"
    fi

    if [ "${exclude_enabled}" = "1" ]; then
        validate_ipset_filename "${exclude_file}" || return 1
        file="${ZAPRET_DIR}/${exclude_file}"
        validate_ipset_file "${file}" || return 1
        IPSET_ARGS="${IPSET_ARGS} --ipset-exclude=${file}"
    fi

    return 0
}

validate_strategy_arguments() {
    local profile="$1"
    local value="$2"
    local saved_ifs="${IFS}"
    local token
    local value_without_spaces
    local saw_desync=0

    if [ -z "${value}" ]; then
        echo "${profile} strategy is empty" >&2
        return 1
    fi

    # The value is later split into argv by /bin/sh. Allow ordinary
    # spaces only as argument separators, and validate the remaining
    # characters with a POSIX shell pattern (hyphen is the final class item).
    # This excludes paths, shell operators, quotes, substitutions, globs,
    # and redirections without relying on an escaped hyphen in a bracket set.
    value_without_spaces=$(printf '%s' "${value}" | tr -d ' ')
    case "${value_without_spaces}" in
        *[!a-zA-Z0-9_,.:=+-]*)
            echo "${profile} strategy contains unsupported characters" >&2
            return 1
            ;;
    esac

    IFS=' 	
'
    for token in ${value}; do
        case "${token}" in
            --payload=*)
                [ -n "${token#--payload=}" ] || { IFS="${saved_ifs}"; echo "empty --payload value in ${profile} strategy" >&2; return 1; }
                ;;
            --lua-desync=*)
                [ -n "${token#--lua-desync=}" ] || { IFS="${saved_ifs}"; echo "empty --lua-desync value in ${profile} strategy" >&2; return 1; }
                saw_desync=1
                ;;
            --out-range=*)
                [ -n "${token#--out-range=}" ] || { IFS="${saved_ifs}"; echo "empty --out-range value in ${profile} strategy" >&2; return 1; }
                ;;
            *)
                IFS="${saved_ifs}"
                echo "${profile} strategy accepts only --payload=..., --lua-desync=..., and --out-range=... arguments; rejected token: ${token}" >&2
                return 1
                ;;
        esac
    done
    IFS="${saved_ifs}"

    if [ "${saw_desync}" -ne 1 ]; then
        echo "${profile} strategy must contain at least one --lua-desync=... argument" >&2
        return 1
    fi

    return 0
}

validate_managed_profiles() {
    local youtube_tcp="${YOUTUBE_TCP_ENABLED:-0}"
    local youtube_quic="${YOUTUBE_QUIC_ENABLED:-0}"
    local discord_tcp="${DISCORD_TCP_ENABLED:-0}"

    case "${youtube_tcp}" in 0|"") ;; 1) ;; *) echo "invalid YouTube TCP profile toggle" >&2; return 1 ;; esac
    case "${youtube_quic}" in 0|"") ;; 1) ;; *) echo "invalid YouTube QUIC profile toggle" >&2; return 1 ;; esac
    case "${discord_tcp}" in 0|"") ;; 1) ;; *) echo "invalid Discord TCP profile toggle" >&2; return 1 ;; esac

    if [ "${youtube_tcp}" = "1" ]; then
        if [ ! -s "${YOUTUBE_HOSTLIST}" ]; then
            echo "YouTube/Google hostlist is missing or empty: ${YOUTUBE_HOSTLIST}" >&2
            return 1
        fi
        validate_strategy_arguments "YouTube/Google TCP" "${YOUTUBE_TCP_ARGS:-}" || return 1
    fi

    if [ "${youtube_quic}" = "1" ]; then
        if [ ! -s "${YOUTUBE_HOSTLIST}" ]; then
            echo "YouTube/Google hostlist is missing or empty: ${YOUTUBE_HOSTLIST}" >&2
            return 1
        fi
        validate_strategy_arguments "YouTube/Google QUIC" "${YOUTUBE_QUIC_ARGS:-}" || return 1
    fi

    if [ "${discord_tcp}" = "1" ]; then
        if [ ! -s "${DISCORD_HOSTLIST}" ]; then
            echo "Discord hostlist is missing or empty: ${DISCORD_HOSTLIST}" >&2
            return 1
        fi
        validate_strategy_arguments "Discord TCP" "${DISCORD_TCP_ARGS:-}" || return 1
    fi

    return 0
}

validate_udp_configuration() {
    # Additional UDP traffic is opt-in. Require ports, an L7 filter, and a
    # strategy together so an accidental partial form submission cannot
    # divert packets into a profile that does not process them.
    local raw_ports="${UDP_PORTS:-}"
    local normalized_ports=""
    local item start end canonical
    local count=0
    local includes_443=0
    local saved_ifs="${IFS}"
    local token

    raw_ports=$(printf '%s' "${raw_ports}" | tr -d '[:space:]')

    if [ -z "${raw_ports}" ]; then
        if [ -n "${UDP_ARGS:-}" ] || [ -n "${UDP_FILTER_L7:-}" ]; then
            echo "Additional UDP Strategy and L7 filter require Additional UDP Ports" >&2
            return 1
        fi
        UDP_PORTS=""
        return 0
    fi

    if [ -z "${UDP_ARGS:-}" ] || [ -z "${UDP_FILTER_L7:-}" ]; then
        echo "Additional UDP Ports require both a UDP L7 filter and UDP strategy" >&2
        return 1
    fi

    case "${raw_ports}" in
        *[!0-9,-]*|,*|*,|*,,*)
            echo "invalid Additional UDP Ports syntax: ${raw_ports}" >&2
            return 1
            ;;
    esac

    # FreeBSD ipfw accepts up to 30 comma-separated port/range items in one
    # rule. Validate and canonicalize numbers before they are used in rules.
    IFS=","
    for item in ${raw_ports}; do
        count=$((count + 1))
        if [ "${count}" -gt 30 ]; then
            IFS="${saved_ifs}"
            echo "Additional UDP Ports supports at most 30 ports or ranges" >&2
            return 1
        fi

        case "${item}" in
            *-*)
                start=${item%%-*}
                end=${item#*-}
                case "${end}" in
                    *-*) IFS="${saved_ifs}"; echo "invalid UDP port range: ${item}" >&2; return 1 ;;
                esac
                ;;
            *)
                start="${item}"
                end="${item}"
                ;;
        esac

        case "${start}" in ''|*[!0-9]*) IFS="${saved_ifs}"; echo "invalid UDP port: ${item}" >&2; return 1 ;; esac
        case "${end}" in ''|*[!0-9]*) IFS="${saved_ifs}"; echo "invalid UDP port: ${item}" >&2; return 1 ;; esac

        # Strip leading zeroes before numeric comparisons to avoid octal arithmetic.
        while [ -n "${start}" ] && [ "${start#0}" != "${start}" ]; do start="${start#0}"; done
        while [ -n "${end}" ] && [ "${end#0}" != "${end}" ]; do end="${end#0}"; done
        [ -n "${start}" ] || start=0
        [ -n "${end}" ] || end=0

        # POSIX test may fail open on arbitrarily large integer strings.
        # Port numbers are at most five decimal digits after normalization.
        if [ "${#start}" -gt 5 ] || [ "${#end}" -gt 5 ]; then
            IFS="${saved_ifs}"
            echo "UDP port number is too large: ${item}" >&2
            return 1
        fi

        if [ "${start}" -lt 1 ] || [ "${end}" -gt 65535 ] || [ "${start}" -gt "${end}" ]; then
            IFS="${saved_ifs}"
            echo "UDP ports and ranges must be within 1-65535 and ranges must be ascending: ${item}" >&2
            return 1
        fi

        if [ "${start}" -le 443 ] && [ "${end}" -ge 443 ]; then
            includes_443=1
        fi

        if [ "${start}" -eq "${end}" ]; then
            canonical="${start}"
        else
            canonical="${start}-${end}"
        fi
        if [ -n "${normalized_ports}" ]; then
            normalized_ports="${normalized_ports},${canonical}"
        else
            normalized_ports="${canonical}"
        fi
    done
    IFS="${saved_ifs}"

    if [ "${includes_443}" -eq 1 ] && { [ -n "${QUIC_ARGS:-}" ] || [ "${YOUTUBE_QUIC_ENABLED:-0}" = "1" ]; }; then
        echo "Additional UDP Ports overlaps UDP/443 while a QUIC profile is enabled; remove 443 from one profile" >&2
        return 1
    fi

    # Normalize protocol names, then keep the filter to documented values.
    UDP_FILTER_L7=$(printf '%s' "${UDP_FILTER_L7}" | tr '[:upper:]' '[:lower:]')
    case "${UDP_FILTER_L7}" in
        *[!a-z0-9,_-]*|,*|*,|*,,*)
            echo "invalid UDP L7 filter syntax: ${UDP_FILTER_L7}" >&2
            return 1
            ;;
    esac
    IFS=","
    for token in ${UDP_FILTER_L7}; do
        case "${token}" in
            discord|stun|wireguard|dht|quic|unknown) ;;
            *) IFS="${saved_ifs}"; echo "unsupported UDP L7 protocol: ${token}" >&2; return 1 ;;
        esac
    done
    IFS="${saved_ifs}"

    validate_strategy_arguments "Additional UDP" "${UDP_ARGS}" || return 1

    UDP_PORTS="${normalized_ports}"
    return 0
}

validate_tcp_ports() {
    local raw="${PORTS:-}"
    local item normalized=""
    local saved_ifs="${IFS}"

    case "${raw}" in
        ""|,*|*,|*,,*|*[!0-9,]*)
            echo "TCP Ports must be a comma-separated list of port numbers from 1 to 65535" >&2
            return 1
            ;;
    esac

    IFS=","
    for item in ${raw}; do
        case "${item}" in
            ""|*[!0-9]*)
                IFS="${saved_ifs}"
                echo "invalid TCP port: ${item}" >&2
                return 1
                ;;
        esac

        while [ -n "${item}" ] && [ "${item#0}" != "${item}" ]; do item="${item#0}"; done
        [ -n "${item}" ] || item=0
        # Guard before test(1): very long numeric strings can make integer
        # comparisons fail with an error and otherwise bypass range checks.
        if [ "${#item}" -gt 5 ]; then
            IFS="${saved_ifs}"
            echo "TCP port number is too large: ${item}" >&2
            return 1
        fi
        if [ "${item}" -lt 1 ] || [ "${item}" -gt 65535 ]; then
            IFS="${saved_ifs}"
            echo "TCP port must be within 1-65535: ${item}" >&2
            return 1
        fi

        case ",${normalized}," in
            *,"${item}",*) ;;
            *) normalized="${normalized:+${normalized},}${item}" ;;
        esac
    done
    IFS="${saved_ifs}"

    PORTS="${normalized}"
    return 0
}


# Normalize a comma-separated list of ports/ranges. Results are returned in
# PORT_SPEC_NORMALIZED and PORT_SPEC_HAS_443 for rule and overlap checks.
normalize_port_spec() {
    local raw="$1"
    local label="$2"
    local item start end canonical count=0
    local normalized=""
    local saved_ifs="${IFS}"

    raw=$(printf '%s' "${raw}" | tr -d '[:space:]')
    case "${raw}" in
        ""|,*|*,|*,,*|*[!0123456789,-]*)
            echo "${label} must be a comma-separated list of ports/ranges" >&2
            return 1
            ;;
    esac

    PORT_SPEC_HAS_443=0
    IFS=","
    for item in ${raw}; do
        count=$((count + 1))
        if [ "${count}" -gt 30 ]; then
            IFS="${saved_ifs}"
            echo "${label} supports at most 30 ports or ranges" >&2
            return 1
        fi

        case "${item}" in
            *-*)
                start=${item%%-*}
                end=${item#*-}
                case "${end}" in
                    *-*) IFS="${saved_ifs}"; echo "invalid range in ${label}: ${item}" >&2; return 1 ;;
                esac
                ;;
            *)
                start="${item}"
                end="${item}"
                ;;
        esac

        case "${start}" in ""|*[!0123456789]*) IFS="${saved_ifs}"; echo "invalid port in ${label}: ${item}" >&2; return 1 ;; esac
        case "${end}" in ""|*[!0123456789]*) IFS="${saved_ifs}"; echo "invalid port in ${label}: ${item}" >&2; return 1 ;; esac

        start=$(printf '%s' "${start}" | sed 's/^0*//')
        end=$(printf '%s' "${end}" | sed 's/^0*//')
        [ -n "${start}" ] || start=0
        [ -n "${end}" ] || end=0

        if [ "${#start}" -gt 5 ] || [ "${#end}" -gt 5 ]; then
            IFS="${saved_ifs}"
            echo "port number too large in ${label}: ${item}" >&2
            return 1
        fi
        if [ "${start}" -lt 1 ] || [ "${end}" -gt 65535 ] || [ "${start}" -gt "${end}" ]; then
            IFS="${saved_ifs}"
            echo "ports/ranges in ${label} must be ascending and within 1-65535: ${item}" >&2
            return 1
        fi
        if [ "${start}" -le 443 ] && [ "${end}" -ge 443 ]; then
            PORT_SPEC_HAS_443=1
        fi

        if [ "${start}" -eq "${end}" ]; then
            canonical="${start}"
        else
            canonical="${start}-${end}"
        fi
        case ",${normalized}," in
            *,"${canonical}",*) ;;
            *) normalized="${normalized:+${normalized},}${canonical}" ;;
        esac
    done
    IFS="${saved_ifs}"
    PORT_SPEC_NORMALIZED="${normalized}"
    return 0
}

validate_profile_domain() {
    local entry="$1"
    local label="$2"
    local domain="${entry#^}"
    local item saved_ifs="${IFS}"

    case "${entry}" in
        ""|*[!a-zA-Z0-9.^-]*)
            echo "invalid hostname entry in ${label}: ${entry}" >&2
            return 1
            ;;
    esac
    case "${domain}" in
        ""|*^*|.*|*.|*..*)
            echo "invalid hostname entry in ${label}: ${entry}" >&2
            return 1
            ;;
    esac
    if [ "${#domain}" -gt 253 ]; then
        echo "hostname entry too long in ${label}" >&2
        return 1
    fi

    IFS="."
    for item in ${domain}; do
        if [ -z "${item}" ] || [ "${#item}" -gt 63 ]; then
            IFS="${saved_ifs}"
            echo "invalid DNS label in ${label}: ${entry}" >&2
            return 1
        fi
        case "${item}" in -*|*-) IFS="${saved_ifs}"; echo "DNS labels may not begin/end with a hyphen: ${entry}" >&2; return 1 ;; esac
    done
    IFS="${saved_ifs}"
    return 0
}

profile_ipset_arguments() {
    local mode="$1"
    PROFILE_IPSET_ARGS=""

    case "${mode}" in
        inherit)
            PROFILE_IPSET_ARGS="${IPSET_ARGS}"
            ;;
        none)
            PROFILE_IPSET_ARGS=""
            ;;
        include)
            if [ "${IPSET_INCLUDE_ENABLED:-0}" != "1" ]; then
                echo "custom profile requests ipset=include but the IPSet include filter is disabled" >&2
                return 1
            fi
            PROFILE_IPSET_ARGS=" --ipset=${ZAPRET_DIR}/${IPSET_INCLUDE_FILE:-ipset-all.txt}"
            ;;
        exclude)
            if [ "${IPSET_EXCLUDE_ENABLED:-0}" != "1" ]; then
                echo "custom profile requests ipset=exclude but the IPSet exclude filter is disabled" >&2
                return 1
            fi
            PROFILE_IPSET_ARGS=" --ipset-exclude=${ZAPRET_DIR}/${IPSET_EXCLUDE_FILE:-ipset-exclude-default.txt}"
            ;;
        both)
            if [ "${IPSET_INCLUDE_ENABLED:-0}" != "1" ] || [ "${IPSET_EXCLUDE_ENABLED:-0}" != "1" ]; then
                echo "custom profile requests ipset=both but both IPSet filters are not enabled" >&2
                return 1
            fi
            PROFILE_IPSET_ARGS=" --ipset=${ZAPRET_DIR}/${IPSET_INCLUDE_FILE:-ipset-all.txt} --ipset-exclude=${ZAPRET_DIR}/${IPSET_EXCLUDE_FILE:-ipset-exclude-default.txt}"
            ;;
        *)
            echo "invalid ipset mode in custom profile: ${mode}" >&2
            return 1
            ;;
    esac
    return 0
}

cleanup_custom_profile_lists() {
    if [ -d "${CUSTOM_PROFILE_LIST_DIR}" ] && [ ! -L "${CUSTOM_PROFILE_LIST_DIR}" ]; then
        rm -f "${CUSTOM_PROFILE_LIST_DIR}"/custom-profile-*.txt
        rmdir "${CUSTOM_PROFILE_LIST_DIR}" 2>/dev/null || true
    fi
}


prepare_custom_profile_hostlists() {
    local count i enabled name transport l7 hostname_supported
    local domains_count excludes_count domains_file excludes_file

    # A missing config means there are no custom profiles to keep; clean
    # only generated plugin-owned files during the preparation/cleanup phase.
    if [ ! -f "${CUSTOM_PROFILES_FILE}" ]; then
        cleanup_custom_profile_lists
        return 0
    fi

    if [ -L "${CUSTOM_PROFILE_LIST_DIR}" ]; then
        echo "custom profile hostlist directory must not be a symlink" >&2
        return 1
    fi
    if [ -e "${CUSTOM_PROFILE_LIST_DIR}" ] && [ ! -d "${CUSTOM_PROFILE_LIST_DIR}" ]; then
        echo "custom profile hostlist path exists but is not a directory" >&2
        return 1
    fi
    mkdir -p "${CUSTOM_PROFILE_LIST_DIR}" || return 1
    rm -f "${CUSTOM_PROFILE_LIST_DIR}"/custom-profile-*.txt

    count=$("${JQ_BIN}" 'length' "${CUSTOM_PROFILES_FILE}") || return 1
    if [ "${count}" -eq 0 ]; then
        cleanup_custom_profile_lists
        return 0
    fi
    i=0
    while [ "${i}" -lt "${count}" ]; do
        enabled=$("${JQ_BIN}" -r ".[${i}].enabled" "${CUSTOM_PROFILES_FILE}")
        if [ "${enabled}" != "true" ]; then
            i=$((i + 1))
            continue
        fi
        name=$("${JQ_BIN}" -r ".[${i}].name" "${CUSTOM_PROFILES_FILE}")
        transport=$("${JQ_BIN}" -r ".[${i}].transport" "${CUSTOM_PROFILES_FILE}")
        l7=$("${JQ_BIN}" -r ".[${i}].l7 | join(\",\")" "${CUSTOM_PROFILES_FILE}")
        domains_count=$("${JQ_BIN}" -r "(.[${i}].domains // []) | length" "${CUSTOM_PROFILES_FILE}")
        excludes_count=$("${JQ_BIN}" -r "(.[${i}].exclude_domains // []) | length" "${CUSTOM_PROFILES_FILE}")
        domains_file="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-${name}-domains.txt"
        excludes_file="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-${name}-exclude.txt"

        # Hostname lists only make sense for TCP flows and pure QUIC UDP.
        # Do not apply global hostname exclusions to Discord/STUN, WireGuard,
        # DHT, or unknown UDP traffic that has no hostname.
        hostname_supported=0
        case "${transport}:${l7}" in
            tcp:*|udp:quic) hostname_supported=1 ;;
        esac
        if [ "${hostname_supported}" -eq 1 ]; then
            if [ "${domains_count}" -gt 0 ]; then
                "${JQ_BIN}" -r ".[${i}].domains[]?" "${CUSTOM_PROFILES_FILE}" > "${domains_file}" || return 1
                chmod 600 "${domains_file}" || return 1
            fi

            if { [ "${excludes_count}" -gt 0 ] || { [ -s "${HOSTLIST_EXCLUDE}" ] && [ -r "${HOSTLIST_EXCLUDE}" ]; }; }; then
                : > "${excludes_file}" || return 1
                if [ -s "${HOSTLIST_EXCLUDE}" ] && [ -r "${HOSTLIST_EXCLUDE}" ]; then
                    cat "${HOSTLIST_EXCLUDE}" >> "${excludes_file}" || return 1
                    printf '\n' >> "${excludes_file}"
                fi
                if [ "${excludes_count}" -gt 0 ]; then
                    "${JQ_BIN}" -r ".[${i}].exclude_domains[]?" "${CUSTOM_PROFILES_FILE}" >> "${excludes_file}" || return 1
                fi
                if [ -s "${excludes_file}" ]; then
                    chmod 600 "${excludes_file}" || return 1
                else
                    rm -f "${excludes_file}"
                fi
            fi
        fi
        i=$((i + 1))
    done
    return 0
}
validate_custom_profiles() {
    local count i enabled name order transport ports l7 strategy ipset
    local domains_count excludes_count j entry token saved_ifs
    CUSTOM_PROFILE_COUNT=0
    CUSTOM_TCP_PORTS=""
    CUSTOM_UDP_PORTS=""
    CUSTOM_PROFILE_ARGS=""
    CUSTOM_PROFILE_ACTIVE=0

    if [ -z "${JQ_BIN}" ] || [ ! -x "${JQ_BIN}" ]; then
        echo "jq is required to validate custom profiles" >&2
        return 1
    fi
    if [ ! -f "${CUSTOM_PROFILES_FILE}" ]; then
        return 0
    fi

    local bytes
    bytes=$(wc -c < "${CUSTOM_PROFILES_FILE}" | tr -d '[:space:]')
    case "${bytes}" in ""|*[!0123456789]*) echo "could not determine custom profile JSON size" >&2; return 1 ;; esac
    if [ "${bytes}" -gt 65536 ]; then
        echo "custom profile JSON exceeds the 64 KiB safety limit" >&2
        return 1
    fi

    if ! "${JQ_BIN}" -e '
        type == "array" and length <= 8 and
        ([.[].name] | unique | length) == length and
        ([.[].order] | unique | length) == length and
        all(.[]; type == "object" and
            (.enabled | type == "boolean") and
            (.name | type == "string") and
            (.order | (type == "number" and floor == .)) and
            (.transport | type == "string") and
            (.ports | type == "string") and
            (.l7 | (type == "array" and all(.[]; type == "string") and length > 0)) and
            ((.domains // []) | (type == "array" and all(.[]; type == "string"))) and
            ((.exclude_domains // []) | (type == "array" and all(.[]; type == "string"))) and
            ((.ipset // "inherit") | type == "string") and
            (.strategy | type == "string")
        )
    ' "${CUSTOM_PROFILES_FILE}" >/dev/null 2>&1; then
        echo "custom profiles must be a JSON array of at most 8 objects with typed fields and unique names/orders" >&2
        return 1
    fi

    count=$("${JQ_BIN}" 'length' "${CUSTOM_PROFILES_FILE}") || return 1
    CUSTOM_PROFILE_COUNT="${count}"
    i=0
    while [ "${i}" -lt "${count}" ]; do
        enabled=$("${JQ_BIN}" -r ".[${i}].enabled" "${CUSTOM_PROFILES_FILE}")
        name=$("${JQ_BIN}" -r ".[${i}].name" "${CUSTOM_PROFILES_FILE}")
        order=$("${JQ_BIN}" -r ".[${i}].order | tostring" "${CUSTOM_PROFILES_FILE}")
        transport=$("${JQ_BIN}" -r ".[${i}].transport" "${CUSTOM_PROFILES_FILE}")
        ports=$("${JQ_BIN}" -r ".[${i}].ports" "${CUSTOM_PROFILES_FILE}")
        l7=$("${JQ_BIN}" -r ".[${i}].l7 | join(\",\")" "${CUSTOM_PROFILES_FILE}")
        strategy=$("${JQ_BIN}" -r ".[${i}].strategy" "${CUSTOM_PROFILES_FILE}")
        ipset=$("${JQ_BIN}" -r ".[${i}].ipset // \"inherit\"" "${CUSTOM_PROFILES_FILE}")
        domains_count=$("${JQ_BIN}" -r "(.[${i}].domains // []) | length" "${CUSTOM_PROFILES_FILE}")
        excludes_count=$("${JQ_BIN}" -r "(.[${i}].exclude_domains // []) | length" "${CUSTOM_PROFILES_FILE}")

        case "${name}" in
            ""|*[!a-zA-Z0-9_-]*|[!a-zA-Z0-9]*)
                echo "invalid custom profile name: ${name}" >&2
                return 1
                ;;
        esac
        if [ "${#name}" -gt 32 ]; then
            echo "custom profile name exceeds 32 characters: ${name}" >&2
            return 1
        fi
        case "${order}" in ""|*[!0123456789]*) echo "custom profile order must be an integer from 0 to 9999: ${name}" >&2; return 1 ;; esac
        if [ "${#order}" -gt 4 ]; then
            echo "custom profile order must be from 0 to 9999: ${name}" >&2
            return 1
        fi

        if [ "${enabled}" != "true" ]; then
            i=$((i + 1))
            continue
        fi

        case "${transport}" in tcp|udp) ;; *) echo "custom profile ${name}: transport must be tcp or udp" >&2; return 1 ;; esac
        case "${ipset}" in inherit|none|include|exclude|both) ;; *) echo "custom profile ${name}: invalid ipset mode" >&2; return 1 ;; esac
        profile_ipset_arguments "${ipset}" || return 1
        normalize_port_spec "${ports}" "custom profile ${name}" || return 1
        ports="${PORT_SPEC_NORMALIZED}"

        saved_ifs="${IFS}"
        IFS=","
        local seen_l7=","
        for token in ${l7}; do
            case "${transport}:${token}" in
                tcp:http|tcp:tls|tcp:unknown|udp:quic|udp:wireguard|udp:dht|udp:discord|udp:stun|udp:unknown) ;;
                *) IFS="${saved_ifs}"; echo "custom profile ${name}: unsupported L7 protocol ${token} for ${transport}" >&2; return 1 ;;
            esac
            case "${seen_l7}" in
                *,"${token}",*) IFS="${saved_ifs}"; echo "custom profile ${name}: duplicate L7 protocol ${token}" >&2; return 1 ;;
            esac
            seen_l7="${seen_l7}${token},"
        done
        IFS="${saved_ifs}"

        validate_strategy_arguments "custom profile ${name}" "${strategy}" || return 1
        if [ "${transport}" = "udp" ] && [ "${l7}" != "quic" ] && { [ "${domains_count}" -gt 0 ] || [ "${excludes_count}" -gt 0 ]; }; then
            echo "custom profile ${name}: hostname lists are supported only for TCP or a pure QUIC UDP profile" >&2
            return 1
        fi

        j=0
        while [ "${j}" -lt "${domains_count}" ]; do
            entry=$("${JQ_BIN}" -r ".[${i}].domains[${j}]" "${CUSTOM_PROFILES_FILE}")
            validate_profile_domain "${entry}" "custom profile ${name} domains" || return 1
            j=$((j + 1))
        done
        j=0
        while [ "${j}" -lt "${excludes_count}" ]; do
            entry=$("${JQ_BIN}" -r ".[${i}].exclude_domains[${j}]" "${CUSTOM_PROFILES_FILE}")
            validate_profile_domain "${entry}" "custom profile ${name} exclude_domains" || return 1
            j=$((j + 1))
        done

        if [ "${transport}" = "tcp" ]; then
            saved_ifs="${IFS}"
            IFS=","
            for token in ${ports}; do
                case ",${CUSTOM_TCP_PORTS}," in
                    *,"${token}",*) ;;
                    *) CUSTOM_TCP_PORTS="${CUSTOM_TCP_PORTS:+${CUSTOM_TCP_PORTS},}${token}" ;;
                esac
            done
            IFS="${saved_ifs}"
        else
            saved_ifs="${IFS}"
            IFS=","
            for token in ${ports}; do
                case ",${CUSTOM_UDP_PORTS}," in
                    *,"${token}",*) ;;
                    *) CUSTOM_UDP_PORTS="${CUSTOM_UDP_PORTS:+${CUSTOM_UDP_PORTS},}${token}" ;;
                esac
            done
            IFS="${saved_ifs}"
        fi
        i=$((i + 1))
    done

    return 0
}

build_custom_profile_args() {
    local profiles_json profile_json name transport ports l7 strategy ipset
    local domains_file excludes_file profile_hostlist_args first=1

    CUSTOM_PROFILE_ARGS=""
    CUSTOM_PROFILE_ACTIVE=0
    [ -f "${CUSTOM_PROFILES_FILE}" ] || return 0

    profiles_json=$("${JQ_BIN}" -c 'sort_by(.order)[] | select(.enabled == true)' "${CUSTOM_PROFILES_FILE}") || return 1
    [ -n "${profiles_json}" ] || return 0

    while IFS= read -r profile_json; do
        [ -n "${profile_json}" ] || continue
        name=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.name')
        transport=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.transport')
        ports=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.ports')
        l7=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.l7 | join(",")')
        strategy=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.strategy')
        ipset=$(printf '%s\n' "${profile_json}" | "${JQ_BIN}" -r '.ipset // "inherit"')
        normalize_port_spec "${ports}" "custom profile ${name}" || return 1
        ports="${PORT_SPEC_NORMALIZED}"
        profile_ipset_arguments "${ipset}" || return 1

        profile_hostlist_args=""
        domains_file="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-${name}-domains.txt"
        excludes_file="${CUSTOM_PROFILE_LIST_DIR}/custom-profile-${name}-exclude.txt"
        if [ -s "${domains_file}" ]; then
            profile_hostlist_args="${profile_hostlist_args} --hostlist=${domains_file}"
        fi
        if [ -s "${excludes_file}" ]; then
            profile_hostlist_args="${profile_hostlist_args} --hostlist-exclude=${excludes_file}"
        fi

        if [ "${first}" -eq 0 ]; then
            CUSTOM_PROFILE_ARGS="${CUSTOM_PROFILE_ARGS} --new"
        fi
        CUSTOM_PROFILE_ARGS="${CUSTOM_PROFILE_ARGS} --filter-${transport}=${ports} --filter-l7=${l7}${profile_hostlist_args}${PROFILE_IPSET_ARGS} ${strategy}"
        first=0
        CUSTOM_PROFILE_ACTIVE=1
    done <<EOF
${profiles_json}
EOF
    return 0
}

build_tcp_intercept_ports() {
    local combined="${PORTS:-}"
    local port saved_ifs="${IFS}"

    # Named TCP profiles require interception on their own ports.
    if [ "${YOUTUBE_TCP_ENABLED:-0}" = "1" ] || [ "${DISCORD_TCP_ENABLED:-0}" = "1" ]; then
        case ",${combined}," in
            *,443,*) ;;
            *) combined="${combined:+${combined},}443" ;;
        esac
    fi

    if [ "${DISCORD_TCP_ENABLED:-0}" = "1" ]; then
        for port in 2053 2083 2087 2096 8443; do
            case ",${combined}," in
                *,"${port}",*) ;;
                *) combined="${combined:+${combined},}${port}" ;;
            esac
        done
    fi

    IFS=","
    for port in ${CUSTOM_TCP_PORTS}; do
        case ",${combined}," in
            *,"${port}",*) ;;
            *) combined="${combined:+${combined},}${port}" ;;
        esac
    done
    IFS="${saved_ifs}"
    printf '%s\n' "${combined}"
}

build_udp_intercept_ports() {
    local combined=""
    local port count=0 saved_ifs="${IFS}"

    # Every UDP profile shares one divert rule; dvtws2 selects a profile
    # based on its own ordered --filter-udp and --filter-l7 filters.
    if [ -n "${QUIC_ARGS:-}" ] || [ "${YOUTUBE_QUIC_ENABLED:-0}" = "1" ]; then
        combined="443"
    fi

    IFS=","
    for port in ${UDP_PORTS}; do
        case ",${combined}," in
            *,"${port}",*) ;;
            *) combined="${combined:+${combined},}${port}" ;;
        esac
    done
    for port in ${CUSTOM_UDP_PORTS}; do
        case ",${combined}," in
            *,"${port}",*) ;;
            *) combined="${combined:+${combined},}${port}" ;;
        esac
    done
    IFS="${saved_ifs}"

    IFS=","
    for port in ${combined}; do
        count=$((count + 1))
    done
    IFS="${saved_ifs}"
    if [ "${count}" -gt 30 ]; then
        echo "combined UDP interception list exceeds ipfw's 30-item limit" >&2
        return 1
    fi
    printf '%s\n' "${combined}"
}

validate_ipfw_rule_capacity() {
    local rule_capacity=$((RULE_MAX - RULE_BASE + 1))
    local rule_count=0
    local IFS_SAVED="${IFS}"

    validate_tcp_ports || return 1
    validate_ipset_configuration || return 1
    validate_managed_profiles || return 1
    validate_udp_configuration || return 1
    validate_custom_profiles || return 1

    TCP_INTERCEPT_PORTS=$(build_tcp_intercept_ports)
    UDP_INTERCEPT_PORTS=$(build_udp_intercept_ports) || return 1

    IFS=","
    for port in ${TCP_INTERCEPT_PORTS}; do
        rule_count=$((rule_count + 1))
    done
    IFS="${IFS_SAVED}"

    if [ -n "${UDP_INTERCEPT_PORTS}" ]; then
        rule_count=$((rule_count + 1))
    fi

    if [ "${rule_count}" -gt "${rule_capacity}" ]; then
        echo "configured TCP and aggregated UDP interception require ${rule_count} ipfw rules; reserved range ${RULE_BASE}-${RULE_MAX} has room for ${rule_capacity}" >&2
        return 1
    fi

    return 0
}

# Install ipfw divert rules — one per TCP interception port, plus one
# aggregated UDP rule for built-in QUIC, the additional UDP profile, and all
# enabled custom UDP profiles. The combined UDP list may contain up to 30
# comma-separated ports/ranges.
#
#   divert 989 tcp from any to any 80,443 out not diverted not sockarg
#
# Loop-guard: `not diverted not sockarg` — BOTH conditions combined.
# - `not diverted` checks the M_IPFW_DIVERT mbuf flag (IPv4).
# - `not sockarg` checks SO_USER_COOKIE (IPv4 only; FreeBSD kernel
#   ignores sockarg on IPv6, which is why upstream uses a second
#   divert socket for IPv6 and falls back to `diverted`-only.)
#
# Either of these flags alone was insufficient in our virtio tests
# (million-packet loops). Combined with the `pfctl -d ; pfctl -e`
# bounce in configure_ipfw_reinject above, traffic flows correctly.
#
# `xmit $wan_dev` scopes to outbound on the WAN device so we only
# intercept traffic actually leaving the firewall.
#
# SOURCE_NETS (optional, comma-separated IPv4 hosts/CIDRs) narrows the
# divert to traffic FROM those networks. This works because ipfw is
# deliberately hooked AHEAD of pf on the outbound chain (see
# configure_ipfw_reinject) — the packet still carries the LAN client's
# pre-NAT source address when the rule is evaluated. Empty SOURCE_NETS
# keeps the historical match-everything behavior.
#
# When SOURCE_NETS is set we install a SECOND rule per port matching
# `from me`, so the firewall's own traffic (the safety watchdog's control
# probe) still goes through the bypass. It has to be a separate rule:
# ipfw's `me` is a standalone keyword and is NOT accepted inside a
# comma-separated address list — `from 10.0.30.0/24,me` fails to parse
# with `hostname "me" unknown` and the whole rule is silently skipped.
# Both rules share one rule number; ipfw allows duplicates and evaluates
# them in insertion order, and `ipfw delete N` removes both.
install_ipfw_rules() {
    local wan_dev="$1"
    local src_spec="any"

    validate_ipfw_rule_capacity || return 1

    if [ -n "${SOURCE_NETS}" ]; then
        src_spec="${SOURCE_NETS}"
    fi

    remove_ipfw_rules

    local rulenum=${RULE_BASE}
    local IFS_SAVED="${IFS}"
    IFS=","

    for port in ${TCP_INTERCEPT_PORTS}; do
        # src_spec is quoted: IFS is "," here and the address list must
        # reach ipfw as a single token.
        if ! /sbin/ipfw -f add ${rulenum} divert ${DIVERT_PORT} tcp \
            from "${src_spec}" to any ${port} \
            out not diverted not sockarg xmit ${wan_dev} >/dev/null 2>&1; then
            remove_ipfw_rules
            IFS="${IFS_SAVED}"
            echo "failed to install ipfw divert rule for port ${port} from '${src_spec}' — check Source Networks syntax" >&2
            return 1
        fi

        if [ -n "${SOURCE_NETS}" ]; then
            if ! /sbin/ipfw -qf add ${rulenum} divert ${DIVERT_PORT} tcp \
                from me to any ${port} \
                out not diverted not sockarg xmit ${wan_dev}; then
                remove_ipfw_rules
                IFS="${IFS_SAVED}"
                echo "failed to install ipfw rule for firewall-originated TCP traffic on port ${port}" >&2
                return 1
            fi
        fi

        rulenum=$((rulenum + 1))
    done

    # All enabled UDP profiles share one divert rule. The comma-separated
    # union is validated before installation; dvtws2 then selects the first
    # matching profile by its ordered transport/port/L7 filters.
    if [ -n "${UDP_INTERCEPT_PORTS}" ]; then
        if ! /sbin/ipfw -f add ${rulenum} divert ${DIVERT_PORT} udp \
            from "${src_spec}" to any "${UDP_INTERCEPT_PORTS}" \
            out not diverted not sockarg xmit ${wan_dev} >/dev/null 2>&1; then
            remove_ipfw_rules
            IFS="${IFS_SAVED}"
            echo "failed to install UDP divert rule for ${UDP_INTERCEPT_PORTS} from '${src_spec}'" >&2
            return 1
        fi

        if [ -n "${SOURCE_NETS}" ]; then
            if ! /sbin/ipfw -qf add ${rulenum} divert ${DIVERT_PORT} udp \
                from me to any "${UDP_INTERCEPT_PORTS}" \
                out not diverted not sockarg xmit ${wan_dev}; then
                remove_ipfw_rules
                IFS="${IFS_SAVED}"
                echo "failed to install UDP rule for firewall-originated traffic" >&2
                return 1
            fi
        fi

        rulenum=$((rulenum + 1))
    fi

    IFS="${IFS_SAVED}"
}

start_service() {
    load_config

    if [ "${ZAPRET_ENABLED}" != "1" ]; then
        echo "zapret is not running (disabled in settings)"
        exit 0
    fi

    if ! validate_ipfw_rule_capacity; then
        # Fail open: an invalid config must not leave stale divert rules
        # pointing to a dead or mismatched dvtws2 listener.
        remove_ipfw_rules
        exit 1
    fi

    # Already running?
    if [ -f "${SUPERVISOR_PIDFILE}" ] && kill -0 "$(cat ${SUPERVISOR_PIDFILE})" 2>/dev/null; then
        echo "zapret is already running as pid $(cat ${PIDFILE} 2>/dev/null || echo unknown)"
        exit 0
    fi

    if [ ! -x "${DVTWS_BIN}" ]; then
        echo "dvtws2 binary not found at ${DVTWS_BIN} — run setup.sh first" >&2
        exit 1
    fi

    # Generate only plugin-owned per-profile hostlists after full validation
    # and before dvtws2 opens them. Validation itself remains side-effect free.
    prepare_custom_profile_hostlists || {
        echo "failed to prepare custom profile hostlists" >&2
        exit 1
    }

    # Load required kernel modules. ipdivert is the divert socket
    # backend; ipfw is the firewall that owns our divert rules.
    kldstat -q -m ipdivert || kldload ipdivert
    kldstat -q -m ipfw     || kldload ipfw
    ensure_ipfw_default_accept
    configure_ipfw_reinject

    local wan_dev=$(resolve_interface "${WAN_IF}")
    if [ -z "${wan_dev}" ]; then
        echo "could not resolve WAN interface '${WAN_IF}' to a kernel device" >&2
        exit 1
    fi

    # Build dvtws2 args. The managed service profiles are intentionally
    # ordered ahead of the generic TCP/QUIC profiles because zapret2 evaluates
    # the first matching profile.
    local args="--port=${DIVERT_PORT}"
    [ -f "${LUA_LIB}" ]      && args="${args} --lua-init=@${LUA_LIB}"
    [ -f "${LUA_ANTIDPI}" ]  && args="${args} --lua-init=@${LUA_ANTIDPI}"

    local hostlist_args=""
    local hostlist_noauto_args=""
    local hostlist_exclude_args=""

    if [ "${HOSTLIST_MODE}" = "list" ] && [ -f "${HOSTLIST}" ] && [ -s "${HOSTLIST}" ]; then
        hostlist_args="${hostlist_args} --hostlist=${HOSTLIST}"
        hostlist_noauto_args="${hostlist_noauto_args} --hostlist=${HOSTLIST}"
    elif [ "${HOSTLIST_MODE}" = "auto" ]; then
        touch "${AUTOHOSTLIST}" 2>/dev/null
        hostlist_args="${hostlist_args} --hostlist-auto=${AUTOHOSTLIST}"
        hostlist_noauto_args="${hostlist_noauto_args} --hostlist=${AUTOHOSTLIST}"
    fi

    if [ -f "${HOSTLIST_EXCLUDE}" ] && [ -s "${HOSTLIST_EXCLUDE}" ]; then
        hostlist_exclude_args=" --hostlist-exclude=${HOSTLIST_EXCLUDE}"
        hostlist_args="${hostlist_args}${hostlist_exclude_args}"
        hostlist_noauto_args="${hostlist_noauto_args}${hostlist_exclude_args}"
    fi

    local profile_started=0
    build_custom_profile_args || {
        echo "could not build custom profile arguments" >&2
        exit 1
    }
    if [ -n "${CUSTOM_PROFILE_ARGS}" ]; then
        args="${args}${CUSTOM_PROFILE_ARGS}"
        profile_started=1
    fi

    # YouTube / Google TLS profile (TCP/443).
    if [ "${YOUTUBE_TCP_ENABLED:-0}" = "1" ]; then
        if [ "${profile_started}" = "1" ]; then
            args="${args} --new"
        fi
        args="${args} --filter-tcp=443 --filter-l7=tls --hostlist=${YOUTUBE_HOSTLIST}${hostlist_exclude_args}${IPSET_ARGS} ${YOUTUBE_TCP_ARGS}"
        profile_started=1
    fi

    # Discord's desktop/web TLS endpoints also use several non-standard ports.
    if [ "${DISCORD_TCP_ENABLED:-0}" = "1" ]; then
        if [ "${profile_started}" = "1" ]; then
            args="${args} --new"
        fi
        args="${args} --filter-tcp=443,2053,2083,2087,2096,8443 --filter-l7=tls --hostlist=${DISCORD_HOSTLIST}${hostlist_exclude_args}${IPSET_ARGS} ${DISCORD_TCP_ARGS}"
        profile_started=1
    fi

    # Keep the existing generic TCP strategy as the fallback. If a named
    # profile was emitted first, start the fallback with --new.
    if [ "${profile_started}" = "1" ]; then
        args="${args} --new"
    fi
    args="${args} --filter-tcp=${PORTS}${IPSET_ARGS}"
    [ -n "${HTTP_ARGS}" ]    && args="${args} ${HTTP_ARGS}"
    [ -n "${HTTPS_ARGS}" ]   && args="${args} ${HTTPS_ARGS}"
    args="${args}${hostlist_args}"

    # Specific YouTube / Google QUIC profile must precede the generic QUIC
    # strategy so that its per-domain strategy is selected first.
    if [ "${YOUTUBE_QUIC_ENABLED:-0}" = "1" ]; then
        args="${args} --new --filter-udp=443 --filter-l7=quic --hostlist=${YOUTUBE_HOSTLIST}${hostlist_exclude_args}${IPSET_ARGS} ${YOUTUBE_QUIC_ARGS}"
    fi

    # Generic QUIC is optional and keeps its historical behavior when set.
    if [ -n "${QUIC_ARGS}" ]; then
        args="${args} --new --filter-udp=443 --filter-l7=quic${hostlist_noauto_args}${IPSET_ARGS} ${QUIC_ARGS}"
    fi

    # Optional built-in Additional UDP profile is a fallback after custom
    # profiles and named service profiles. Only a pure QUIC profile can use
    # hostname hostlists; other UDP traffic should be scoped with IPSet.
    if [ -n "${UDP_PORTS}" ]; then
        local udp_hostlist_args=""
        if [ "${UDP_FILTER_L7}" = "quic" ]; then
            udp_hostlist_args="${hostlist_noauto_args}"
        fi
        args="${args} --new --filter-udp=${UDP_PORTS} --filter-l7=${UDP_FILTER_L7}${udp_hostlist_args}${IPSET_ARGS} ${UDP_ARGS}"
    fi

    [ -n "${EXTRA_ARGS}" ] && args="${args} ${EXTRA_ARGS}"

    # Run dvtws2 under daemon(8) -r so a crash auto-restarts within 1s.
    # No --daemon / --pidfile to dvtws2 — daemon(8) manages those.
    #
    # `--user=nobody` drops privs to UID 65534 AFTER dvtws2 has bound its
    # raw/divert sockets. This is what enables our `not uid 65534` ipfw
    # filter (see remove/install rules below) to skip dvtws2's reinjected
    # packets — without it, the reinjects re-enter our own divert rule
    # and produce the catastrophic million-packet loop observed on virtio.
    /usr/sbin/daemon \
        -P "${SUPERVISOR_PIDFILE}" \
        -p "${PIDFILE}" \
        -r -R 1 \
        -t zapret2 \
        -f \
        ${DVTWS_BIN} ${args} --sockarg=0x200 --user=nobody

    sleep 1
    if [ ! -f "${SUPERVISOR_PIDFILE}" ] || ! kill -0 "$(cat ${SUPERVISOR_PIDFILE})" 2>/dev/null; then
        echo "dvtws2 supervisor failed to start" >&2
        exit 1
    fi
    if [ ! -f "${PIDFILE}" ] || ! kill -0 "$(cat ${PIDFILE})" 2>/dev/null; then
        sleep 2
        if [ ! -f "${PIDFILE}" ] || ! kill -0 "$(cat ${PIDFILE})" 2>/dev/null; then
            kill "$(cat ${SUPERVISOR_PIDFILE})" 2>/dev/null
            rm -f "${SUPERVISOR_PIDFILE}"
            echo "dvtws2 child failed to start — check strategy arguments" >&2
            exit 1
        fi
    fi

    if ! install_ipfw_rules "${wan_dev}"; then
        stop_service
        exit 1
    fi

    # Start the safety watchdog under daemon(8) too. It probes a control URL
    # every minute and stops the service if 3 consecutive checks fail —
    # so a misconfigured strategy that breaks general HTTPS auto-recovers
    # within ~3 minutes instead of leaving the household offline.
    if [ -x "${WATCHDOG_LOOP}" ]; then
        /usr/sbin/daemon \
            -P "${WATCHDOG_SUPERVISOR_PIDFILE}" \
            -p "${WATCHDOG_PIDFILE}" \
            -r -R 5 \
            -t zapret-watchdog \
            -f \
            "${WATCHDOG_LOOP}"
    fi

    echo "zapret is running as pid $(cat ${PIDFILE}) (supervisor pid $(cat ${SUPERVISOR_PIDFILE}))"
}

stop_service() {
    # Remove ipfw divert rules FIRST so traffic flows normally during
    # the tear-down window. If we killed dvtws2 first, the rules would
    # still divert to a dead socket and packets would drop until we got
    # around to removing them.
    remove_ipfw_rules

    # Kill the watchdog FIRST (before its supervisor can respawn it).
    # Also clean any orphans from previous installs that lost their
    # supervisor's pidfile during pkg upgrade.
    if [ -f "${WATCHDOG_SUPERVISOR_PIDFILE}" ]; then
        kill "$(cat ${WATCHDOG_SUPERVISOR_PIDFILE})" 2>/dev/null
        rm -f "${WATCHDOG_SUPERVISOR_PIDFILE}"
    fi
    if [ -f "${WATCHDOG_PIDFILE}" ]; then
        kill "$(cat ${WATCHDOG_PIDFILE})" 2>/dev/null
        rm -f "${WATCHDOG_PIDFILE}"
    fi
    pkill -f watchdog_loop.sh 2>/dev/null
    pkill -f "daemon: zapret-watchdog" 2>/dev/null
    rm -f /var/run/zapret-watchdog.state

    # Kill the dvtws2 supervisor so daemon -r doesn't respawn dvtws2
    if [ -f "${SUPERVISOR_PIDFILE}" ]; then
        kill "$(cat ${SUPERVISOR_PIDFILE})" 2>/dev/null
        rm -f "${SUPERVISOR_PIDFILE}"
    fi

    # Then dvtws2 itself, in case it survives or wasn't supervised
    if [ -f "${PIDFILE}" ]; then
        kill "$(cat ${PIDFILE})" 2>/dev/null
        rm -f "${PIDFILE}"
    fi
    killall dvtws2 2>/dev/null
    cleanup_custom_profile_lists

    echo "zapret is not running (stopped)"
}

status_service() {
    # Output must match the convention ApiMutableServiceControllerBase
    # parses: substring "is running" → running; "not running" → stopped.
    if [ -f "${PIDFILE}" ] && kill -0 "$(cat ${PIDFILE})" 2>/dev/null; then
        echo "zapret is running as pid $(cat ${PIDFILE})"
    else
        echo "zapret is not running"
    fi
}

repair_service() {
    load_config

    if [ "${ZAPRET_ENABLED}" != "1" ]; then
        echo "zapret repair skipped (disabled in settings)"
        exit 0
    fi

    if ! validate_ipfw_rule_capacity; then
        # If the new config cannot be used, remove interception rules rather
        # than leave traffic diverted to a stale profile.
        remove_ipfw_rules
        exit 1
    fi

    # Repair is intended for events such as WAN DHCP/PPPoE renew where
    # OPNsense may disable or rebuild ipfw while dvtws2 itself keeps running.
    # Do not restart the daemon here.
    if [ ! -f "${PIDFILE}" ] || ! kill -0 "$(cat ${PIDFILE})" 2>/dev/null; then
        echo "zapret repair skipped (dvtws2 is not running)"
        exit 0
    fi

    kldstat -q -m ipdivert || kldload ipdivert
    kldstat -q -m ipfw     || kldload ipfw

    ensure_ipfw_default_accept
    configure_ipfw_reinject

    local wan_dev=$(resolve_interface "${WAN_IF}")
    if [ -z "${wan_dev}" ]; then
        echo "could not resolve WAN interface '${WAN_IF}' to a kernel device" >&2
        exit 1
    fi

    install_ipfw_rules "${wan_dev}" || exit 1

    echo "zapret firewall state repaired on ${wan_dev}"
}

reconfigure_service() {
    /usr/local/sbin/configctl template reload OPNsense/Zapret

    load_config

    if [ "${ZAPRET_ENABLED}" = "1" ]; then
        stop_service > /dev/null 2>&1
        sleep 1
        start_service
    else
        stop_service
    fi
}

case "$1" in
    start)       start_service ;;
    stop)        stop_service ;;
    restart)     stop_service > /dev/null 2>&1; sleep 1; start_service ;;
    status)      status_service ;;
    repair)      repair_service ;;
    reconfigure) reconfigure_service ;;
    *)
        echo "usage: zapret_service.sh {start|stop|restart|status|repair|reconfigure}" >&2
        exit 1
        ;;
esac

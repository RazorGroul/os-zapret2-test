#!/bin/sh
# Sourced library: reversible IPFW state; PF is never disabled.
# The caller defines state paths, rule numbers, command paths and rule range.

ipfw_state_position() {
    local head wanted_hook
    head="$1"
    wanted_hook="$2"
    [ -x "$PFILCTL_BIN" ] || { echo "unknown"; return 0; }
    "$PFILCTL_BIN" heads 2>/dev/null | awk -v wanted_head="$head" -v wanted_hook="$wanted_hook" '
        /^[[:space:]]*(inet|inet6|ethernet)[[:space:]]+/ {
            current_head=$1
        }
        current_head == wanted_head && $1 == "Out" {
            if ($2 == wanted_hook) ipfw_line=NR
            if ($2 ~ /^pf:default-out/) pf_line=NR
        }
        END {
            if (!ipfw_line) print "absent"
            else if (!pf_line) print "unknown"
            else if (ipfw_line > pf_line) print "before"
            else print "after"
        }'
}

ipfw_state_read() {
    [ -f "$IPFW_STATE_FILE" ] && [ ! -L "$IPFW_STATE_FILE" ] || {
        echo "IPFW state file is missing or unsafe" >&2; return 1;
    }
    {
        IFS= read -r IPFW_SAVED_MODULE || return 1
        IFS= read -r IPFW_SAVED_ENABLE || return 1
        IFS= read -r IPFW_SAVED_ONE_PASS || return 1
        IFS= read -r IPFW_SAVED_DEFAULT || return 1
        IFS= read -r IPFW_SAVED6_ENABLE || return 1
        IFS= read -r IPFW_SAVED4_ORDER || return 1
        IFS= read -r IPFW_SAVED6_ORDER || return 1
    } < "$IPFW_STATE_FILE"
    for value in "$IPFW_SAVED_MODULE" "$IPFW_SAVED_ENABLE" "$IPFW_SAVED_ONE_PASS" "$IPFW_SAVED_DEFAULT" "$IPFW_SAVED6_ENABLE"; do
        case "$value" in 0|1) ;; *) echo "invalid IPFW state value" >&2; return 1 ;; esac
    done
    case "$IPFW_SAVED4_ORDER:$IPFW_SAVED6_ORDER" in
        before:before|before:after|before:absent|before:unknown|after:before|after:after|after:absent|after:unknown|absent:before|absent:after|absent:absent|absent:unknown|unknown:before|unknown:after|unknown:absent|unknown:unknown) ;;
        *) echo "invalid saved pfil hook order" >&2; return 1 ;;
    esac
    return 0
}

ipfw_state_capture() {
    local fw_enable fw_one_pass fw_default fw6_enable order4 order6 tmp
    [ ! -e "$IPFW_STATE_FILE" ] || { echo "IPFW state already exists; recover previous service state first" >&2; return 1; }
    if [ "$IPFW_MODULE_WAS_LOADED" = "1" ]; then
        fw_enable=$("$SYSCTL_BIN" -n net.inet.ip.fw.enable 2>/dev/null) || return 1
        fw_one_pass=$("$SYSCTL_BIN" -n net.inet.ip.fw.one_pass 2>/dev/null) || return 1
        fw_default=$("$SYSCTL_BIN" -n net.inet.ip.fw.default_to_accept 2>/dev/null) || return 1
        fw6_enable=$("$SYSCTL_BIN" -n net.inet6.ip6.fw.enable 2>/dev/null) || {
            echo "IPv6 IPFW control is unavailable; refusing incomplete dual-stack interception" >&2; return 1;
        }
        for value in "$fw_enable" "$fw_one_pass" "$fw_default" "$fw6_enable"; do
            case "$value" in 0|1) ;; *) echo "unexpected IPFW sysctl value: $value" >&2; return 1 ;; esac
        done
        # Capture hook positions even when IPFW is currently disabled:
        # its hooks may still be linked and must be restored to their prior order.
        order4=$(ipfw_state_position inet ipfw:default)
        order6=$(ipfw_state_position inet6 ipfw:default6)
        case "$order4:$order6" in *unknown*) echo "could not determine current IPv4/IPv6 pfil hook order" >&2; return 1 ;; esac
    else
        # The module was not active before startup. Capture its freshly exposed
        # defaults so loading it for this service does not leave changed sysctls.
        fw_enable=0
        fw_one_pass=$("$SYSCTL_BIN" -n net.inet.ip.fw.one_pass 2>/dev/null) || return 1
        fw_default=$("$SYSCTL_BIN" -n net.inet.ip.fw.default_to_accept 2>/dev/null) || return 1
        fw6_enable=0
        order4=absent
        order6=absent
    fi
    tmp="$IPFW_STATE_FILE.tmp"
    (umask 077; printf '%s\n' "$IPFW_MODULE_WAS_LOADED" "$fw_enable" "$fw_one_pass" "$fw_default" "$fw6_enable" "$order4" "$order6" > "$tmp") || return 1
    mv "$tmp" "$IPFW_STATE_FILE" || { rm -f "$tmp"; return 1; }
    ipfw_state_read
}

ipfw_state_list_rules() {
    "$IPFW_BIN" list 2>/dev/null || {
        echo "unable to read the active IPFW ruleset" >&2
        return 1
    }
}

ipfw_state_get_rule() {
    local rule="$1" rules
    rules=$(ipfw_state_list_rules) || return 1
    printf '%s\n' "$rules" | awk -v rule="$rule" '$1 == rule { print }'
}

ipfw_state_check_empty_ruleset() {
    local rules
    rules=$(ipfw_state_list_rules) || return 1
    printf '%s\n' "$rules" | awk -v base="$RULE_BASE" -v max="$RULE_MAX" -v p4="$IPFW_PASS4_RULE" -v p6="$IPFW_PASS6_RULE" '
        $1 == 65535 { default_rule=1; next }
        ($1 >= base && $1 <= max) || $1 == p4 || $1 == p6 { next }
        NF { print "existing IPFW rule prevents safe temporary enable: " $0 > "/dev/stderr"; found=1 }
        END {
            if (!default_rule) {
                print "IPFW default rule 65535 is missing; refusing to enable the ruleset" > "/dev/stderr"
                found=1
            }
            exit found ? 1 : 0
        }'
}

ipfw_state_add_pass_rule() {
    local rule="$1" marker="$2" spec="$3" existing
    existing=$(ipfw_state_get_rule "$rule") || return 1
    if [ -f "$marker" ]; then
        if [ "$existing" = "$rule $spec" ]; then return 0; fi
        if [ -n "$existing" ]; then echo "IPFW pass-through rule $rule changed unexpectedly" >&2; return 1; fi
    elif [ -n "$existing" ]; then
        echo "IPFW rule $rule is occupied; refusing to overwrite it" >&2
        return 1
    fi
    (umask 077; printf '%s\n' 'os-zapret2' > "$marker") || return 1
    case "$spec" in
        "allow ip from any to any"|"allow ip6 from any to any") ;;
        *) rm -f "$marker"; echo "invalid temporary IPFW pass rule" >&2; return 1 ;;
    esac
    if ! "$IPFW_BIN" -q add "$rule" $spec; then
        rm -f "$marker"
        return 1
    fi
    return 0
}

ipfw_state_cleanup_pass_rule() {
    local rule="$1" marker="$2" spec="$3" existing
    [ -f "$marker" ] || return 0
    existing=$(ipfw_state_get_rule "$rule") || return 1
    if [ -z "$existing" ]; then
        rm -f "$marker"
    elif [ "$existing" = "$rule $spec" ]; then
        "$IPFW_BIN" -q delete "$rule" || return 1
        rm -f "$marker"
    else
        echo "not removing IPFW rule $rule: it no longer matches the temporary rule owned by os-zapret2" >&2
        return 1
    fi
}

ipfw_state_cleanup_pass_rules() {
    ipfw_state_cleanup_pass_rule "$IPFW_PASS4_RULE" "$IPFW_PASS4_MARKER" "allow ip from any to any" || return 1
    ipfw_state_cleanup_pass_rule "$IPFW_PASS6_RULE" "$IPFW_PASS6_MARKER" "allow ip6 from any to any" || return 1
    return 0
}

ipfw_state_ensure_passthrough() {
    ipfw_state_read || return 1
    [ "$IPFW_SAVED_ENABLE" = "0" ] || return 0
    # Never enable a previously disabled ruleset containing user rules.
    ipfw_state_check_empty_ruleset || return 1
    [ "$IPFW_SAVED_DEFAULT" = "1" ] && return 0
    ipfw_state_add_pass_rule "$IPFW_PASS4_RULE" "$IPFW_PASS4_MARKER" "allow ip from any to any" || return 1
    ipfw_state_add_pass_rule "$IPFW_PASS6_RULE" "$IPFW_PASS6_MARKER" "allow ip6 from any to any" || {
        ipfw_state_cleanup_pass_rules || true; return 1;
    }
    return 0
}

ipfw_state_configure() {
    ipfw_state_read || return 1
    [ -x "$PFILCTL_BIN" ] || { echo "pfilctl is required; PF will not be disabled as a fallback" >&2; return 1; }

    # Enabling IPv6 IPFW can activate IPv6 rules that were previously dormant.
    # If IPv4 IPFW is already active but IPv6 filtering was disabled, only
    # enable IPv6 when no unrelated rules exist; otherwise keep the saved
    # network policy and fail closed rather than silently changing it.
    if [ "$IPFW_SAVED_MODULE" = "1" ] && [ "$IPFW_SAVED_ENABLE" = "1" ] && [ "$IPFW_SAVED6_ENABLE" = "0" ]; then
        ipfw_state_check_empty_ruleset || {
            echo "IPv6 IPFW is disabled while IPv4 IPFW is active and unrelated rules exist; refusing to activate IPv6 filtering" >&2
            return 1
        }
        if [ "$IPFW_SAVED_DEFAULT" != "1" ]; then
            ipfw_state_add_pass_rule "$IPFW_PASS6_RULE" "$IPFW_PASS6_MARKER" "allow ip6 from any to any" || return 1
        fi
    fi

    "$SYSCTL_BIN" net.inet.ip.fw.one_pass=1 >/dev/null 2>&1 || return 1
    "$SYSCTL_BIN" net.inet.ip.fw.enable=1 >/dev/null 2>&1 || return 1
    "$SYSCTL_BIN" net.inet6.ip6.fw.enable=1 >/dev/null 2>&1 || return 1
    "$PFILCTL_BIN" unlink -o ipfw:default inet >/dev/null 2>&1 || true
    "$PFILCTL_BIN" link -o -a ipfw:default inet >/dev/null 2>&1 || {
        echo "failed to put IPv4 IPFW before PF with pfilctl" >&2; return 1;
    }
    "$PFILCTL_BIN" unlink -o ipfw:default6 inet6 >/dev/null 2>&1 || true
    "$PFILCTL_BIN" link -o -a ipfw:default6 inet6 >/dev/null 2>&1 || {
        echo "failed to put IPv6 IPFW before PF with pfilctl" >&2; return 1;
    }
    [ "$(ipfw_state_position inet ipfw:default)" = "before" ] || {
        echo "IPv4 IPFW is not ahead of PF in the output pfil chain" >&2; return 1;
    }
    [ "$(ipfw_state_position inet6 ipfw:default6)" = "before" ] || {
        echo "IPv6 IPFW is not ahead of PF in the output pfil chain" >&2; return 1;
    }
    return 0
}

ipfw_state_restore_hook() {
    local head="$1" hook="$2" previous="$3"
    [ -x "$PFILCTL_BIN" ] || return 1
    "$PFILCTL_BIN" unlink -o "$hook" "$head" >/dev/null 2>&1 || true
    case "$previous" in
        before) "$PFILCTL_BIN" link -o -a "$hook" "$head" ;;
        after) "$PFILCTL_BIN" link -o "$hook" "$head" ;;
        absent) return 0 ;;
        *) echo "cannot restore unknown pfil hook order for $head" >&2; return 1 ;;
    esac
}

ipfw_state_restore() {
    local failed=0
    if [ ! -f "$IPFW_STATE_FILE" ]; then
        ipfw_state_cleanup_pass_rules || return 1
        if [ "$IPFW_MODULE_WAS_LOADED" = "0" ]; then
            # If module loading failed before creating these sysctls, there is
            # no kernel state to restore. Otherwise leave both families disabled.
            if "$SYSCTL_BIN" -n net.inet6.ip6.fw.enable >/dev/null 2>&1; then
                "$SYSCTL_BIN" net.inet6.ip6.fw.enable=0 >/dev/null 2>&1 || return 1
            fi
            if "$SYSCTL_BIN" -n net.inet.ip.fw.enable >/dev/null 2>&1; then
                "$SYSCTL_BIN" net.inet.ip.fw.enable=0 >/dev/null 2>&1 || return 1
            fi
        fi
        return 0
    fi
    ipfw_state_read || return 1
    ipfw_state_cleanup_pass_rules || failed=1
    ipfw_state_restore_hook inet ipfw:default "$IPFW_SAVED4_ORDER" || failed=1
    ipfw_state_restore_hook inet6 ipfw:default6 "$IPFW_SAVED6_ORDER" || failed=1
    if [ "$IPFW_SAVED_MODULE" = "1" ]; then
        "$SYSCTL_BIN" net.inet.ip.fw.one_pass="$IPFW_SAVED_ONE_PASS" >/dev/null 2>&1 || failed=1
        "$SYSCTL_BIN" net.inet6.ip6.fw.enable="$IPFW_SAVED6_ENABLE" >/dev/null 2>&1 || failed=1
        "$SYSCTL_BIN" net.inet.ip.fw.enable="$IPFW_SAVED_ENABLE" >/dev/null 2>&1 || failed=1
    else
        "$SYSCTL_BIN" net.inet.ip.fw.one_pass="$IPFW_SAVED_ONE_PASS" >/dev/null 2>&1 || failed=1
        "$SYSCTL_BIN" net.inet6.ip6.fw.enable=0 >/dev/null 2>&1 || failed=1
        "$SYSCTL_BIN" net.inet.ip.fw.enable=0 >/dev/null 2>&1 || failed=1
    fi
    if [ "$failed" -eq 0 ]; then
        rm -f "$IPFW_STATE_FILE"
        return 0
    fi
    echo "could not completely restore original IPFW state; state retained for retry" >&2
    return 1
}

ipfw_state_recover_stale() {
    local supervisor=""
    if [ -f "$SUPERVISOR_PIDFILE" ]; then
        supervisor=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || true)
        case "$supervisor" in
            ""|*[!0-9]*) ;;
            *) if kill -0 "$supervisor" 2>/dev/null; then return 0; fi ;;
        esac
    fi
    if [ -f "$IPFW_STATE_FILE" ]; then
        remove_ipfw_rules
        ipfw_state_restore || return 1
    else
        ipfw_state_cleanup_pass_rules || return 1
    fi
    return 0
}

# Validate an IPSet file for zapret2: one IPv4/IPv6 address or CIDR per line.
# Blank lines and lines beginning with # are ignored. This deliberately rejects
# hostname entries, arbitrary tokens, malformed prefixes, and overlarge files.
function valid_ipv4(addr, parts, n, i) {
    n = split(addr, parts, /\./)
    if (n != 4) return 0
    for (i = 1; i <= 4; i++) {
        if (parts[i] !~ /^[0-9]+$/ || length(parts[i]) > 3 || (parts[i] + 0) > 255) return 0
    }
    return 1
}

function valid_ipv6_group(group) {
    return length(group) >= 1 && length(group) <= 4 && group ~ /^[[:xdigit:]]+$/
}

function valid_ipv6(addr, left, right, pos, left_count, right_count, i, left_parts, right_parts, parts, n) {
    if (addr !~ /^[[:xdigit:]:]+$/ || index(addr, ":::") > 0) return 0
    pos = index(addr, "::")
    if (pos > 0) {
        left = substr(addr, 1, pos - 1)
        right = substr(addr, pos + 2)
        if (index(right, "::") > 0) return 0
        left_count = 0
        right_count = 0
        if (left != "") {
            left_count = split(left, left_parts, /:/)
            for (i = 1; i <= left_count; i++) if (!valid_ipv6_group(left_parts[i])) return 0
        }
        if (right != "") {
            right_count = split(right, right_parts, /:/)
            for (i = 1; i <= right_count; i++) if (!valid_ipv6_group(right_parts[i])) return 0
        }
        # Compression must stand for at least one omitted 16-bit group.
        return (left_count + right_count < 8)
    }

    n = split(addr, parts, /:/)
    if (n != 8) return 0
    for (i = 1; i <= n; i++) if (!valid_ipv6_group(parts[i])) return 0
    return 1
}

function valid_cidr(line, parts, n, addr, prefix, max_prefix) {
    n = split(line, parts, /\//)
    if (n > 2 || parts[1] == "") return 0
    addr = parts[1]
    if (n == 2 && (parts[2] !~ /^[0-9]+$/ || length(parts[2]) > 3)) return 0

    if (index(addr, ":") > 0) {
        if (!valid_ipv6(addr)) return 0
        max_prefix = 128
    } else {
        if (!valid_ipv4(addr)) return 0
        max_prefix = 32
    }
    if (n == 2 && (parts[2] + 0) > max_prefix) return 0
    return 1
}

{
    line = $0
    sub(/\r$/, "", line)
    sub(/^[[:space:]]+/, "", line)
    sub(/[[:space:]]+$/, "", line)
    if (line == "" || line ~ /^#/) next

    if (!valid_cidr(line)) {
        printf "invalid IPSet CIDR at line %d: %s\n", NR, line > "/dev/stderr"
        failed = 1
        exit 1
    }
    entries++
    if (entries > 100000) {
        print "IPSet file exceeds 100000 non-comment entries" > "/dev/stderr"
        failed = 1
        exit 1
    }
}

END {
    if (!failed && entries == 0) {
        print "IPSet file contains no CIDR entries" > "/dev/stderr"
        exit 1
    }
    if (failed) exit 1
}

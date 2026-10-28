#!/bin/sh

# setup.sh — Download and compile zapret2 for OPNsense/FreeBSD
# Run once after plugin installation or to update zapret2.

ZAPRET_DIR="/usr/local/etc/zapret2"
ZAPRET_REPO="https://github.com/bol-van/zapret2.git"

set -e

echo "=== zapret2 setup ==="

# Install build + runtime dependencies if missing.
# These come from FreeBSD's main pkg repo (not OPNsense's). Older OPNsense
# ships that repo *disabled* via an override at
# /usr/local/etc/pkg/repos/FreeBSD.conf containing { enabled: no }; newer
# OPNsense (26.7+) ships no FreeBSD repo definition at all. Either way we
# make the repo available ONLY for the duration of the dependency install,
# and we ALWAYS restore the original state on exit — success, failure, or
# interrupt — via a trap. Leaving the FreeBSD repo enabled lets a later
# `pkg upgrade` pull FreeBSD's upstream builds over OPNsense's own forks,
# which corrupts system packages and dashboard widgets (issue #2).
FREEBSD_REPO_OVERRIDE=/usr/local/etc/pkg/repos/FreeBSD.conf
FREEBSD_REPO_BACKUP="${FREEBSD_REPO_OVERRIDE}.bak"
FREEBSD_REPO_MARKER="Temporarily created by os-zapret2 setup.sh"
ENABLED_FREEBSD_REPO=0
CREATED_FREEBSD_REPO=0

restore_freebsd_repo() {
    if [ "${CREATED_FREEBSD_REPO}" = "1" ]; then
        rm -f "${FREEBSD_REPO_OVERRIDE}"
        CREATED_FREEBSD_REPO=0
        ENABLED_FREEBSD_REPO=0
        echo "Removed temporary FreeBSD pkg repo definition."
    elif [ "${ENABLED_FREEBSD_REPO}" = "1" ] && [ -f "${FREEBSD_REPO_BACKUP}" ]; then
        mv "${FREEBSD_REPO_BACKUP}" "${FREEBSD_REPO_OVERRIDE}"
        ENABLED_FREEBSD_REPO=0
        echo "Restored FreeBSD pkg repo to its original (disabled) state."
    fi
}

# Write a COMPLETE FreeBSD repo definition (the stock /etc/pkg/FreeBSD.conf
# contents), not just `FreeBSD: { enabled: yes }`. Newer OPNsense (26.7+)
# no longer ships the base definition in /etc/pkg/FreeBSD.conf, so a bare
# enable merges onto nothing — a repo with no URL — and pkg reports
# "No repositories are enabled." (issue #4). Only the base FreeBSD repo is
# defined here; FreeBSD-kmods stays off — no kernel module is needed, and
# pulling kmods risks clobbering OPNsense's own.
write_freebsd_repo_conf() {
    cat > "${FREEBSD_REPO_OVERRIDE}" <<EOF
# ${FREEBSD_REPO_MARKER}; safe to delete.
FreeBSD: {
  url: "pkg+https://pkg.FreeBSD.org/\${ABI}/latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
EOF
}

restore_then_exit() {
    _status="$1"
    trap - EXIT INT TERM HUP
    restore_freebsd_repo
    exit "${_status}"
}

# Failsafe: restore the repo no matter how the script terminates.
trap restore_freebsd_repo EXIT
trap 'restore_then_exit 130' INT
trap 'restore_then_exit 143' TERM
trap 'restore_then_exit 129' HUP

# Recover from older setup.sh runs that enabled the FreeBSD repo and aborted
# before moving the backup back into place.
if [ -f "${FREEBSD_REPO_BACKUP}" ]; then
    echo "Found previous FreeBSD pkg repo backup; restoring it before continuing."
    ENABLED_FREEBSD_REPO=1
    restore_freebsd_repo
fi

# Recover from runs that CREATED a temporary repo definition (no backup file)
# and died hard before removing it — identified by our marker comment.
if [ -f "${FREEBSD_REPO_OVERRIDE}" ] && grep -q "${FREEBSD_REPO_MARKER}" "${FREEBSD_REPO_OVERRIDE}"; then
    echo "Found leftover temporary FreeBSD repo definition from an earlier run; removing it."
    rm -f "${FREEBSD_REPO_OVERRIDE}"
fi

if [ ! -f "${FREEBSD_REPO_OVERRIDE}" ]; then
    # Newer OPNsense ships no FreeBSD repo definition at all (neither the base
    # /etc/pkg/FreeBSD.conf nor a disabled override) — create a temporary one.
    echo "Temporarily adding FreeBSD pkg repo to fetch luajit/jq/git/pkgconf..."
    mkdir -p "$(dirname "${FREEBSD_REPO_OVERRIDE}")"
    CREATED_FREEBSD_REPO=1
    ENABLED_FREEBSD_REPO=1
    write_freebsd_repo_conf
elif grep -q 'enabled: no' "${FREEBSD_REPO_OVERRIDE}"; then
    echo "Temporarily enabling FreeBSD pkg repo to fetch luajit/jq/git/pkgconf..."
    cp "${FREEBSD_REPO_OVERRIDE}" "${FREEBSD_REPO_BACKUP}"
    ENABLED_FREEBSD_REPO=1
    write_freebsd_repo_conf
fi

# Refresh package catalogues. Do NOT use `-f` (force): a forced refresh churns
# the entire catalog against every enabled repo and was implicated in breaking
# system package state (issue #2). When we just enabled the FreeBSD repo,
# refresh ONLY that repo (`-r FreeBSD`) so an OPNsense-repo hiccup can't fail
# the run; otherwise the default refresh fetches any missing or stale catalog
# and is a fast no-op.
if [ "${ENABLED_FREEBSD_REPO}" = "1" ]; then
    if ! pkg update -r FreeBSD; then
        # A "wrong OS version" here means pkg's ABI doesn't match the catalog
        # fetched from pkg.FreeBSD.org — usually a stale ABI override in
        # pkg.conf on the local system, not a plugin problem (issue #4).
        # Surface the ABI so the mismatch is visible instead of dying with
        # only the repo-restore message as the last output.
        _abi=$(pkg config abi 2>/dev/null || echo "unknown")
        echo "ERROR: could not refresh the FreeBSD pkg catalog." >&2
        echo "  pkg ABI:  ${_abi}" >&2
        echo "  kernel:   $(uname -r)" >&2
        echo "If pkg reported 'wrong OS version' above, the pkg ABI does not match" >&2
        echo "the FreeBSD release this system is running. Check /usr/local/etc/pkg.conf" >&2
        echo "for an ABI override, fix or remove it, then re-run this script." >&2
        exit 1
    fi
else
    pkg update -q
fi

# Install a dependency, accepting any of several candidate package names. This
# tolerates naming differences across OPNsense/FreeBSD versions: some releases
# ship `git-lite`, others only the full `git` (issue #1). Succeeds if any
# candidate is already installed or can be installed; fails only if none can.
install_dep() {
    for _name in "$@"; do
        if pkg info -q "${_name}"; then
            return 0
        fi
    done
    for _name in "$@"; do
        if pkg install -y "${_name}"; then
            return 0
        fi
    done
    echo "ERROR: could not install dependency (tried: $*)" >&2
    return 1
}

install_dep pkgconf
install_dep luajit
# Accept either the slim `git-lite` or the full `git`, whichever the running
# OPNsense/FreeBSD version offers — and skip entirely if git is already present.
install_dep git-lite git
# jq is required at runtime by zapret_service.sh to parse pluginctl JSON
# when resolving the WAN interface name.
install_dep jq

# Re-disable the FreeBSD repo now that deps are installed, so it stays off for
# the rest of the script (git clone below) and for all future pkg operations.
# The EXIT trap above is the backstop; this is the normal path.
restore_freebsd_repo

# Pin the engine to the release against which the profile arguments were checked.
# Never silently follow upstream master: CLI options and strategy semantics may change.
ZAPRET2_TAG="v1.0.6"
ZAPRET2_COMMIT="221d7dff24bfec0cd5ac0a5070b8acef2008af3d"

if [ -d "$ZAPRET_DIR/.git" ]; then
    echo "Updating existing zapret2 installation to $ZAPRET2_TAG..."
    # Plugin settings and hostlists are intentionally untracked in this
    # directory. Refuse only modified engine files; keep user-owned files.
    if ! git -C "$ZAPRET_DIR" diff --quiet --ignore-submodules -- ||
        ! git -C "$ZAPRET_DIR" diff --cached --quiet --ignore-submodules --; then
        echo "ERROR: tracked zapret2 engine files have local changes in $ZAPRET_DIR; back them up or revert them before updating." >&2
        git -C "$ZAPRET_DIR" status --short >&2
        exit 1
    fi
    cd "$ZAPRET_DIR"
    git fetch --depth 1 origin "refs/tags/$ZAPRET2_TAG"
    git checkout --detach FETCH_HEAD
else
    echo "Installing zapret2 $ZAPRET2_TAG without overwriting existing settings..."
    _clone_tmp="${ZAPRET_DIR}.engine-install.$$"
    if [ -e "$_clone_tmp" ]; then
        echo "ERROR: temporary engine directory already exists: $_clone_tmp" >&2
        exit 1
    fi
    git clone --depth 1 --branch "$ZAPRET2_TAG" --single-branch "$ZAPRET_REPO" "$_clone_tmp"
    mkdir -p "$ZAPRET_DIR"
    # cp -n adds missing engine files but never replaces settings or lists.
    cp -Rn "$_clone_tmp"/. "$ZAPRET_DIR"/
    rm -rf "$_clone_tmp"
fi

# In both installation paths, refuse to compile if pre-existing files differ
# from the pinned engine. Untracked user configuration/list files are preserved.
if ! git -C "$ZAPRET_DIR" diff --quiet --ignore-submodules -- ||
    ! git -C "$ZAPRET_DIR" diff --cached --quiet --ignore-submodules --; then
    echo "ERROR: existing files conflict with tracked zapret2 engine files. No existing files were overwritten; resolve the conflict and retry." >&2
    git -C "$ZAPRET_DIR" status --short >&2
    exit 1
fi

resolved_commit=$(git -C "$ZAPRET_DIR" rev-parse HEAD)
if [ "$resolved_commit" != "$ZAPRET2_COMMIT" ]; then
    echo "ERROR: zapret2 $ZAPRET2_TAG resolved to unexpected commit $resolved_commit; expected $ZAPRET2_COMMIT." >&2
    exit 1
fi
echo "Using verified zapret2 $ZAPRET2_TAG ($resolved_commit)."

# Compile
echo "Compiling zapret2..."
cd "${ZAPRET_DIR}"
make clean 2>/dev/null || true
make

# Verify binaries
if [ -x "${ZAPRET_DIR}/binaries/my/dvtws2" ]; then
    echo "dvtws2 compiled successfully: ${ZAPRET_DIR}/binaries/my/dvtws2"
else
    echo "ERROR: dvtws2 compilation failed!" >&2
    exit 1
fi

if [ -x "${ZAPRET_DIR}/binaries/my/tpws2" ]; then
    echo "tpws2 compiled successfully: ${ZAPRET_DIR}/binaries/my/tpws2"
fi

# Ensure config directory exists
mkdir -p "${ZAPRET_DIR}"

echo "=== zapret2 setup complete ==="

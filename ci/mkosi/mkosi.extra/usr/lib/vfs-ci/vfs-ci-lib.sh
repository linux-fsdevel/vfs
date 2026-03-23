#!/bin/bash
# Shared preamble for vfs-ci test runner scripts.

# Detect distro — gives us $ID ("fedora", "debian", …), $VERSION_ID, etc.
. /etc/os-release

echo "vfsci: running on ${ID} ${VERSION_ID:-unstable} ($(uname -r))"

busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetShowStatus s no || true

# Known-flaky or expected-failing tests per suite.
XFS_EXCLUDE=""
OVL_EXCLUDE=""
SELFTESTS_DENYLIST=(filesystems:file_stressor filelock:ofdlocks)

case "$ID" in
    debian)
	    # Quota tools on Debian are too old. We need >=4.11
	    XFS_EXCLUDE+="-x quota"
	    OVL_EXCLUDE+="-x quota"
	    # Quota-related tests not in the quota group; fail with quota-tools <4.11
	    XFS_EXCLUDE+=" -e generic/305 -e generic/326 -e generic/327 -e generic/328 -e xfs/213 -e xfs/214"
        ;;
    fedora)
        ;;
esac

# xfs/008: unreliable - "holes has value of 44 holes is NOT in range 45 .. 55"
XFS_EXCLUDE+=" -e xfs/008 \
 -e xfs/017 \
 -e xfs/018 \
 -e xfs/176 \
 -e xfs/556 \
 -e xfs/620"
OVL_EXCLUDE+=" -e generic/091 \
 -e generic/103 \
 -e generic/263 \
 -e generic/760 \
 ${XFS_EXCLUDE}"

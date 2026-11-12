#!/bin/bash
set -euo pipefail

. /usr/lib/vfs-ci/vfs-ci-lib.sh

# VFS/filesystem selftest targets to run
TARGETS=(
	mount
	mount_setattr
	# filesystems
	filelock
	tmpfs
	pidfd
	pid_namespace
	cachestat
)

cd /usr/lib/kernel/selftests

ARGS=()

if [[ $# -gt 0 ]]; then
	for t in "$@"; do
		ARGS+=(-c "$t")
	done
else
	for t in "${TARGETS[@]}"; do
		ARGS+=(-c "$t")
	done
fi

for t in "${SELFTESTS_DENYLIST[@]}"; do
	ARGS+=(-S "$t")
done

exec > >(tee /usr/lib/kernel/selftests/output.log) 2>&1
exec ./run_kselftest.sh "${ARGS[@]}"

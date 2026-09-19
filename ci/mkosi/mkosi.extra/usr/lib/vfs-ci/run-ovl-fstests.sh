#!/bin/bash
set -euo pipefail

. /usr/lib/vfs-ci/vfs-ci-lib.sh

cd /var/lib/xfstests/
FSDEVEL1=$(readlink -f /dev/disk/by-label/fsdevel1)
FSDEVEL2=$(readlink -f /dev/disk/by-label/fsdevel2)

bash -c "cat <<EOF >local.config
FSTYP=xfs
export TEST_DEV=${FSDEVEL1}
export SCRATCH_DEV=${FSDEVEL2}
export TEST_DIR=/mnt/test
export SCRATCH_MNT=/mnt/scratch
EOF"

mkfs.xfs -f ${FSDEVEL1}
mkfs.xfs -f ${FSDEVEL2}
./check -overlay -g quick -g 'overlay/union' ${OVL_EXCLUDE}

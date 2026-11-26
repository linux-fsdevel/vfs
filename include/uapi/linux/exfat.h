/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2024 Unisoc Technologies Co., Ltd.
 */

#ifndef _UAPI_LINUX_EXFAT_H
#define _UAPI_LINUX_EXFAT_H
#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * exfat-specific ioctl commands
 */

#define EXFAT_IOC_SHUTDOWN _IOR('X', 125, __u32)
#define EXFAT_IOC_COMBINE  _IOW('r', 0x20, struct exfat_combine_args)

/*
 * Flags used by EXFAT_IOC_SHUTDOWN
 */

#define EXFAT_GOING_DOWN_DEFAULT	0x0	/* default with full sync */
#define EXFAT_GOING_DOWN_FULLSYNC	0x1     /* going down with full sync*/
#define EXFAT_GOING_DOWN_NOSYNC         0x2     /* going down */

/*
 * Argument for EXFAT_IOC_COMBINE.
 *
 * The ioctl is issued on the destination file.  The clusters of @src_fd
 * are appended to the destination without copying any data, and the
 * source is left as an empty file, so that only metadata is changed.
 * The caller unlinks the source afterwards if it is not needed; if the
 * name of the source has to keep referring to the same file until then,
 * the caller has to prevent concurrent renames.
 *
 * Clusters can only be appended at a cluster boundary.  If the size of
 * the destination is not a multiple of the cluster size, it is first
 * extended with zeroes up to the end of its last cluster, so the combined
 * file has a zero-filled gap between the original and the appended data,
 * and the appended data starts at offset round_up(old size, cluster size).
 * User space has to account for that gap, e.g. by making the file format
 * skip it.  To fill it with something else, user space can pad the
 * destination itself before the call, in which case nothing is zeroed.
 * The cluster size is reported in st_blksize by stat(2).  Any range of
 * the destination that was never written, e.g. after fallocate(2), is
 * zeroed as well, which can take a while if it is large.
 *
 * An unlinked destination is refused (ENOENT); an unlinked source is
 * accepted.  An empty source leaves the destination unchanged.
 *
 * Errors are reported even when the device fails only after the
 * destination was updated.  The clusters may then already belong to the
 * destination, with the source empty or still to be written as empty;
 * callers can tell from the size of the destination.  Otherwise a failed
 * call leaves both files unchanged.
 *
 * A crash during the call may leave both files referencing the appended
 * clusters.  fsck.exfat resolves this without losing data, but the source
 * must not be truncated or removed before fsck has run.  On a volume that
 * was not cleanly unmounted, the call fails with EUCLEAN until fsck.exfat
 * has run.  After a crash, an empty source next to a destination that
 * already contains its data means that the call completed and only the
 * unlink is left.
 */
struct exfat_combine_args {
	__s32 src_fd;	/* file whose clusters are moved */
	__u32 flags;	/* must be zero */
};

#endif /* _UAPI_LINUX_EXFAT_H */

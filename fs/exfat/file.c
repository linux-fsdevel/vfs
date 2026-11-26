// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/msdos_fs.h>
#include <linux/writeback.h>
#include <linux/filelock.h>
#include <linux/falloc.h>
#include <linux/file.h>
#include <linux/fileattr.h>
#include <linux/iomap.h>
#include <linux/pagemap.h>

#include "exfat_raw.h"
#include "exfat_fs.h"
#include "iomap.h"

static int exfat_cont_expand(struct inode *inode, loff_t size)
{
	int ret;
	unsigned int num_clusters, new_num_clusters, last_clu;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_chain clu;
	loff_t oldsize = i_size_read(inode);

	truncate_pagecache(inode, oldsize);

	ret = inode_newsize_ok(inode, size);
	if (ret)
		return ret;

	num_clusters = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode));
	/* integer overflow is already checked in inode_newsize_ok(). */
	new_num_clusters = exfat_bytes_to_cluster_round_up(sbi, size);

	if (new_num_clusters == num_clusters)
		goto out;

	if (num_clusters) {
		exfat_chain_set(&clu, ei->start_clu, num_clusters, ei->flags);
		ret = exfat_find_last_cluster(sb, &clu, &last_clu);
		if (ret)
			return ret;

		clu.dir = last_clu + 1;
	} else {
		last_clu = EXFAT_EOF_CLUSTER;
		clu.dir = EXFAT_EOF_CLUSTER;
	}

	clu.size = 0;
	clu.flags = ei->flags;

	ret = exfat_alloc_cluster(inode, new_num_clusters - num_clusters,
			&clu, inode_needs_sync(inode), false);
	if (ret)
		return ret;

	/* Append new clusters to chain */
	if (num_clusters) {
		if (clu.flags != ei->flags)
			if (exfat_chain_cont_cluster(sb, ei->start_clu, num_clusters))
				goto free_clu;

		if (clu.flags == ALLOC_FAT_CHAIN)
			if (exfat_ent_set(sb, last_clu, clu.dir))
				goto free_clu;
	} else
		ei->start_clu = clu.dir;

	ei->flags = clu.flags;

out:
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	/* Expanded range not zeroed, do not update valid_size */
	i_size_write(inode, size);
	/*
	 * When extending file size, call truncate_pagecache() first,
	 * then update i_size, and call pagecache_isize_extended()
	 * to ensures the straddling folio is properly marked RO so
	 * page_mkwrite() is called and post-EOF area is zeroed.
	 */
	pagecache_isize_extended(inode, oldsize, inode->i_size);

	inode->i_blocks = round_up(size, sbi->cluster_size) >> 9;
	mark_inode_dirty(inode);

	if (IS_SYNC(inode))
		return write_inode_now(inode, 1);

	return 0;

free_clu:
	exfat_free_cluster(inode, &clu);
	return -EIO;
}

/*
 * Preallocate space for a file. This implements exfat's fallocate file
 * operation, which gets called from sys_fallocate system call. User space
 * requests len bytes at offset. In contrary to fat, we only support
 * FALLOC_FL_ALLOCATE_RANGE because by leaving the valid data length(VDL)
 * field, it is unnecessary to zero out the newly allocated clusters.
 */
static long exfat_fallocate(struct file *file, int mode,
			  loff_t offset, loff_t len)
{
	struct inode *inode = file->f_mapping->host;
	loff_t newsize = offset + len;
	int err = 0;

	/* No support for other modes */
	if (mode != FALLOC_FL_ALLOCATE_RANGE)
		return -EOPNOTSUPP;

	/* No support for dir */
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	inode_lock(inode);

	if (newsize <= i_size_read(inode))
		goto error;

	/* This is just an expanding truncate */
	err = exfat_cont_expand(inode, newsize);

error:
	inode_unlock(inode);

	return err;
}

static bool exfat_allow_set_time(struct mnt_idmap *idmap,
				 struct exfat_sb_info *sbi, struct inode *inode)
{
	mode_t allow_utime = sbi->options.allow_utime;

	if (!vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, inode),
			    current_fsuid())) {
		if (vfsgid_in_group_p(i_gid_into_vfsgid(idmap, inode)))
			allow_utime >>= 3;
		if (allow_utime & MAY_WRITE)
			return true;
	}

	/* use a default check */
	return false;
}

static int exfat_sanitize_mode(const struct exfat_sb_info *sbi,
		struct inode *inode, umode_t *mode_ptr)
{
	mode_t i_mode, mask, perm;

	i_mode = inode->i_mode;

	mask = (S_ISREG(i_mode) || S_ISLNK(i_mode)) ?
		sbi->options.fs_fmask : sbi->options.fs_dmask;
	perm = *mode_ptr & ~(S_IFMT | mask);

	/* Of the r and x bits, all (subject to umask) must be present.*/
	if ((perm & 0555) != (i_mode & 0555))
		return -EPERM;

	if (exfat_mode_can_hold_ro(inode)) {
		/*
		 * Of the w bits, either all (subject to umask) or none must
		 * be present.
		 */
		if ((perm & 0222) && ((perm & 0222) != (0222 & ~mask)))
			return -EPERM;
	} else {
		/*
		 * If exfat_mode_can_hold_ro(inode) is false, can't change
		 * w bits.
		 */
		if ((perm & 0222) != (0222 & ~mask))
			return -EPERM;
	}

	*mode_ptr &= S_IFMT | perm;

	return 0;
}

/* resize the file length */
int __exfat_truncate(struct inode *inode)
{
	unsigned int num_clusters_new, num_clusters_phys;
	unsigned int last_clu = EXFAT_FREE_CLUSTER;
	struct exfat_chain clu;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);

	/* check if the given file ID is opened */
	if (ei->type != TYPE_FILE && ei->type != TYPE_DIR)
		return -EPERM;

	exfat_set_volume_dirty(sb);

	num_clusters_new = exfat_bytes_to_cluster_round_up(sbi, i_size_read(inode));
	num_clusters_phys = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(inode));

	exfat_chain_set(&clu, ei->start_clu, num_clusters_phys, ei->flags);

	if (i_size_read(inode) > 0) {
		/*
		 * Truncate FAT chain num_clusters after the first cluster
		 * num_clusters = min(new, phys);
		 */
		unsigned int num_clusters =
			min(num_clusters_new, num_clusters_phys);

		/*
		 * Follow FAT chain
		 * (defensive coding - works fine even with corrupted FAT table
		 */
		if (clu.flags == ALLOC_NO_FAT_CHAIN) {
			clu.dir += num_clusters;
			clu.size -= num_clusters;
		} else {
			while (num_clusters > 0) {
				last_clu = clu.dir;
				if (exfat_get_next_cluster(sb, &(clu.dir)))
					return -EIO;

				num_clusters--;
				clu.size--;
			}
		}
	} else {
		ei->flags = ALLOC_NO_FAT_CHAIN;
		ei->start_clu = EXFAT_EOF_CLUSTER;
	}

	if (i_size_read(inode) < ei->valid_size)
		ei->valid_size = ei->zeroed_size = i_size_read(inode);

	if (ei->type == TYPE_FILE)
		ei->attr |= EXFAT_ATTR_ARCHIVE;

	/*
	 * update the directory entry
	 *
	 * If the directory entry is updated by mark_inode_dirty(), the
	 * directory entry will be written after a writeback cycle of
	 * updating the bitmap/FAT, which may result in clusters being
	 * freed but referenced by the directory entry in the event of a
	 * sudden power failure.
	 * __exfat_write_inode() is called for directory entry, bitmap
	 * and FAT to be written in a same writeback.
	 */
	if (__exfat_write_inode(inode, inode_needs_sync(inode)))
		return -EIO;

	/* cut off from the FAT chain */
	if (ei->flags == ALLOC_FAT_CHAIN && last_clu != EXFAT_FREE_CLUSTER &&
			last_clu != EXFAT_EOF_CLUSTER) {
		if (exfat_ent_set(sb, last_clu, EXFAT_EOF_CLUSTER))
			return -EIO;
	}

	/* invalidate cache and free the clusters */
	/* clear exfat cache */
	exfat_cache_inval_inode(inode);

	/* hint information */
	ei->hint_bmap.off = EXFAT_EOF_CLUSTER;
	ei->hint_bmap.clu = EXFAT_EOF_CLUSTER;

	/* hint_stat will be used if this is directory. */
	ei->hint_stat.eidx = 0;
	ei->hint_stat.clu = ei->start_clu;
	ei->hint_femp.eidx = EXFAT_HINT_NONE;

	/* free the clusters */
	if (exfat_free_cluster(inode, &clu))
		return -EIO;

	return 0;
}

static void exfat_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	int err;

	mutex_lock(&sbi->s_lock);
	if (ei->start_clu == 0) {
		/*
		 * Empty start_clu != ~0 (not allocated)
		 */
		exfat_fs_error(sb, "tried to truncate zeroed cluster.");
		goto write_size;
	}

	err = __exfat_truncate(inode);
	if (err)
		goto write_size;

	inode->i_blocks = round_up(i_size_read(inode), sbi->cluster_size) >> 9;
write_size:
	mutex_unlock(&sbi->s_lock);
}

int exfat_getattr(struct mnt_idmap *idmap, const struct path *path,
		  struct kstat *stat, unsigned int request_mask,
		  unsigned int query_flags)
{
	struct inode *inode = d_backing_inode(path->dentry);
	struct exfat_inode_info *ei = EXFAT_I(inode);

	generic_fillattr(idmap, request_mask, inode, stat);
	exfat_truncate_atime(&stat->atime);
	stat->result_mask |= STATX_BTIME;
	stat->btime.tv_sec = ei->i_crtime.tv_sec;
	stat->btime.tv_nsec = ei->i_crtime.tv_nsec;
	stat->blksize = EXFAT_SB(inode->i_sb)->cluster_size;
	return 0;
}

int exfat_fileattr_get(struct dentry *dentry, struct file_kattr *fa)
{
	/*
	 * exFAT compares filenames through an upcase table, so lookup
	 * is always case-insensitive. Long names are stored in UTF-16
	 * with case intact; CASENONPRESERVING stays clear.
	 */
	fa->fsx_xflags |= FS_XFLAG_CASEFOLD;
	fa->flags |= FS_CASEFOLD_FL;
	return 0;
}

int exfat_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
		  struct iattr *attr)
{
	struct exfat_sb_info *sbi = EXFAT_SB(dentry->d_sb);
	struct inode *inode = dentry->d_inode;
	unsigned int ia_valid;
	int error;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size > i_size_read(inode)) {
		error = exfat_cont_expand(inode, attr->ia_size);
		if (error || attr->ia_valid == ATTR_SIZE)
			return error;
		attr->ia_valid &= ~ATTR_SIZE;
	}

	/* Check for setting the inode time. */
	ia_valid = attr->ia_valid;
	if ((ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)) &&
	    exfat_allow_set_time(idmap, sbi, inode)) {
		attr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET |
				ATTR_TIMES_SET);
	}

	error = setattr_prepare(idmap, dentry, attr);
	attr->ia_valid = ia_valid;
	if (error)
		goto out;

	if (((attr->ia_valid & ATTR_UID) &&
	      (!uid_eq(from_vfsuid(idmap, i_user_ns(inode), attr->ia_vfsuid),
	       sbi->options.fs_uid))) ||
	    ((attr->ia_valid & ATTR_GID) &&
	      (!gid_eq(from_vfsgid(idmap, i_user_ns(inode), attr->ia_vfsgid),
	       sbi->options.fs_gid))) ||
	    ((attr->ia_valid & ATTR_MODE) &&
	     (attr->ia_mode & ~(S_IFREG | S_IFLNK | S_IFDIR | 0777)))) {
		error = -EPERM;
		goto out;
	}

	/*
	 * We don't return -EPERM here. Yes, strange, but this is too
	 * old behavior.
	 */
	if (attr->ia_valid & ATTR_MODE) {
		if (exfat_sanitize_mode(sbi, inode, &attr->ia_mode) < 0)
			attr->ia_valid &= ~ATTR_MODE;
	}

	if (attr->ia_valid & ATTR_SIZE)
		inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));

	setattr_copy(idmap, inode, attr);
	exfat_truncate_inode_atime(inode);

	if (attr->ia_valid & ATTR_SIZE) {
		/*
		 * Wait for any in-flight DIO to finish before truncating to
		 * prevent a concurrent DIO from writing to clusters that are
		 * about to be freed.
		 */
		inode_dio_wait(inode);
		truncate_setsize(inode, attr->ia_size);

		/*
		 * __exfat_write_inode() is called from exfat_truncate(), inode
		 * is already written by it, so mark_inode_dirty() is unneeded.
		 */
		exfat_truncate(inode);
	} else
		mark_inode_dirty(inode);

out:
	return error;
}

/*
 * modified ioctls from fat/file.c by Welmer Almesberger
 */
static int exfat_ioctl_get_attributes(struct inode *inode, u32 __user *user_attr)
{
	u32 attr;

	inode_lock_shared(inode);
	attr = exfat_make_attr(inode);
	inode_unlock_shared(inode);

	return put_user(attr, user_attr);
}

static int exfat_ioctl_set_attributes(struct file *file, u32 __user *user_attr)
{
	struct inode *inode = file_inode(file);
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	int is_dir = S_ISDIR(inode->i_mode);
	u32 attr, oldattr;
	struct iattr ia;
	int err;

	err = get_user(attr, user_attr);
	if (err)
		goto out;

	err = mnt_want_write_file(file);
	if (err)
		goto out;
	inode_lock(inode);

	oldattr = exfat_make_attr(inode);

	/*
	 * Mask attributes so we don't set reserved fields.
	 */
	attr &= (EXFAT_ATTR_READONLY | EXFAT_ATTR_HIDDEN | EXFAT_ATTR_SYSTEM |
		 EXFAT_ATTR_ARCHIVE);
	attr |= (is_dir ? EXFAT_ATTR_SUBDIR : 0);

	/* Equivalent to a chmod() */
	ia.ia_valid = ATTR_MODE | ATTR_CTIME;
	ia.ia_ctime = current_time(inode);
	if (is_dir)
		ia.ia_mode = exfat_make_mode(sbi, attr, 0777);
	else
		ia.ia_mode = exfat_make_mode(sbi, attr, 0666 | (inode->i_mode & 0111));

	/* The root directory has no attributes */
	if (inode->i_ino == EXFAT_ROOT_INO && attr != EXFAT_ATTR_SUBDIR) {
		err = -EINVAL;
		goto out_unlock_inode;
	}

	if (((attr | oldattr) & EXFAT_ATTR_SYSTEM) &&
	    !capable(CAP_LINUX_IMMUTABLE)) {
		err = -EPERM;
		goto out_unlock_inode;
	}

	/*
	 * The security check is questionable...  We single
	 * out the RO attribute for checking by the security
	 * module, just because it maps to a file mode.
	 */
	err = security_inode_setattr(file_mnt_idmap(file),
				     file->f_path.dentry, &ia);
	if (err)
		goto out_unlock_inode;

	/* This MUST be done before doing anything irreversible... */
	err = exfat_setattr(file_mnt_idmap(file), file->f_path.dentry, &ia);
	if (err)
		goto out_unlock_inode;

	fsnotify_change(file->f_path.dentry, ia.ia_valid);

	exfat_save_attr(inode, attr);
	mark_inode_dirty(inode);
out_unlock_inode:
	inode_unlock(inode);
	mnt_drop_write_file(file);
out:
	return err;
}

static int exfat_ioctl_fitrim(struct inode *inode, unsigned long arg)
{
	struct fstrim_range range;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!bdev_max_discard_sectors(inode->i_sb->s_bdev))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range __user *)arg, sizeof(range)))
		return -EFAULT;

	range.minlen = max_t(unsigned int, range.minlen,
				bdev_discard_granularity(inode->i_sb->s_bdev));

	ret = exfat_trim_fs(inode, &range);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct fstrim_range __user *)arg, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

static int exfat_ioctl_shutdown(struct super_block *sb, unsigned long arg)
{
	u32 flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, (__u32 __user *)arg))
		return -EFAULT;

	return exfat_force_shutdown(sb, flags);
}

static int exfat_ioctl_get_volume_label(struct super_block *sb, unsigned long arg)
{
	int ret;
	char label[FSLABEL_MAX] = {0};
	struct exfat_uni_name uniname;

	ret = exfat_read_volume_label(sb, &uniname);
	if (ret < 0)
		return ret;

	ret = exfat_utf16_to_nls(sb, &uniname, label, sizeof(label));
	if (ret < 0)
		return ret;

	if (copy_to_user((char __user *)arg, label, ret + 1))
		return -EFAULT;

	return 0;
}

static int exfat_ioctl_set_volume_label(struct super_block *sb,
					unsigned long arg)
{
	int ret = 0, lossy, label_len;
	char label[FSLABEL_MAX] = {0};
	struct exfat_uni_name uniname;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(label, (char __user *)arg, FSLABEL_MAX))
		return -EFAULT;

	memset(&uniname, 0, sizeof(uniname));
	label_len = strnlen(label, FSLABEL_MAX - 1);
	if (label[0]) {
		ret = exfat_nls_to_utf16(sb, label, label_len,
					 &uniname, &lossy);
		if (ret < 0)
			return ret;
		else if (lossy & NLS_NAME_LOSSY)
			return -EINVAL;
	}

	uniname.name_len = ret;

	return exfat_write_volume_label(sb, &uniname);
}

static int exfat_extend_valid_size(struct inode *inode, loff_t new_valid_size);

/*
 * Write back all dirty metadata buffers and flush the device cache.  The
 * error flags of the block device mapping go to whoever checks them
 * first, an fsync() of any file on the volume included, so also check
 * its errseq sampled in @since.  Advance @since, also when the writeback
 * returned the error itself, so that the error is marked seen and fails
 * one call only.
 */
static int exfat_combine_flush(struct super_block *sb, errseq_t *since)
{
	int err = sync_blockdev(sb->s_bdev);
	int ret = errseq_check_and_advance(&sb->s_bdev->bd_mapping->wb_err,
					   since);

	if (!err)
		err = ret;
	return err ? err : blkdev_issue_flush(sb->s_bdev);
}

static void exfat_combine_reset_hints(struct inode *inode)
{
	struct exfat_inode_info *ei = EXFAT_I(inode);

	exfat_cache_inval_inode(inode);
	ei->hint_bmap.off = EXFAT_EOF_CLUSTER;
	ei->hint_bmap.clu = EXFAT_EOF_CLUSTER;
}

/*
 * Find the last cluster of @dst, walking only the clusters it owns.  A
 * crash during an earlier call can have left the last one linked to @src,
 * which is rewritten anyway, or, once the entry of @dst was written too,
 * @src among them until fsck.exfat has run.  Refuse the latter, and any
 * other overlap with the clusters of @src known without walking its
 * chain (all of them if it is contiguous), as linking @src would create
 * a loop in the FAT.
 */
static int exfat_combine_find_last(struct super_block *sb,
				   struct exfat_chain *chain,
				   struct exfat_chain *src, unsigned int *last)
{
	struct buffer_head *bh = NULL;
	unsigned int clu = chain->dir, next, n;
	unsigned int src_end = src->dir +
		(src->flags == ALLOC_NO_FAT_CHAIN ? src->size : 1);
	int err = 0;

	if (chain->flags == ALLOC_NO_FAT_CHAIN) {
		if (clu < src_end && src->dir < clu + chain->size)
			return -EIO;
		*last = clu + chain->size - 1;
		return 0;
	}

	for (n = 1; ; n++) {
		if (clu >= src->dir && clu < src_end) {
			err = -EIO;
			break;
		}
		err = exfat_ent_get(sb, clu, &next, &bh);
		if (err)
			break;
		if (n == chain->size) {
			if (next != EXFAT_EOF_CLUSTER && next != src->dir)
				goto bogus;
			*last = clu;
			break;
		}
		if (next == EXFAT_EOF_CLUSTER)
			goto bogus;
		clu = next;
	}
	brelse(bh);
	return err;

bogus:
	brelse(bh);
	exfat_fs_error(sb, "bogus cluster chain (start 0x%08x, %u clusters)",
		       chain->dir, chain->size);
	return -EIO;
}

/*
 * Move the cluster chain of @src to the end of @dst, leaving @src empty.
 *
 * Only the FAT and the two stream extension entries are updated, no file
 * data is copied.  The caller must have found the last cluster @last_clu
 * of @dst with exfat_combine_check_chains() and zero-filled @dst up to
 * its end, so that no stale data ends up in the middle of the file, and
 * must hold the inode and invalidate locks of both files.
 *
 * exFAT has no journal, so the updates are ordered on disk such that a
 * crash at any point leaves all data reachable:
 *
 * 1. the data of both files and the FAT, so that the new chain of @dst
 *    is complete before any entry refers to it; until step 2, the chain
 *    of @dst runs into the clusters of @src beyond its size, which
 *    fsck.exfat cuts off again;
 * 2. the entry of @dst, after which both entries reference the clusters
 *    of @src; fsck.exfat keeps them in whichever file it checks first and
 *    truncates the other one;
 * 3. the entry of @src as an empty file.
 *
 * This follows the write ordering recommended by section 8.1 of the
 * exFAT specification: the FAT before the entry that refers to it.  No
 * cluster is allocated or freed, so the allocation bitmap is not
 * touched.
 *
 * s_lock is only held while updating the FAT and the entries, not while
 * waiting for the device, so that other files on the volume are not
 * stalled.  Until step 2, the in-memory state of @dst is left alone, so
 * that writeback cannot publish its new chain flags early, and the
 * in-memory state of @src is only changed once @dst is on disk.
 */
static int __exfat_combine(struct inode *dst, struct inode *src,
			   unsigned int last_clu, errseq_t *meta_since)
{
	struct super_block *sb = dst->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *dst_ei = EXFAT_I(dst);
	struct exfat_inode_info *src_ei = EXFAT_I(src);
	loff_t dst_size = i_size_read(dst);
	loff_t src_size = i_size_read(src);
	loff_t new_valid_size;
	unsigned int dst_clus, src_clus, dst_start, dst_start_old;
	unsigned char dst_flags, dst_flags_old;
	bool linked = false;
	int err = 0, ret;

	dst_clus = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(dst));
	src_clus = exfat_bytes_to_cluster(sbi, exfat_ondisk_size(src));

	/* Ensured by exfat_ioctl_combine() and stable under its locks. */
	if (exfat_cluster_to_bytes(sbi, dst_clus) != dst_size ||
	    (!dst_clus && dst_ei->start_clu != EXFAT_EOF_CLUSTER) ||
	    (dst_clus && dst_ei->start_clu == EXFAT_EOF_CLUSTER) ||
	    exfat_get_valid_size(dst_ei) != dst_size ||
	    src_ei->start_clu == EXFAT_EOF_CLUSTER ||
	    exfat_bytes_to_cluster_round_up(sbi, src_size) != src_clus)
		return -EIO;

	/* Step 1: build the new chain of @dst in the FAT. */
	mutex_lock(&sbi->s_lock);
	err = exfat_emergency_state(sb);
	if (err)
		goto unlock;
	exfat_set_volume_dirty(sb);
	dst_start_old = dst_ei->start_clu;
	dst_flags_old = dst_ei->flags;
	dst_start = dst_start_old;
	dst_flags = dst_flags_old;

	if (!dst_clus) {
		dst_start = src_ei->start_clu;
		dst_flags = src_ei->flags;
		goto unlock;
	}

	/*
	 * A contiguous @dst can stay contiguous only if @src is contiguous
	 * and starts right after it.  Otherwise build its FAT chain first.
	 */
	if (dst_flags == ALLOC_NO_FAT_CHAIN &&
	    (src_ei->flags != ALLOC_NO_FAT_CHAIN ||
	     src_ei->start_clu != last_clu + 1)) {
		err = exfat_chain_cont_cluster(sb, dst_start, dst_clus);
		if (err)
			goto unlock;
		dst_flags = ALLOC_FAT_CHAIN;
	}

	if (dst_flags == ALLOC_FAT_CHAIN) {
		if (src_ei->flags == ALLOC_NO_FAT_CHAIN) {
			err = exfat_chain_cont_cluster(sb, src_ei->start_clu,
						       src_clus);
			if (err)
				goto unlock;
		}
		err = exfat_ent_set(sb, last_clu, src_ei->start_clu);
		linked = !err;
	}
unlock:
	mutex_unlock(&sbi->s_lock);
	if (err)
		return err;

	err = exfat_combine_flush(sb, meta_since);
	if (err)
		goto undo;

	/*
	 * Step 2: publish the new size and chain of @dst.  As the rest of
	 * exfat, write nothing more once the volume is in an emergency
	 * state, which leaves what a crash after step 1 leaves.  If it
	 * enters that state after the entry of @dst is written, @src keeps
	 * its entry, as after a crash after step 2.
	 */
	mutex_lock(&sbi->s_lock);
	err = exfat_emergency_state(sb);
	if (err) {
		mutex_unlock(&sbi->s_lock);
		goto undo;
	}
	dst_ei->start_clu = dst_start;
	dst_ei->flags = dst_flags;
	new_valid_size = dst_size + exfat_get_valid_size(src_ei);
	dst->i_blocks = exfat_cluster_to_sectors(sbi, dst_clus + src_clus);
	i_size_write(dst, dst_size + src_size);
	exfat_set_valid_size(dst_ei, new_valid_size);
	exfat_set_zeroed_size(dst_ei, new_valid_size);
	dst_ei->attr |= EXFAT_ATTR_ARCHIVE;
	inode_set_mtime_to_ts(dst, inode_set_ctime_current(dst));
	exfat_combine_reset_hints(dst);
	err = __exfat_write_inode(dst, 1);
	if (err) {
		/*
		 * The error is returned, mark it seen in the errseq of the
		 * block device mapping, which no flush checks now, so that it
		 * does not fail later calls.  Its error flags are left alone:
		 * they are shared by every file on the volume.
		 */
		errseq_check_and_advance(&sb->s_bdev->bd_mapping->wb_err,
					 meta_since);
		/*
		 * Keep @src the only owner of its clusters: give @dst back its
		 * old state, which writeback retries to put on disk.
		 */
		dst_ei->start_clu = dst_start_old;
		dst_ei->flags = dst_flags_old;
		dst->i_blocks = exfat_cluster_to_sectors(sbi, dst_clus);
		i_size_write(dst, dst_size);
		exfat_set_valid_size(dst_ei, dst_size);
		exfat_set_zeroed_size(dst_ei, dst_size);
		exfat_combine_reset_hints(dst);
		mark_inode_dirty(dst);
	}
	mutex_unlock(&sbi->s_lock);
	if (err)
		goto undo;

	err = blkdev_issue_flush(sb->s_bdev);

	/*
	 * Step 3: the clusters now belong to @dst.  Write @src as an empty
	 * file.  If the flush failed, the entry of @dst was still written,
	 * so do it anyway.  If writing @src fails, its in-memory state no
	 * longer owns the clusters, so evicting it frees nothing, and
	 * writeback retries the entry; until then both entries reference
	 * the clusters, as after a crash.
	 */
	mutex_lock(&sbi->s_lock);
	src_ei->start_clu = EXFAT_EOF_CLUSTER;
	src_ei->flags = ALLOC_NO_FAT_CHAIN;
	src->i_blocks = 0;
	i_size_write(src, 0);
	exfat_set_valid_size(src_ei, 0);
	exfat_set_zeroed_size(src_ei, 0);
	exfat_combine_reset_hints(src);
	src_ei->attr |= EXFAT_ATTR_ARCHIVE;
	inode_set_mtime_to_ts(src, inode_set_ctime_current(src));
	ret = exfat_emergency_state(sb);
	if (!ret) {
		ret = __exfat_write_inode(src, 1);
		if (ret)	/* as for @dst in step 2 */
			errseq_check_and_advance(&sb->s_bdev->bd_mapping->wb_err,
						 meta_since);
	}
	if (ret)
		mark_inode_dirty(src);
	mutex_unlock(&sbi->s_lock);
	return err ? err : ret;

undo:
	/*
	 * @dst does not own the clusters of @src, cut its chain again,
	 * unless the volume is in an emergency state.
	 */
	if (linked) {
		mutex_lock(&sbi->s_lock);
		if (!exfat_emergency_state(sb))
			exfat_ent_set(sb, last_clu, EXFAT_EOF_CLUSTER);
		mutex_unlock(&sbi->s_lock);
	}
	return err;
}

/*
 * Write back @inode and check that everything dirtied since @since has
 * reached the disk.  The error flags of a mapping go to whoever checks
 * them first, a concurrent fsync() included, so a clean return of the
 * writeback alone does not tell; its errseq does.  Mark the error seen,
 * so that it does not fail later calls; @since is the caller's copy, so
 * checking again with it still reports the error.
 */
static int exfat_combine_write_back(struct inode *inode, errseq_t since)
{
	int err = filemap_write_and_wait(inode->i_mapping);
	int ret = errseq_check_and_advance(&inode->i_mapping->wb_err, &since);

	return err ? err : ret;
}

/*
 * Undo the zero padding of @dst after a failed combine: drop its size
 * back to @old_size.  Once @dst was written back, the zeroes and any
 * stores through mmap below @old_size are on disk, so keep them, as
 * exfat_extend_valid_size() does, after flushing them to the medium
 * ahead of the entry that covers them.  Only if @dst cannot be written
 * back, drop its valid size back to @old_valid and its zeroed size to
 * no more than that, and unmap that range so that further stores through
 * mmap fault again and extend valid_size.  The entry is written right
 * away.
 * Called with the inode and invalidate locks of @dst held.
 */
static void exfat_combine_unpad(struct inode *dst, loff_t old_size,
				loff_t old_valid, loff_t old_zeroed,
				bool written, errseq_t since)
{
	struct exfat_sb_info *sbi = EXFAT_SB(dst->i_sb);
	struct exfat_inode_info *ei = EXFAT_I(dst);
	bool shrink = i_size_read(dst) > old_size;
	loff_t zeroed;

	if (shrink)
		truncate_setsize(dst, old_size);
	/* Do not rely on exfat_truncate(), which stops early after an error. */
	if (exfat_get_valid_size(ei) > old_size)
		exfat_set_valid_size(ei, old_size);
	if (exfat_get_zeroed_size(ei) > old_size)
		exfat_set_zeroed_size(ei, old_size);

	/*
	 * Padding or writing back @src may have failed before @dst was
	 * written back: try that first, as stores through mmap that have
	 * already completed cannot be made to fault again.
	 */
	if (!written)
		written = !exfat_combine_write_back(dst, since);

	if (written) {
		if (exfat_get_valid_size(ei) > old_valid)
			blkdev_issue_flush(dst->i_sb->s_bdev);
	} else {
		if (exfat_get_valid_size(ei) > old_valid) {
			/*
			 * unmap_mapping_range() rounds the start down but not
			 * the length up past it: pass whole pages, or the last
			 * page of the range stays mapped writable.
			 */
			if (old_valid < old_size) {
				loff_t start = round_down(old_valid, PAGE_SIZE);

				unmap_mapping_range(dst->i_mapping, start,
						    old_size - start, 0);
			}
			exfat_set_valid_size(ei, old_valid);
		}
		/*
		 * The failed writeback also cleaned a folio that was dirty
		 * before the call, without its blocks reaching the disk: do
		 * not count its tail past @old_valid as initialized, so that
		 * extending valid_size prepares and dirties it again.
		 */
		zeroed = min(old_zeroed, old_valid);
		if (exfat_get_zeroed_size(ei) > zeroed)
			exfat_set_zeroed_size(ei, zeroed);
	}

	if (shrink) {
		exfat_truncate(dst);	/* writes the entry */
	} else if (!exfat_emergency_state(dst->i_sb)) {
		mutex_lock(&sbi->s_lock);
		if (__exfat_write_inode(dst, inode_needs_sync(dst)))
			mark_inode_dirty(dst);
		mutex_unlock(&sbi->s_lock);
	}
}

/*
 * A failed truncate can leave the allocation of a file larger than its
 * size, or its valid_size above its size, and a corrupt entry can carry
 * neither chain layout, or a contiguous chain running past the volume.
 * Refuse such a file before anything is changed, as padding @dst
 * allocates based on its allocation, the valid_size of @src is carried
 * over to @dst, and Step 1 writes the FAT entries of contiguous chains.
 */
static bool exfat_combine_inode_ok(struct inode *inode)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	loff_t size = i_size_read(inode);

	if (exfat_ondisk_size(inode) != round_up(size, sbi->cluster_size) ||
	    (!size && ei->start_clu != EXFAT_EOF_CLUSTER) ||
	    (size && ei->start_clu == EXFAT_EOF_CLUSTER) ||
	    exfat_get_valid_size(ei) > size)
		return false;
	if (!size || ei->flags == ALLOC_FAT_CHAIN)
		return true;
	/* As exfat_validate_vendor_alloc() checks a contiguous range. */
	return ei->flags == ALLOC_NO_FAT_CHAIN &&
	       DIV_ROUND_UP_ULL(size, sbi->cluster_size) <=
	       sbi->num_clusters - ei->start_clu;
}

/*
 * Only a corrupt volume has files sharing clusters.  Refuse them before
 * anything is changed: zero-filling @dst would overwrite data of @src in
 * a shared cluster, and linking @src would create a loop in the FAT.
 * Two files owning more clusters than are in use share some of them, and
 * the result would fail the check of exfat_find() too.  The chain of
 * @dst cannot change until the combine, as it is fully allocated and the
 * caller holds its inode lock.
 */
static int exfat_combine_check_chains(struct inode *dst, struct inode *src,
				      unsigned int *last)
{
	struct super_block *sb = dst->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *dst_ei = EXFAT_I(dst);
	struct exfat_inode_info *src_ei = EXFAT_I(src);
	unsigned int dst_clus, src_clus;
	struct exfat_chain chain, src_chain;
	int err = 0;

	dst_clus = exfat_bytes_to_cluster_round_up(sbi, i_size_read(dst));
	src_clus = exfat_bytes_to_cluster_round_up(sbi, i_size_read(src));
	*last = EXFAT_EOF_CLUSTER;

	mutex_lock(&sbi->s_lock);
	if ((u64)dst_clus + src_clus > sbi->used_clusters) {
		err = -EIO;
	} else if (dst_clus) {
		exfat_chain_set(&chain, dst_ei->start_clu, dst_clus,
				dst_ei->flags);
		exfat_chain_set(&src_chain, src_ei->start_clu, src_clus,
				src_ei->flags);
		err = exfat_combine_find_last(sb, &chain, &src_chain, last);
	}
	mutex_unlock(&sbi->s_lock);
	return err;
}

static int exfat_ioctl_combine(struct file *dst_file, unsigned long arg)
{
	struct inode *dst = file_inode(dst_file);
	struct exfat_sb_info *sbi = EXFAT_SB(dst->i_sb);
	struct exfat_combine_args args;
	struct file *src_file;
	struct inode *src;
	loff_t old_size, old_valid, old_zeroed, dst_size, src_size;
	errseq_t dst_since, src_since, meta_since;
	unsigned int last_clu;
	bool written = false, moved = false;
	int err = 0;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	if (args.flags)
		return -EINVAL;

	CLASS(fd, f)(args.src_fd);
	if (fd_empty(f))
		return -EBADF;
	src_file = fd_file(f);
	src = file_inode(src_file);

	/* The data of @src becomes readable through @dst. */
	if (!(dst_file->f_mode & FMODE_WRITE) ||
	    !(src_file->f_mode & FMODE_READ) ||
	    !(src_file->f_mode & FMODE_WRITE))
		return -EBADF;

	if (dst_file->f_path.mnt != src_file->f_path.mnt)
		return -EXDEV;

	if (!S_ISREG(dst->i_mode) || !S_ISREG(src->i_mode) || dst == src)
		return -EINVAL;

	if (unlikely(exfat_forced_shutdown(dst->i_sb)))
		return -EIO;

	/*
	 * After an unclean shutdown, the clusters of a source may already
	 * belong to its destination as well, or be linked to it, and any file
	 * may be inconsistent until fsck.exfat has run.
	 */
	if (sbi->vol_flags_persistent & VOLUME_DIRTY)
		return -EUCLEAN;

	/* LSM and fanotify permission checks, done before taking any lock. */
	src_size = i_size_read(src);
	err = remap_verify_area(src_file, 0, src_size, true);
	if (err)
		return err;
	err = remap_verify_area(dst_file, i_size_read(dst), src_size, true);
	if (err)
		return err;

	err = mnt_want_write_file(dst_file);
	if (err)
		return err;

	lock_two_nondirectories(dst, src);
	/* swapon() sets S_SWAPFILE under the inode lock. */
	if (IS_SWAPFILE(dst) || IS_SWAPFILE(src)) {
		err = -ETXTBSY;
		goto out_unlock_inodes;
	}
	/* An unlinked @dst is not written back: @src would lose its data. */
	if (!dst->i_nlink) {
		err = -ENOENT;
		goto out_unlock_inodes;
	}
	if (!exfat_combine_inode_ok(dst) || !exfat_combine_inode_ok(src)) {
		err = -EIO;
		goto out_unlock_inodes;
	}
	inode_dio_wait(dst);
	inode_dio_wait(src);

	src_size = i_size_read(src);
	if (!src_size)
		goto out_unlock_inodes;

	err = exfat_combine_check_chains(dst, src, &last_clu);
	if (err)
		goto out_unlock_inodes;

	err = exfat_emergency_state(dst->i_sb);
	if (err)
		goto out_unlock_inodes;

	/*
	 * exFAT cannot describe a gap in the middle of a file, and the rest
	 * of the last cluster of @dst may hold stale data.  Zero-fill @dst
	 * up to the end of its last cluster, including any uninitialized
	 * range before i_size, so that @src starts at a cluster boundary.
	 */
	dst_size = round_up(i_size_read(dst), sbi->cluster_size);
	err = inode_newsize_ok(dst, dst_size + src_size);
	if (err)
		goto out_unlock_inodes;

	old_size = i_size_read(dst);
	old_valid = exfat_get_valid_size(EXFAT_I(dst));
	old_zeroed = exfat_get_zeroed_size(EXFAT_I(dst));
	dst_since = filemap_sample_wb_err(dst->i_mapping);
	src_since = filemap_sample_wb_err(src->i_mapping);
	meta_since = filemap_sample_wb_err(dst->i_sb->s_bdev->bd_mapping);
	err = exfat_extend_valid_size(dst, dst_size);

	filemap_invalidate_lock_two(dst->i_mapping, src->i_mapping);
	if (err)
		goto out_unlock;

	/*
	 * Dirty data of @src must reach its clusters before they change
	 * owner.  All dirty data of @dst, including the zeroes just written,
	 * must be on disk before its new valid_size is, and cached folios of
	 * @dst past its EOF must not shadow the data appended from @src.
	 */
	err = exfat_combine_write_back(src, src_since);
	if (err)
		goto out_unlock;

	err = exfat_combine_write_back(dst, dst_since);
	if (err)
		goto out_unlock;
	written = true;

	err = invalidate_inode_pages2_range(dst->i_mapping,
					    dst_size >> PAGE_SHIFT, -1);
	if (err)
		goto out_unlock;

	err = __exfat_combine(dst, src, last_clu, &meta_since);
	moved = i_size_read(dst) > dst_size;

	/* @src may have been emptied even if a later step failed. */
	truncate_pagecache(src, i_size_read(src));
	if (moved) {
		fsnotify_modify(dst_file);
		fsnotify_modify(src_file);
	}

out_unlock:
	/*
	 * If the clusters were not moved, undo the zero padding so that a
	 * failed call leaves @dst as it was.
	 */
	if (err && i_size_read(dst) <= dst_size)
		exfat_combine_unpad(dst, old_size, old_valid, old_zeroed,
				    written, dst_since);
	filemap_invalidate_unlock_two(dst->i_mapping, src->i_mapping);
out_unlock_inodes:
	unlock_two_nondirectories(dst, src);

	/*
	 * Make the empty entry of @src durable and check for metadata write
	 * errors, with the inode locks dropped so that writers of either
	 * file are not stalled by the device.  Unlinking the emptied @src,
	 * if it is not needed, is up to the caller.
	 */
	if (!err && moved)
		err = exfat_combine_flush(dst->i_sb, &meta_since);
	mnt_drop_write_file(dst_file);
	return err;
}

long exfat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	u32 __user *user_attr = (u32 __user *)arg;

	switch (cmd) {
	case FAT_IOCTL_GET_ATTRIBUTES:
		return exfat_ioctl_get_attributes(inode, user_attr);
	case FAT_IOCTL_SET_ATTRIBUTES:
		return exfat_ioctl_set_attributes(filp, user_attr);
	case EXFAT_IOC_SHUTDOWN:
		return exfat_ioctl_shutdown(inode->i_sb, arg);
	case EXFAT_IOC_COMBINE:
		return exfat_ioctl_combine(filp, arg);
	case FITRIM:
		return exfat_ioctl_fitrim(inode, arg);
	case FS_IOC_GETFSLABEL:
		return exfat_ioctl_get_volume_label(inode->i_sb, arg);
	case FS_IOC_SETFSLABEL:
		return exfat_ioctl_set_volume_label(inode->i_sb, arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long exfat_compat_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	return exfat_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

int exfat_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	int err;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	err = simple_fsync_noflush(filp, start, end, datasync);
	if (err)
		return err;

	err = sync_blockdev(inode->i_sb->s_bdev);
	if (err)
		return err;

	return blkdev_issue_flush(inode->i_sb->s_bdev);
}

/*
 * exfat_zero_new_range - zero [start, end) without overwriting uptodate blocks
 *
 * Uptodate blocks may contain data written through a shared mapping beyond
 * valid_size.
 */
static int exfat_zero_new_range(struct inode *inode, loff_t start, loff_t end)
{
	struct address_space *mapping = inode->i_mapping;
	unsigned int blocksize = i_blocksize(inode);
	loff_t pos = start;
	int err;

	while (pos < end) {
		loff_t next = min_t(loff_t,
				round_down(pos, PAGE_SIZE) + PAGE_SIZE, end);
		struct folio *folio;
		loff_t bpos;

		folio = filemap_get_folio(mapping, pos >> PAGE_SHIFT);
		if (IS_ERR(folio)) {
			err = iomap_zero_range(inode, pos, next - pos, NULL,
					       &exfat_iomap_ops, NULL, NULL);
			if (err < 0)
				return err;
			pos = next;
			continue;
		}

		if (folio_test_uptodate(folio)) {
			folio_lock(folio);
			if (folio->mapping == mapping)
				folio_mark_dirty(folio);
			folio_unlock(folio);
			folio_put(folio);
			pos = next;
			continue;
		}

		/*
		 * Zero not-uptodate block runs. iomap_zero_range() requires an
		 * unlocked folio, so recheck ->mapping after each call.
		 */
		folio_lock(folio);
		bpos = pos;
		while (bpos < next) {
			loff_t rstart, rend;

			if (folio->mapping != mapping) {
				folio_unlock(folio);
				err = iomap_zero_range(inode, bpos, next - bpos,
						NULL, &exfat_iomap_ops, NULL, NULL);
				if (err < 0) {
					folio_put(folio);
					return err;
				}
				folio_lock(folio);
				break;
			}

			if (iomap_is_partially_uptodate(folio,
					offset_in_folio(folio, bpos), blocksize)) {
				bpos += blocksize;
				continue;
			}

			rstart = bpos;
			rend = min_t(loff_t, bpos + blocksize, next);
			while (rend < next &&
			       !iomap_is_partially_uptodate(folio,
					offset_in_folio(folio, rend), blocksize))
				rend = min_t(loff_t, rend + blocksize, next);

			folio_unlock(folio);
			err = iomap_zero_range(inode, rstart, rend - rstart,
					NULL, &exfat_iomap_ops, NULL, NULL);
			if (err < 0) {
				folio_put(folio);
				return err;
			}
			folio_lock(folio);
			bpos = rend;
		}

		/*
		 * Dirty only a fully uptodate folio. Dirtying a partial folio could
		 * write uninitialised cache contents over valid on-disk blocks.
		 */
		if (folio->mapping == mapping && folio_test_uptodate(folio))
			folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
		pos = next;
	}

	return 0;
}

static int exfat_extend_valid_size(struct inode *inode, loff_t new_valid_size)
{
	struct exfat_inode_info *ei = EXFAT_I(inode);
	loff_t old_valid_size = ei->valid_size;
	int ret = 0;

	if (old_valid_size < new_valid_size) {
		/* Do not re-zero blocks already covered by zeroed_size. */
		loff_t gap_start = max(old_valid_size, ei->zeroed_size);

		if (i_size_read(inode) < new_valid_size) {
			/*
			 * Allocate clusters before increasing i_size. The gap
			 * may already be zeroed, so the subsequent zeroing
			 * can be skipped.
			 */
			ret = exfat_cont_expand(inode, new_valid_size);
			if (ret)
				return ret;
		}

		/*
		 * Revoke writable PTEs while zeroing the gap. A racing mmap
		 * store re-faults through exfat_page_mkwrite() after valid_size
		 * is updated.
		 */
		filemap_invalidate_lock(inode->i_mapping);
		if (gap_start < new_valid_size)
			unmap_mapping_range(inode->i_mapping, gap_start,
					new_valid_size - gap_start, 0);
		ret = exfat_zero_new_range(inode, gap_start, new_valid_size);
		filemap_invalidate_unlock(inode->i_mapping);
		if (ret) {
			truncate_setsize(inode, old_valid_size);
			exfat_truncate(inode);
			return ret;
		}

		ei->valid_size = new_valid_size;
		if (ei->zeroed_size < round_up(new_valid_size, i_blocksize(inode)))
			ei->zeroed_size = round_up(new_valid_size, i_blocksize(inode));
		mark_inode_dirty(inode);
	}

	return ret;
}

static ssize_t exfat_fallback_buffered_write(struct kiocb *iocb,
		struct iov_iter *from)
{
	loff_t offset = iocb->ki_pos, end;
	ssize_t written;
	int ret;

	iocb->ki_flags &= ~IOCB_DIRECT;

	written = iomap_file_buffered_write(iocb, from, &exfat_write_iomap_ops,
			NULL, NULL);
	if (written < 0)
		return written;

	end = iocb->ki_pos + written - 1;
	ret = filemap_write_and_wait_range(iocb->ki_filp->f_mapping,
			offset, end);
	if (ret)
		return -EIO;

	invalidate_mapping_pages(iocb->ki_filp->f_mapping,
			offset >> PAGE_SHIFT,
			end >> PAGE_SHIFT);

	return written;
}

static ssize_t exfat_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;

	ret = iomap_dio_rw(iocb, from, &exfat_write_iomap_ops,
			&exfat_write_dio_ops, 0, NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;
	else if (ret < 0)
		return ret;

	if (iov_iter_count(from)) {
		ssize_t written;

		written = exfat_fallback_buffered_write(iocb, from);
		if (written < 0)
			return written;
		ret += written;
	}

	return ret;
}

static ssize_t exfat_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	loff_t pos = iocb->ki_pos;
	loff_t valid_size;
	int err;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	inode_lock(inode);

	if (pos > i_size_read(inode))
		truncate_pagecache(inode, i_size_read(inode));

	valid_size = ei->valid_size;

	ret = generic_write_checks(iocb, iter);
	if (ret <= 0)
		goto unlock;

	err = file_modified(iocb->ki_filp);
	if (err) {
		ret = err;
		goto unlock;
	}

	if (pos > valid_size) {
		ret = exfat_extend_valid_size(inode, pos);
		if (ret < 0 && ret != -ENOSPC) {
			exfat_err(inode->i_sb,
				"write: fail to zero from %llu to %llu(%zd)",
				valid_size, pos, ret);
		}
		if (ret < 0)
			goto unlock;
	}

	if (iocb->ki_flags & IOCB_DIRECT)
		ret = exfat_dio_write_iter(iocb, iter);
	else
		ret = iomap_file_buffered_write(iocb, iter,
				&exfat_write_iomap_ops, NULL, NULL);
	if (ret < 0)
		goto unlock;

	inode_unlock(inode);

	if (pos > valid_size)
		pos = valid_size;

	if (iocb->ki_pos > pos) {
		ssize_t err = generic_write_sync(iocb, iocb->ki_pos - pos);

		if (err < 0)
			return err;
	}

	return ret;

unlock:
	inode_unlock(inode);

	return ret;
}

static ssize_t exfat_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	inode_lock_shared(inode);

	if (iocb->ki_flags & IOCB_DIRECT) {
		file_accessed(iocb->ki_filp);
		ret = iomap_dio_rw(iocb, iter, &exfat_iomap_ops, NULL, 0,
				NULL, 0);
	} else {
		ret = generic_file_read_iter(iocb, iter);
	}

	inode_unlock_shared(inode);

	return ret;
}

static vm_fault_t exfat_page_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	vm_fault_t ret;
	loff_t new_valid_size, mmap_valid_size, fault_page_start;

	if (!inode_trylock(inode))
		return VM_FAULT_RETRY;

	mmap_valid_size = ((loff_t)vmf->pgoff + 1) << PAGE_SHIFT;
	fault_page_start = ((loff_t)vmf->pgoff) << PAGE_SHIFT;
	new_valid_size = min(mmap_valid_size, i_size_read(inode));

	if (ei->valid_size < new_valid_size) {
		if (ei->zeroed_size < fault_page_start) {
			int err;

			/*
			 * Zero only the gap below the faulting page. The read
			 * fault populated its folio and iomap_page_mkwrite()
			 * will dirty it.
			 */
			err = exfat_zero_new_range(inode, ei->zeroed_size,
					fault_page_start);
			if (err < 0) {
				inode_unlock(inode);
				return vmf_fs_error(err);
			}
		}

		/*
		 * Track zeroed_size by block, not page, because writeback stops
		 * at i_size recording blocks wholly beyond it could skip a
		 * later required zeroing.
		 */
		if (ei->zeroed_size < round_up(new_valid_size, i_blocksize(inode)))
			ei->zeroed_size = round_up(new_valid_size, i_blocksize(inode));
		ei->valid_size = new_valid_size;
		mark_inode_dirty(inode);
	}

	sb_start_pagefault(inode->i_sb);
	file_update_time(vmf->vma->vm_file);

	filemap_invalidate_lock_shared(inode->i_mapping);
	ret = iomap_page_mkwrite(vmf, &exfat_iomap_ops, NULL);
	filemap_invalidate_unlock_shared(inode->i_mapping);
	sb_end_pagefault(inode->i_sb);
	inode_unlock(inode);

	return ret;
}

static const struct vm_operations_struct exfat_file_vm_ops = {
	.fault		= filemap_fault,
	.page_mkwrite	= exfat_page_mkwrite,
};

static int exfat_file_mmap_prepare(struct vm_area_desc *desc)
{
	struct file *file = desc->file;

	if (unlikely(exfat_forced_shutdown(file_inode(desc->file)->i_sb)))
		return -EIO;

	file_accessed(file);
	desc->vm_ops = &exfat_file_vm_ops;
	return 0;
}

static ssize_t exfat_splice_read(struct file *in, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	if (unlikely(exfat_forced_shutdown(file_inode(in)->i_sb)))
		return -EIO;

	return filemap_splice_read(in, ppos, pipe, len, flags);
}

static int exfat_file_open(struct inode *inode, struct file *filp)
{
	int err;

	if (unlikely(exfat_forced_shutdown(inode->i_sb)))
		return -EIO;

	err = generic_file_open(inode, filp);
	if (err)
		return err;

	filp->f_mode |= FMODE_CAN_ODIRECT;

	return 0;
}

static loff_t exfat_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	switch (whence) {
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, &exfat_iomap_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, &exfat_iomap_ops);
		inode_unlock_shared(inode);
		break;
	default:
		return generic_file_llseek(file, offset, whence);
	}
	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

const struct file_operations exfat_file_operations = {
	.open		= exfat_file_open,
	.llseek		= exfat_file_llseek,
	.read_iter	= exfat_file_read_iter,
	.write_iter	= exfat_file_write_iter,
	.unlocked_ioctl = exfat_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = exfat_compat_ioctl,
#endif
	.mmap_prepare	= exfat_file_mmap_prepare,
	.fsync		= exfat_file_fsync,
	.splice_read	= exfat_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= exfat_fallocate,
	.setlease	= generic_setlease,
};

const struct inode_operations exfat_file_inode_operations = {
	.setattr	= exfat_setattr,
	.getattr	= exfat_getattr,
	.fileattr_get	= exfat_fileattr_get,
};

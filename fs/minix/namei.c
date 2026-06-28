// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include "minix.h"
#include <linux/buffer_head.h>
#include <linux/namei.h>

static int add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = minix_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

static struct dentry *minix_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
	struct inode * inode = NULL;
	ino_t ino;

	if (dentry->d_name.len > minix_sb(dir->i_sb)->s_namelen)
		return ERR_PTR(-ENAMETOOLONG);

	ino = minix_inode_by_name(dentry);
	if (ino)
		inode = minix_iget(dir->i_sb, ino);
	return d_splice_alias(inode, dentry);
}

static int minix_mknod(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct inode *inode;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = minix_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	minix_set_inode(inode, rdev);
	mark_inode_dirty(inode);
	return add_nondir(dentry, inode);
}

static int minix_tmpfile(struct mnt_idmap *idmap, struct inode *dir,
			 struct file *file, umode_t mode)
{
	struct inode *inode = minix_new_inode(dir, mode);

	if (IS_ERR(inode))
		return finish_open_simple(file, PTR_ERR(inode));
	minix_set_inode(inode, 0);
	mark_inode_dirty(inode);
	d_tmpfile(file, inode);
	return finish_open_simple(file, 0);
}

static int minix_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	return minix_mknod(&nop_mnt_idmap, dir, dentry, mode, 0);
}

static inline u16 *v1_i_data(struct inode *inode)
{
	return (u16 *)minix_i(inode)->u.i1_data;
}

static inline u32 *v2_i_data(struct inode *inode)
{
	return (u32 *)minix_i(inode)->u.i2_data;
}

static inline u16 cpu_to_v1_block(sector_t n)
{
	return n;
}

static inline u32 cpu_to_v2_block(sector_t n)
{
	return n;
}

static inline sector_t v1_block_to_cpu(u16 n)
{
	return n;
}

static inline sector_t v2_block_to_cpu(u32 n)
{
	return n;
}

/* Reimplement page_symlink's general logic while avoiding using buffer head
 * based aops operations like aops->write_begin so things behave better with
 * the new regime of iomap based aops operations. Cribbing from page_symlink in
 * fs/namei.c and ext4's ext4_init_symlink_block.
 */
static int __page_symlink(struct inode *inode, const char *symname, int len)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	char *kaddr;
	int err = 0;
	u16 *p16; /* v1 16 bit block */
	u32 *p32; /* v2/3 32 bit block */

	sector_t phys;

	phys = minix_new_block(inode);
	if (!phys) {
		err = -ENOSPC;
		goto ps_out;
	}

	if (INODE_VERSION(inode) == MINIX_V1) {
		p16 = v1_i_data(inode);
		*p16 = cpu_to_v1_block(phys);
	} else {
		p32 = v2_i_data(inode);
		*p32 = cpu_to_v2_block(phys);
	}

	bh = sb_getblk(sb, phys);
	if (!bh) {
		err = -ENOMEM;
		goto ps_fail;
	}

	lock_buffer(bh);
	kaddr = (char *)bh->b_data;
	memset(kaddr, 0, sb->s_blocksize);
	memcpy(kaddr, symname, len);
	inode->i_size = len - 1;
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	mmb_mark_buffer_dirty(bh, &minix_i(inode)->i_metadata_bhs);
	if (inode_needs_sync(inode)) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			pr_err("i/o error syncing itable block");
			err = -EIO;
		}

	}

	mark_inode_dirty(inode);
	brelse(bh);

ps_out:
	return err;

ps_fail:
	minix_free_block(inode, phys);
	goto ps_out;
}

static int minix_symlink(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, const char *symname)
{
	int i = strlen(symname)+1;
	struct inode * inode;
	int err;

	if (i > dir->i_sb->s_blocksize)
		return -ENAMETOOLONG;

	inode = minix_new_inode(dir, S_IFLNK | 0777);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	minix_set_inode(inode, 0);
	err = __page_symlink(inode, symname, i);
	if (unlikely(err)) {
		inode_dec_link_count(inode);
		iput(inode);
		return err;
	}
	return add_nondir(dentry, inode);
}

static int minix_link(struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	inode_set_ctime_current(inode);
	inode_inc_link_count(inode);
	ihold(inode);
	return add_nondir(dentry, inode);
}

static struct dentry *minix_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				  struct dentry *dentry, umode_t mode)
{
	struct inode * inode;
	int err;

	inode = minix_new_inode(dir, S_IFDIR | mode);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode_inc_link_count(dir);
	minix_set_inode(inode, 0);
	inode_inc_link_count(inode);

	err = minix_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = minix_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
out:
	return ERR_PTR(err);

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput(inode);
	inode_dec_link_count(dir);
	goto out;
}

static int minix_unlink(struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = d_inode(dentry);
	struct folio *folio;
	struct minix_dir_entry * de;
	int err;

	if (inode->i_nlink == 0) {
		minix_error_inode(inode, "inode has corrupted nlink");
		return -EFSCORRUPTED;
	}

	de = minix_find_entry(dentry, &folio);
	if (!de)
		return -ENOENT;
	err = minix_delete_entry(de, folio);
	folio_release_kmap(folio, de);

	if (err)
		return err;
	inode_set_ctime_to_ts(inode, inode_get_ctime(dir));
	inode_dec_link_count(inode);
	return 0;
}

static int minix_rmdir(struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = d_inode(dentry);
	int err = -EFSCORRUPTED;

	if (dir->i_nlink <= 2) {
		minix_error_inode(dir, "inode has corrupted nlink");
		goto out;
	}

	err = -ENOTEMPTY;
	if (!minix_empty_dir(inode))
		goto out;

	err = minix_unlink(dir, dentry);
	if (!err) {
		inode_dec_link_count(dir);
		inode_dec_link_count(inode);
	}

out:
	return err;
}

static int minix_rename(struct mnt_idmap *idmap,
			struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct inode * old_inode = d_inode(old_dentry);
	struct inode * new_inode = d_inode(new_dentry);
	struct folio * dir_folio = NULL;
	struct minix_dir_entry * dir_de = NULL;
	struct folio *old_folio;
	struct minix_dir_entry * old_de;
	int err = -ENOENT;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	old_de = minix_find_entry(old_dentry, &old_folio);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = minix_dotdot(old_inode, &dir_folio);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct folio *new_folio;
		struct minix_dir_entry * new_de;

		err = -ENOTEMPTY;
		if (dir_de && !minix_empty_dir(new_inode))
			goto out_dir;

		err = -EFSCORRUPTED;
		if (new_inode->i_nlink == 0 || (dir_de && new_inode->i_nlink != 2)) {
			minix_error_inode(new_inode, "inode has corrupted nlink");
			goto out_dir;
		}

		if (dir_de && old_dir->i_nlink <= 2) {
			minix_error_inode(old_dir, "inode has corrupted nlink");
			goto out_dir;
		}

		err = -ENOENT;
		new_de = minix_find_entry(new_dentry, &new_folio);
		if (!new_de)
			goto out_dir;
		err = minix_set_link(new_de, new_folio, old_inode);
		folio_release_kmap(new_folio, new_de);
		if (err)
			goto out_dir;
		inode_set_ctime_current(new_inode);
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = minix_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	err = minix_delete_entry(old_de, old_folio);
	if (err)
		goto out_dir;

	mark_inode_dirty(old_inode);

	if (dir_de) {
		err = minix_set_link(dir_de, dir_folio, new_dir);
		if (!err)
			inode_dec_link_count(old_dir);
	}
out_dir:
	if (dir_de)
		folio_release_kmap(dir_folio, dir_de);
out_old:
	folio_release_kmap(old_folio, old_de);
out:
	return err;
}

/* straight up thievery here; stolen verbatim from ext4_get_link */
static void minix_free_link(void *bh)
{
	brelse(bh);
}

/* Borrowing from ext4_get_link to a degree; since minix inodes and symlinks
 * are significantly simpler, we don't need to do nearly as much as ext4
 * requires for old-timey ext4 slow links.
 */
const char *minix_get_link(struct dentry *dentry, struct inode *inode,
		struct delayed_call *callback)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	sector_t blk;

	/* Get yon block, depending on what version of the minix fs this is. */
	if (INODE_VERSION(inode) == MINIX_V1)
		blk = v1_block_to_cpu(*(v1_i_data(inode)));
	else
		blk = v2_block_to_cpu(*(v2_i_data(inode)));

	bh = sb_bread(sb, blk);
	if (IS_ERR(bh))
		return ERR_CAST(bh);
	if (!bh) {
		pr_err("bad symlink on inode %llu", inode->i_ino);
		return ERR_PTR(-EFSCORRUPTED);
	}

	set_delayed_call(callback, minix_free_link, bh);
	nd_terminate_link(bh->b_data, inode->i_size,
			inode->i_sb->s_blocksize - 1);

	return bh->b_data;
}

/*
 * directories can handle most operations...
 */
const struct inode_operations minix_dir_inode_operations = {
	.create		= minix_create,
	.lookup		= minix_lookup,
	.link		= minix_link,
	.unlink		= minix_unlink,
	.symlink	= minix_symlink,
	.mkdir		= minix_mkdir,
	.rmdir		= minix_rmdir,
	.mknod		= minix_mknod,
	.rename		= minix_rename,
	.getattr	= minix_getattr,
	.tmpfile	= minix_tmpfile,
};

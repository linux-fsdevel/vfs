// SPDX-License-Identifier: GPL-2.0-only
/*
 * iomap functions for minix. At least the first pass of this file was taken
 * from the xiafs iomap.c, which is fitting since the xiafs module in turn
 * borrowed heavily from the modernized minix fs kernel module.
 */

/*
 * minix_iomap_begin - map a file range to disk blocks. It acts as a replacement
 * for get_block in itree_common.c, at least in the important ways, and is
 * adapted from it, but it uses iomap instead of buffer_head. This is taken
 * directly from the out-of-tree xiafs iomap changes, and the exfat iomap
 * changes were an inspiration for that.
 */
static int minix_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	struct super_block *sb = inode->i_sb;
	unsigned int blkbits = sb->s_blocksize_bits;
	sector_t iblock = offset >> blkbits;
	int create = flags & IOMAP_WRITE;

	/* Mostly taken from modern-xiafs itree.c get_block with elements from
	 * similar exfat operations.
	 */
	int offsets[DEPTH];
	Indirect chain[DEPTH];
	Indirect *partial;
	int depth = block_to_path(inode, iblock, offsets);
	int left;
	int err = -EIO;

	sector_t phys;

	/* block is beyond max file size */
	if (depth == 0)
		goto out;

	iomap->bdev = inode->i_sb->s_bdev;

reread:
	partial = get_branch(inode, depth, offsets, chain, &err);

	/* Simplest case - block found, no allocation needed */
	if (!partial) {
		/* Bit of a weird order, but it'll make sense when you get to
		 * the bottom.
		 */
		iomap->flags = IOMAP_F_MERGED;
got_it:
		phys = block_to_cpu(chain[depth - 1].key);
		partial = chain+depth-1;
		/* Set up the iomap struct before cleaning up */
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (u64)phys << blkbits;
		iomap->length = 1 << blkbits;
		iomap->offset = (u64)iblock << blkbits;
		goto cleanup;
	}

	/* Next simple case - plain lookup or failed read of indirect block */
	if (!create || err == -EIO) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->length = 1 << blkbits;
		iomap->offset = (u64)iblock << blkbits;
		iomap->flags = 0;
cleanup:
		while (partial > chain) {
			brelse(partial->bh);
			partial--;
		}
out:
		return err;
	}

	/*
	 * Indirect block might be removed by truncate while we were
	 * reading it. Handling of that case (forget what we've got and
	 * reread) is taken out of the main path.
	 */
	if (err == -EAGAIN)
		goto changed;

	left = (chain + depth) - partial;
	err = alloc_branch(inode, left, offsets + (partial - chain), partial);
	if (err)
		goto cleanup;

	if (splice_branch(inode, chain, partial, left) < 0)
		goto changed;

	/* Successful allocation, mapping it. */
	iomap->flags = IOMAP_F_NEW;
	goto got_it;

changed:
	while (partial > chain) {
		brelse(partial->bh);
		partial--;
	}
	goto reread;
}

/*
 * minix_iomap_end ends up being a nop; since minix doesn't have any extents or
 * transactions to worry about, there isn't anything to update here. The on-disk
 * indirect blocks get dirtied in minix_iomap_begin.
 */
static int minix_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned int flags, struct iomap *iomap)
{
	return 0;
}

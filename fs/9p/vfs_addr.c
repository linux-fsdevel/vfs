// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contians vfs address (mmap) ops for 9P2000.
 *
 *  Copyright (C) 2005 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/netfs.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>
#include <trace/events/netfs.h>

#include "v9fs.h"
#include "v9fs_vfs.h"
#include "cache.h"
#include "fid.h"

/*
 * Writeback calls this when it finds a folio that needs uploading.  This isn't
 * called if writeback only has copy-to-cache to deal with.
 */
static void v9fs_begin_writeback(struct netfs_io_request *wreq)
{
	struct p9_fid *fid;

	fid = v9fs_fid_find_inode(wreq->inode, true, INVALID_UID, true);
	if (!fid) {
		WARN_ONCE(1, "folio expected an open fid inode->i_ino=%lx\n",
			  wreq->inode->i_ino);
		return;
	}

	wreq->wsize = fid->clnt->msize - P9_IOHDRSZ;
	if (fid->iounit)
		wreq->wsize = min(wreq->wsize, fid->iounit);
	wreq->netfs_priv = fid;
	wreq->io_streams[0].avail = true;
}

/*
 * Estimate how much data should be accumulated before we start issuing
 * write subrequests.
 */
static int v9fs_estimate_write(struct netfs_io_request *wreq,
			       struct netfs_io_stream *stream,
			       struct netfs_write_estimate *estimate)
{
	struct p9_fid *fid = wreq->netfs_priv;
	unsigned long long limit = ULLONG_MAX - stream->issue_from;
	unsigned long long max_len = fid->clnt->msize - P9_IOHDRSZ;

	estimate->issue_at = stream->issue_from + umin(max_len, limit);
	return 0;
}

/*
 * Issue a subrequest to write to the server.
 */
static int v9fs_issue_write(struct netfs_io_subrequest *subreq)
{
	struct iov_iter iter;
	struct p9_fid *fid = subreq->rreq->netfs_priv;
	int err, len;

	subreq->len = umin(subreq->len, fid->clnt->msize - P9_IOHDRSZ);

	err = netfs_prepare_write_buffer(subreq, INT_MAX);
	if (err < 0)
		return err;

	iov_iter_bvec_queue(&iter, ITER_SOURCE, subreq->content.bvecq,
			    subreq->content.slot, subreq->content.offset, subreq->len);

	len = p9_client_write(fid, subreq->start, &iter, &err);
	if (len > 0)
		__set_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
	netfs_write_subrequest_terminated(subreq, len ?: err);
	return err;
}

/**
 * v9fs_issue_read - Issue a read from 9P
 * @subreq: The read to make
 * @rctx: Read generation context
 */
static int v9fs_issue_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct iov_iter iter;
	struct p9_fid *fid = rreq->netfs_priv;
	unsigned long long pos = subreq->start + subreq->transferred;
	int total, err;

	err = netfs_prepare_read_buffer(subreq, INT_MAX);
	if (err < 0)
		return err;

	iov_iter_bvec_queue(&iter, ITER_DEST, subreq->content.bvecq,
			    subreq->content.slot, subreq->content.offset, subreq->len);

	/* After this point, we're not allowed to return an error. */
	netfs_mark_read_submission(subreq);

	total = p9_client_read(fid, pos, &iter, &err);

	/* if we just extended the file size, any portion not in
	 * cache won't be on server and is zeroes */
	if (subreq->rreq->origin != NETFS_UNBUFFERED_READ &&
	    subreq->rreq->origin != NETFS_DIO_READ)
		__set_bit(NETFS_SREQ_CLEAR_TAIL, &subreq->flags);
	if (pos + total >= i_size_read(rreq->inode))
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
	if (!err && total) {
		subreq->transferred += total;
		__set_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
	}

	subreq->error = err;
	netfs_read_subreq_terminated(subreq);
	return -EIOCBQUEUED;
}

/**
 * v9fs_init_request - Initialise a request
 * @rreq: The read request
 * @file: The file being read from
 */
static int v9fs_init_request(struct netfs_io_request *rreq, struct file *file)
{
	struct p9_fid *fid;
	bool writing = (rreq->origin == NETFS_READ_FOR_WRITE ||
			rreq->origin == NETFS_WRITETHROUGH ||
			rreq->origin == NETFS_UNBUFFERED_WRITE ||
			rreq->origin == NETFS_DIO_WRITE);

	if (rreq->origin == NETFS_WRITEBACK)
		return 0; /* We don't get the write handle until we find we
			   * have actually dirty data and not just
			   * copy-to-cache data.
			   */

	if (file) {
		fid = file->private_data;
		if (!fid)
			goto no_fid;
		p9_fid_get(fid);
	} else {
		fid = v9fs_fid_find_inode(rreq->inode, writing, INVALID_UID, true);
		if (!fid)
			goto no_fid;
	}

	rreq->wsize = fid->clnt->msize - P9_IOHDRSZ;
	if (fid->iounit)
		rreq->wsize = min(rreq->wsize, fid->iounit);

	/* we might need to read from a fid that was opened write-only
	 * for read-modify-write of page cache, use the writeback fid
	 * for that */
	WARN_ON(rreq->origin == NETFS_READ_FOR_WRITE && !(fid->mode & P9_ORDWR));
	rreq->netfs_priv = fid;
	return 0;

no_fid:
	WARN_ONCE(1, "folio expected an open fid inode->i_ino=%lx\n",
		  rreq->inode->i_ino);
	return -EINVAL;
}

/**
 * v9fs_free_request - Cleanup request initialized by v9fs_init_rreq
 * @rreq: The I/O request to clean up
 */
static void v9fs_free_request(struct netfs_io_request *rreq)
{
	struct p9_fid *fid = rreq->netfs_priv;

	p9_fid_put(fid);
}

const struct netfs_request_ops v9fs_req_ops = {
	.init_request		= v9fs_init_request,
	.free_request		= v9fs_free_request,
	.issue_read		= v9fs_issue_read,
	.begin_writeback	= v9fs_begin_writeback,
	.estimate_write		= v9fs_estimate_write,
	.issue_write		= v9fs_issue_write,
};

const struct address_space_operations v9fs_addr_operations = {
	.read_folio		= netfs_read_folio,
	.readahead		= netfs_readahead,
	.dirty_folio		= netfs_dirty_folio,
	.release_folio		= netfs_release_folio,
	.invalidate_folio	= netfs_invalidate_folio,
	.direct_IO		= noop_direct_IO,
	.writepages		= netfs_writepages,
	.migrate_folio		= filemap_migrate_folio,
};

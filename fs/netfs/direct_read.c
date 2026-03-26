// SPDX-License-Identifier: GPL-2.0-or-later
/* Direct I/O support.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * Perform a read to a buffer from the server, slicing up the region to be read
 * according to the network rsize.
 */
static int netfs_dispatch_unbuffered_reads(struct netfs_io_request *rreq)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	unsigned long long start = rreq->start;
	ssize_t size = rreq->len;
	int ret = 0;

	bvecq_pos_set(&rreq->dispatch_cursor, &rreq->load_cursor);

	do {
		struct netfs_io_subrequest *subreq;

		subreq = netfs_alloc_subrequest(rreq);
		if (!subreq) {
			ret = -ENOMEM;
			break;
		}

		subreq->source	= NETFS_DOWNLOAD_FROM_SERVER;
		subreq->start	= start;
		subreq->len	= size;

		__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);

		spin_lock(&rreq->lock);
		list_add_tail(&subreq->rreq_link, &stream->subrequests);
		if (list_is_first(&subreq->rreq_link, &stream->subrequests)) {
			if (!stream->active) {
				stream->collected_to = subreq->start;
				/* Store list pointers before active flag */
				smp_store_release(&stream->active, true);
			}
		}
		trace_netfs_sreq(subreq, netfs_sreq_trace_added);
		spin_unlock(&rreq->lock);

		netfs_stat(&netfs_n_rh_download);
		if (rreq->netfs_ops->prepare_read) {
			ret = rreq->netfs_ops->prepare_read(subreq);
			if (ret < 0) {
				netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
				break;
			}
		}

		bvecq_pos_set(&subreq->dispatch_pos, &rreq->dispatch_cursor);
		bvecq_pos_set(&subreq->content, &rreq->dispatch_cursor);
		subreq->len = bvecq_slice(&rreq->dispatch_cursor,
					  umin(size, stream->sreq_max_len),
					  stream->sreq_max_segs,
					  &subreq->nr_segs);

		size -= subreq->len;
		start += subreq->len;
		rreq->submitted += subreq->len;
		if (size <= 0) {
			smp_wmb(); /* Write lists before ALL_QUEUED. */
			set_bit(NETFS_RREQ_ALL_QUEUED, &rreq->flags);
		}

		iov_iter_bvec_queue(&subreq->io_iter, ITER_DEST, subreq->content.bvecq,
				    subreq->content.slot, subreq->content.offset, subreq->len);

		rreq->netfs_ops->issue_read(subreq);

		if (test_bit(NETFS_RREQ_PAUSE, &rreq->flags))
			netfs_wait_for_paused_read(rreq);
		if (test_bit(NETFS_RREQ_FAILED, &rreq->flags))
			break;
		cond_resched();
	} while (size > 0);

	if (unlikely(size > 0)) {
		smp_wmb(); /* Write lists before ALL_QUEUED. */
		set_bit(NETFS_RREQ_ALL_QUEUED, &rreq->flags);
		netfs_wake_collector(rreq);
	}

	bvecq_pos_unset(&rreq->dispatch_cursor);
	return ret;
}

/*
 * Perform a read to an application buffer, bypassing the pagecache and the
 * local disk cache.
 */
static ssize_t netfs_unbuffered_read(struct netfs_io_request *rreq, bool sync)
{
	ssize_t ret;

	_enter("R=%x %llx-%llx",
	       rreq->debug_id, rreq->start, rreq->start + rreq->len - 1);

	if (rreq->len == 0) {
		pr_err("Zero-sized read [R=%x]\n", rreq->debug_id);
		netfs_put_request(rreq, netfs_rreq_trace_put_discard);
		return -EIO;
	}

	// TODO: Use bounce buffer if requested

	inode_dio_begin(rreq->inode);

	ret = netfs_dispatch_unbuffered_reads(rreq);

	if (!rreq->submitted) {
		netfs_put_request(rreq, netfs_rreq_trace_put_no_submit);
		inode_dio_end(rreq->inode);
		ret = 0;
		goto out;
	}

	if (sync)
		ret = netfs_wait_for_read(rreq);
	else
		ret = -EIOCBQUEUED;
out:
	_leave(" = %zd", ret);
	return ret;
}

/**
 * netfs_unbuffered_read_iter_locked - Perform an unbuffered or direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 *
 * Perform an unbuffered I/O or direct I/O from the file in @iocb to the
 * output buffer.  No use is made of the pagecache.
 *
 * The caller must hold any appropriate locks.
 */
ssize_t netfs_unbuffered_read_iter_locked(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_io_request *rreq;
	ssize_t ret;
	size_t orig_count = iov_iter_count(iter);
	bool sync = is_sync_kiocb(iocb);

	_enter("");

	if (!orig_count)
		return 0; /* Don't update atime */

	ret = kiocb_write_and_wait(iocb, orig_count);
	if (ret < 0)
		return ret;
	file_accessed(iocb->ki_filp);

	rreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   iocb->ki_pos, orig_count,
				   iocb->ki_flags & IOCB_DIRECT ?
				   NETFS_DIO_READ : NETFS_UNBUFFERED_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	netfs_stat(&netfs_n_rh_dio_read);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_dio_read);

	/* If this is an async op, we have to keep track of the destination
	 * buffer for ourselves as the caller's iterator will be trashed when
	 * we return.
	 *
	 * Extract a buffer queue to represent as much of the output buffer as
	 * we can manage.  The fragments are extracted into a bvecq which will
	 * have sufficient nodes allocated to hold all the data, though this
	 * may end up truncated if ENOMEM is encountered.
	 */
	ret = netfs_extract_iter(iter, rreq->len, INT_MAX, iocb->ki_pos,
				 &rreq->load_cursor.bvecq, 0);
	if (ret < 0)
		goto error_put;

	// TODO: Set up bounce buffer if needed

	if (!sync) {
		rreq->iocb = iocb;
		__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &rreq->flags);
	}

	ret = netfs_unbuffered_read(rreq, sync);
	if (ret < 0)
		goto out; /* May be -EIOCBQUEUED */
	if (sync) {
		// TODO: Copy from bounce buffer
		iocb->ki_pos += rreq->transferred;
		ret = rreq->transferred;
	}

out:
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	if (ret > 0)
		orig_count -= ret;
	return ret;

error_put:
	netfs_put_failed_request(rreq);
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_read_iter_locked);

/**
 * netfs_unbuffered_read_iter - Perform an unbuffered or direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 *
 * Perform an unbuffered I/O or direct I/O from the file in @iocb to the
 * output buffer.  No use is made of the pagecache.
 */
ssize_t netfs_unbuffered_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (!iter->count)
		return 0; /* Don't update atime */

	ret = netfs_start_io_direct(inode);
	if (ret == 0) {
		ret = netfs_unbuffered_read_iter_locked(iocb, iter);
		netfs_end_io_direct(inode);
	}
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_read_iter);

// SPDX-License-Identifier: GPL-2.0-or-later
/* Single, monolithic object support (e.g. AFS directory).
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
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

int netfs_prepare_read_single_buffer(struct netfs_io_subrequest *subreq,
				     unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct netfs_io_stream *stream = &rreq->io_streams[0];

	bvecq_pos_set(&subreq->dispatch_pos, &rreq->load_cursor);
	bvecq_pos_set(&subreq->content, &subreq->dispatch_pos);

	stream->issue_from += subreq->len;
	return 0;
}

/**
 * netfs_single_mark_inode_dirty - Mark a single, monolithic object inode dirty
 * @inode: The inode to mark
 *
 * Mark an inode that contains a single, monolithic object as dirty so that its
 * writepages op will get called.  If set, the SINGLE_NO_UPLOAD flag indicates
 * that the object will only be written to the cache and not uploaded (e.g. AFS
 * directory contents).
 */
void netfs_single_mark_inode_dirty(struct inode *inode)
{
	struct netfs_inode *ictx = netfs_inode(inode);
	bool cache_only = test_bit(NETFS_ICTX_SINGLE_NO_UPLOAD, &ictx->flags);
	bool caching = fscache_cookie_enabled(netfs_i_cookie(netfs_inode(inode)));

	if (cache_only && !caching)
		return;

	mark_inode_dirty(inode);

	if (caching && !(inode_state_read_once(inode) & I_PINNING_NETFS_WB)) {
		bool need_use = false;

		spin_lock(&inode->i_lock);
		if (!(inode_state_read(inode) & I_PINNING_NETFS_WB)) {
			inode_state_set(inode, I_PINNING_NETFS_WB);
			need_use = true;
		}
		spin_unlock(&inode->i_lock);

		if (need_use)
			fscache_use_cookie(netfs_i_cookie(ictx), true);
	}

}
EXPORT_SYMBOL(netfs_single_mark_inode_dirty);

static int netfs_single_begin_cache_read(struct netfs_io_request *rreq, struct netfs_inode *ctx)
{
	return fscache_begin_read_operation(&rreq->cache_resources, netfs_i_cookie(ctx));
}

/*
 * Perform a read to a buffer from the cache or the server.  Only a single
 * subreq is permitted as the object must be fetched in a single transaction.
 */
static int netfs_single_dispatch_read(struct netfs_io_request *rreq)
{
	struct fscache_occupancy occ = {
		.query_from	= 0,
		.query_to	= rreq->len,
		.cached_from[0]	= ULLONG_MAX,
		.cached_to[0]	= ULLONG_MAX,
		.cached_from[1]	= ULLONG_MAX,
		.cached_to[1]	= ULLONG_MAX,
	};
	struct netfs_io_subrequest *subreq;
	int ret;

	ret = netfs_read_query_cache(rreq, &occ);
	if (ret < 0)
		return ret;

	subreq = netfs_alloc_subrequest(rreq);
	if (!subreq)
		return -ENOMEM;

	subreq->start	= 0;
	subreq->len	= rreq->len;

	trace_netfs_sreq(subreq, netfs_sreq_trace_prepare);

	/* Try to use the cache if the cache content matches the size of the
	 * remote file.
	 */
	if (occ.cached_from[0] == 0 &&
	    occ.cached_to[0] == rreq->len) {
		struct netfs_cache_resources *cres = &rreq->cache_resources;

		subreq->source = NETFS_READ_FROM_CACHE;
		netfs_stat(&netfs_n_rh_read);
		ret = cres->ops->issue_read(subreq);
		if (ret == -EIOCBQUEUED)
			ret = netfs_wait_for_in_progress_subreq(rreq, subreq);
		if (ret == -ENOMEM)
			goto cancel;
		if (ret == 0)
			goto success;

		/* Didn't manage to retrieve from the cache, so toss it to the
		 * server instead.
		 */
		if (netfs_reset_for_read_retry(subreq) < 0)
			goto cancel;
	}

	__set_bit(NETFS_RREQ_FOLIO_COPY_TO_CACHE, &rreq->flags);

	/* Try to send it to the cache. */
	for (;;) {
		subreq->source = NETFS_DOWNLOAD_FROM_SERVER;
		netfs_stat(&netfs_n_rh_download);
		ret = rreq->netfs_ops->issue_read(subreq);
		if (ret == -EIOCBQUEUED)
			ret = netfs_wait_for_in_progress_subreq(rreq, subreq);
		if (ret == 0)
			goto success;
		if (ret == -ENOMEM)
			goto cancel;
		if (ret != -EAGAIN)
			goto failed;
		if (netfs_reset_for_read_retry(subreq) < 0)
			goto cancel;
	}

success:
	rreq->transferred = subreq->transferred;
	list_del_init(&subreq->rreq_link);
	netfs_put_subrequest(subreq, netfs_sreq_trace_put_consumed);
	return 0;
cancel:
	rreq->error = ret;
	list_del_init(&subreq->rreq_link);
	netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
	return ret;
failed:
	rreq->error = ret;
	list_del_init(&subreq->rreq_link);
	netfs_put_subrequest(subreq, netfs_sreq_trace_put_failed);
	return ret;
}

/**
 * netfs_read_single - Synchronously read a single blob of pages.
 * @inode: The inode to read from.
 * @file: The file we're using to read or NULL.
 * @iter: The buffer we're reading into.
 *
 * Fulfil a read request for a single monolithic object by drawing data from
 * the cache if possible, or the netfs if not.  The buffer may be larger than
 * the file content; unused beyond the EOF will be zero-filled.  The content
 * will be read with a single I/O request (though this may be retried).
 *
 * The calling netfs must initialise a netfs context contiguous to the vfs
 * inode before calling this.
 *
 * This is usable whether or not caching is enabled.  If caching is enabled,
 * the data will be stored as a single object into the cache.
 */
ssize_t netfs_read_single(struct inode *inode, struct file *file, struct iov_iter *iter)
{
	struct netfs_io_request *rreq;
	struct netfs_inode *ictx = netfs_inode(inode);
	ssize_t ret;

	rreq = netfs_alloc_request(inode->i_mapping, file, 0, iov_iter_count(iter),
				   NETFS_READ_SINGLE);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	ret = netfs_extract_iter(iter, rreq->len, INT_MAX, 0, &rreq->load_cursor.bvecq, 0);
	if (ret < 0)
		goto cleanup_free;

	ret = netfs_single_begin_cache_read(rreq, ictx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto cleanup_free;

	netfs_stat(&netfs_n_rh_read_single);
	trace_netfs_read(rreq, 0, rreq->len, netfs_read_trace_read_single);

	ret = netfs_single_dispatch_read(rreq);

	trace_netfs_rreq(rreq, netfs_rreq_trace_complete);
	if (ret == 0) {
		task_io_account_read(rreq->transferred);

		if (test_bit(NETFS_RREQ_FOLIO_COPY_TO_CACHE, &rreq->flags) &&
		    fscache_resources_valid(&rreq->cache_resources)) {
			trace_netfs_rreq(rreq, netfs_rreq_trace_dirty);
			netfs_single_mark_inode_dirty(rreq->inode);
		}
		ret = rreq->transferred;
	}

	if (rreq->netfs_ops->done)
		rreq->netfs_ops->done(rreq);

	netfs_wake_rreq_flag(rreq, NETFS_RREQ_IN_PROGRESS, netfs_rreq_trace_wake_ip);
	/* As we cleared NETFS_RREQ_IN_PROGRESS, we acquired its ref. */
	netfs_put_request(rreq, netfs_rreq_trace_put_work_ip);

	trace_netfs_rreq(rreq, netfs_rreq_trace_done);

	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	return ret;

cleanup_free:
	netfs_put_failed_request(rreq);
	return ret;
}
EXPORT_SYMBOL(netfs_read_single);

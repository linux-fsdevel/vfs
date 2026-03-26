// SPDX-License-Identifier: GPL-2.0-or-later
/* Network filesystem high-level buffered read support.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/task_io_accounting_ops.h>
#include "internal.h"

static void netfs_cache_expand_readahead(struct netfs_io_request *rreq,
					 unsigned long long *_start,
					 unsigned long long *_len,
					 unsigned long long i_size)
{
	struct netfs_cache_resources *cres = &rreq->cache_resources;

	if (cres->ops && cres->ops->expand_readahead)
		cres->ops->expand_readahead(cres, _start, _len, i_size);
}

static void netfs_rreq_expand(struct netfs_io_request *rreq,
			      struct readahead_control *ractl)
{
	/* Give the cache a chance to change the request parameters.  The
	 * resultant request must contain the original region.
	 */
	netfs_cache_expand_readahead(rreq, &rreq->start, &rreq->len, rreq->i_size);

	/* Give the netfs a chance to change the request parameters.  The
	 * resultant request must contain the original region.
	 */
	if (rreq->netfs_ops->expand_readahead)
		rreq->netfs_ops->expand_readahead(rreq);

	/* Expand the request if the cache wants it to start earlier.  Note
	 * that the expansion may get further extended if the VM wishes to
	 * insert THPs and the preferred start and/or end wind up in the middle
	 * of THPs.
	 *
	 * If this is the case, however, the THP size should be an integer
	 * multiple of the cache granule size, so we get a whole number of
	 * granules to deal with.
	 */
	if (rreq->start  != readahead_pos(ractl) ||
	    rreq->len != readahead_length(ractl)) {
		readahead_expand(ractl, rreq->start, rreq->len);
		rreq->start  = readahead_pos(ractl);
		rreq->len = readahead_length(ractl);

		trace_netfs_read(rreq, readahead_pos(ractl), readahead_length(ractl),
				 netfs_read_trace_expanded);
	}
}

/*
 * Drop the folio refs acquired from the readahead API.
 */
static void netfs_bulk_drop_ra_refs(struct netfs_io_request *rreq)
{
	struct folio_batch fbatch;
	struct folio *folio;
	pgoff_t nr_pages = DIV_ROUND_UP(rreq->len, PAGE_SIZE);
	pgoff_t first = rreq->start / PAGE_SIZE;
	XA_STATE(xas, &rreq->mapping->i_pages, first);

	folio_batch_init(&fbatch);

	rcu_read_lock();

	xas_for_each(&xas, folio,  first + nr_pages - 1) {
		if (xas_retry(&xas, folio))
			continue;

		if (!folio_batch_add(&fbatch, folio))
			folio_batch_release(&fbatch);
	}

	rcu_read_unlock();
	folio_batch_release(&fbatch);
	trace_netfs_rreq(rreq, netfs_rreq_trace_ra_put_ref);
}

static void netfs_maybe_bulk_drop_ra_refs(struct netfs_io_request *rreq)
{
	if (test_and_clear_bit(NETFS_RREQ_NEED_PUT_RA_REFS, &rreq->flags))
		netfs_bulk_drop_ra_refs(rreq);
}

/*
 * Begin an operation, and fetch the stored zero point value from the cookie if
 * available.
 */
static int netfs_begin_cache_read(struct netfs_io_request *rreq, struct netfs_inode *ctx)
{
	return fscache_begin_read_operation(&rreq->cache_resources, netfs_i_cookie(ctx));
}

/*
 * Prepare the I/O buffer on a buffered read subrequest for the filesystem to
 * use as a bvec queue.
 */
static int netfs_prepare_buffered_read_buffer(struct netfs_io_subrequest *subreq,
					      unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	ssize_t extracted;

	_enter("R=%08x[%x] l=%zx s=%u",
	       rreq->debug_id, subreq->debug_index, subreq->len, max_segs);

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);
	bvecq_pos_set(&subreq->content, &subreq->dispatch_pos);
	extracted = bvecq_slice(&stream->dispatch_cursor, subreq->len,
				max_segs, &subreq->nr_segs);

	stream->buffered -= extracted;
	if (extracted < subreq->len) {
		subreq->len = extracted;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	return 0;
}

/**
 * netfs_prepare_read_buffer - Get the buffer for a subrequest
 * @subreq: The subrequest to get the buffer for
 * @max_segs: Maximum number of segments in buffer (or INT_MAX)
 *
 * Extract a slice of buffer from the stream and attach it to the subrequest as
 * a bio_vec queue.  The maximum amount of data attached is set by
 * @subreq->len, but this may be shortened if @max_segs would be exceeded.
 *
 * [!] NOTE: This must be run in the same thread as ->issue_read() was called
 * in as we access the readahead_control struct if there is one.
 */
int netfs_prepare_read_buffer(struct netfs_io_subrequest *subreq,
			      unsigned int max_segs)
{
	switch (subreq->rreq->origin) {
	case NETFS_READAHEAD:
	case NETFS_READPAGE:
	case NETFS_READ_FOR_WRITE:
		if (subreq->retry_count)
			return netfs_prepare_buffered_read_retry_buffer(subreq, max_segs);
		return netfs_prepare_buffered_read_buffer(subreq, max_segs);

	case NETFS_UNBUFFERED_READ:
	case NETFS_DIO_READ:
	case NETFS_READ_GAPS:
		return netfs_prepare_unbuffered_read_buffer(subreq, max_segs);
	case NETFS_READ_SINGLE:
		return netfs_prepare_read_single_buffer(subreq, max_segs);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}
EXPORT_SYMBOL(netfs_prepare_read_buffer);

int netfs_read_query_cache(struct netfs_io_request *rreq, struct fscache_occupancy *occ)
{
	struct netfs_cache_resources *cres = &rreq->cache_resources;

	occ->granularity = PAGE_SIZE;
	if (occ->query_from >= occ->query_to)
		return 0;
	if (!cres->ops)
		return 0;
	occ->query_from = round_up(occ->query_from, occ->granularity);
	return cres->ops->query_occupancy(cres, occ);
}

/**
 * netfs_mark_read_submission - Mark a read subrequest as being ready for submission
 * @subreq: The subrequest to be marked
 *
 * Calling this marks a read subrequest as being ready for submission and makes
 * it available to the collection thread.  After calling this, the filesystem's
 * ->issue_read() method must invoke netfs_read_subreq_terminated() to end the
 * subrequest and must return -EIOCBQUEUED.
 */
void netfs_mark_read_submission(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct netfs_io_stream *stream = &rreq->io_streams[0];

	_enter("R=%08x[%x]", rreq->debug_id, subreq->debug_index);

	__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);

	/* We add to the end of the list whilst the collector may be walking
	 * the list.  The collector only goes nextwards and uses the lock to
	 * remove entries off of the front.
	 */
	spin_lock(&rreq->lock);
	if (list_empty(&subreq->rreq_link)) {
		list_add_tail(&subreq->rreq_link, &stream->subrequests);
		if (list_is_first(&subreq->rreq_link, &stream->subrequests)) {
			if (!stream->active) {
				stream->collected_to = subreq->start;
				/* Store list pointers before active flag */
				smp_store_release(&stream->active, true);
			}
		}
	}

	rreq->submitted += subreq->len;
	stream->issue_from = subreq->start + subreq->len;
	if (!stream->buffered) {
		smp_wmb(); /* Write lists before ALL_QUEUED. */
		set_bit(NETFS_RREQ_ALL_QUEUED, &rreq->flags);
		trace_netfs_rreq(rreq, netfs_rreq_trace_all_queued);
	}

	spin_unlock(&rreq->lock);

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
}
EXPORT_SYMBOL(netfs_mark_read_submission);

static int netfs_issue_read(struct netfs_io_request *rreq,
			    struct netfs_io_subrequest *subreq)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];

	_enter("R=%08x[%x]", rreq->debug_id, subreq->debug_index);

	switch (subreq->source) {
	case NETFS_DOWNLOAD_FROM_SERVER:
		return rreq->netfs_ops->issue_read(subreq);
	case NETFS_READ_FROM_CACHE: {
		struct netfs_cache_resources *cres = &rreq->cache_resources;

		netfs_stat(&netfs_n_rh_read);
		cres->ops->issue_read(subreq);
		return -EIOCBQUEUED;
	}
	default:
		stream->issue_from = subreq->start + subreq->len;
		stream->buffered = 0;
		netfs_mark_read_submission(subreq);
		bvecq_zero(&stream->dispatch_cursor, subreq->len);
		subreq->transferred = subreq->len;
		subreq->error = 0;
		netfs_read_subreq_terminated(subreq);
		return 0;
	}
}

/*
 * Perform a read to the pagecache from a series of sources of different types,
 * slicing up the region to be read according to available cache blocks and
 * network rsize.
 */
static void netfs_read_to_pagecache(struct netfs_io_request *rreq)
{
	struct fscache_occupancy _occ = {
		.query_from	= rreq->start,
		.query_to	= rreq->start + rreq->len,
		.cached_from[0]	= 0,
		.cached_to[0]	= 0,
		.cached_from[1]	= ULLONG_MAX,
		.cached_to[1]	= ULLONG_MAX,
	};
	struct fscache_occupancy *occ = &_occ;
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	struct netfs_inode *ictx = netfs_inode(rreq->inode);
	int ret = 0;

	_enter("R=%08x", rreq->debug_id);

	bvecq_pos_set(&stream->dispatch_cursor, &rreq->load_cursor);
	bvecq_pos_set(&rreq->collect_cursor, &rreq->load_cursor);

	do {
		struct netfs_io_subrequest *subreq;
		unsigned long long hole_to, cache_to, stop;

		/* If we don't have any, find out the next couple of data
		 * extents from the cache, containing of following the
		 * specified start offset.  Holes have to be fetched from the
		 * server; data regions from the cache.
		 */
		hole_to = occ->cached_from[0];
		cache_to = occ->cached_to[0];
		if (stream->issue_from >= cache_to) {
			/* Extent exhausted; shuffle down. */
			int i;

			for (i = 0; i < ARRAY_SIZE(occ->cached_from) - 1; i++) {
				occ->cached_from[i] = occ->cached_from[i + 1];
				occ->cached_to[i]   = occ->cached_to[i + 1];
				occ->cached_type[i] = occ->cached_type[i + 1];
			}
			occ->cached_from[i] = ULLONG_MAX;
			occ->cached_to[i]   = ULLONG_MAX;

			if (occ->cached_from[0] != ULLONG_MAX)
				continue;

			/* Get new extents */
			ret = netfs_read_query_cache(rreq, occ);
			if (ret < 0)
				break;
			continue;
		}

		subreq = netfs_alloc_subrequest(rreq);
		if (!subreq) {
			ret = -ENOMEM;
			break;
		}

		subreq->start = stream->issue_from;
		stop = stream->issue_from + stream->buffered;

		_debug("rsub %llx %llx-%llx", subreq->start, hole_to, cache_to);

		if (stream->issue_from >= hole_to && stream->issue_from < cache_to) {
			/* Overlap with a cached region, where the cache may
			 * record a block of zeroes.
			 */
			_debug("cached s=%llx c=%llx l=%zx",
			       stream->issue_from, cache_to, stream->buffered);
			subreq->len = umin(cache_to - stream->issue_from, stream->buffered);
			subreq->len = round_up(subreq->len, occ->granularity);
			if (occ->cached_type[0] == FSCACHE_EXTENT_ZERO) {
				subreq->source = NETFS_FILL_WITH_ZEROES;
				netfs_stat(&netfs_n_rh_zero);
			} else {
				subreq->source = NETFS_READ_FROM_CACHE;
			}
		} else if ((subreq->start >= ictx->zero_point ||
			    subreq->start >= rreq->i_size) &&
			   subreq->start < stop) {
			/* If this range lies beyond the zero-point, that part
			 * can just be cleared locally.
			 */
			_debug("zero %llx-%llx", subreq->start, stop);
			subreq->len = stream->buffered;
			subreq->source = NETFS_FILL_WITH_ZEROES;
			if (rreq->cache_resources.ops)
				__set_bit(NETFS_SREQ_COPY_TO_CACHE, &subreq->flags);
			netfs_stat(&netfs_n_rh_zero);
		} else {
			/* Read a cache hole from the server.  If any part of
			 * this range lies beyond the zero-point or the EOF,
			 * that part can just be cleared locally.
			 */
			unsigned long long zlimit = umin(rreq->i_size, ictx->zero_point);
			unsigned long long limit = min3(zlimit, stop, hole_to);

			_debug("limit %llx %llx", rreq->i_size, ictx->zero_point);
			_debug("download %llx-%llx", subreq->start, stop);
			subreq->len = umin(limit - subreq->start, ULONG_MAX);
			subreq->source = NETFS_DOWNLOAD_FROM_SERVER;
			if (rreq->cache_resources.ops)
				__set_bit(NETFS_SREQ_COPY_TO_CACHE, &subreq->flags);
			netfs_stat(&netfs_n_rh_download);
		}

		if (subreq->len == 0) {
			pr_err("ZERO-LEN READ: R=%08x[%x] l=%zx/%zx s=%llx z=%llx i=%llx",
			       rreq->debug_id, subreq->debug_index,
			       subreq->len, stream->buffered,
			       subreq->start, ictx->zero_point, rreq->i_size);
			trace_netfs_sreq(subreq, netfs_sreq_trace_cancel);
			/* Not queued - release both refs. */
			netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
			netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
			break;
		}

		ret = netfs_issue_read(rreq, subreq);
		if (ret != 0 && ret != -EIOCBQUEUED) {
			subreq->error = ret;
			trace_netfs_sreq(subreq, netfs_sreq_trace_cancel);
			/* Not queued - release both refs. */
			netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
			netfs_put_subrequest(subreq, netfs_sreq_trace_put_cancel);
			break;
		}
		ret = 0;

		cond_resched();
	} while (stream->buffered > 0);

	if (unlikely(stream->buffered > 0)) {
		smp_wmb(); /* Write lists before ALL_QUEUED. */
		set_bit(NETFS_RREQ_ALL_QUEUED, &rreq->flags);
		netfs_wake_collector(rreq);
	}

	/* Defer error return as we may need to wait for outstanding I/O. */
	cmpxchg(&rreq->error, 0, ret);

	bvecq_pos_unset(&rreq->load_cursor);
	bvecq_pos_unset(&stream->dispatch_cursor);
}

/**
 * netfs_readahead - Helper to manage a read request
 * @ractl: The description of the readahead request
 *
 * Fulfil a readahead request by drawing data from the cache if possible, or
 * the netfs if not.  Space beyond the EOF is zero-filled.  Multiple I/O
 * requests from different sources will get munged together.  If necessary, the
 * readahead window can be expanded in either direction to a more convenient
 * alighment for RPC efficiency or to make storage in the cache feasible.
 *
 * The calling netfs must initialise a netfs context contiguous to the vfs
 * inode before calling this.
 *
 * This is usable whether or not caching is enabled.
 */
void netfs_readahead(struct readahead_control *ractl)
{
	struct netfs_io_request *rreq;
	struct netfs_io_stream *stream;
	struct netfs_inode *ictx = netfs_inode(ractl->mapping->host);
	unsigned long long start = readahead_pos(ractl);
	ssize_t added;
	size_t size = readahead_length(ractl);
	int ret;

	_enter("");

	rreq = netfs_alloc_request(ractl->mapping, ractl->file, start, size,
				   NETFS_READAHEAD);
	if (IS_ERR(rreq))
		return;

	stream = &rreq->io_streams[0];

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &rreq->flags);

	ret = netfs_begin_cache_read(rreq, ictx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto cleanup_free;

	netfs_stat(&netfs_n_rh_readahead);
	trace_netfs_read(rreq, readahead_pos(ractl), readahead_length(ractl),
			 netfs_read_trace_readahead);

	netfs_rreq_expand(rreq, ractl);

	/* Load the folios to be read into a bvecq chain.  Note that this
	 * acquires a ref on each folio that we will need to release later -
	 * but we don't want to do that until after we've started the I/O.
	 */
	added = bvecq_load_from_ra(&rreq->load_cursor, ractl);
	if (added < 0) {
		ret = added;
		goto cleanup_free;
	}
	__set_bit(NETFS_RREQ_NEED_PUT_RA_REFS, &rreq->flags);

	rreq->submitted = rreq->start + added;
	rreq->cleaned_to = rreq->start;
	rreq->front_folio_order = get_order(rreq->load_cursor.bvecq->bv[0].bv_len);
	stream->issue_from = rreq->start;
	stream->buffered = added;

	netfs_read_to_pagecache(rreq);
	netfs_maybe_bulk_drop_ra_refs(rreq);
	return netfs_put_request(rreq, netfs_rreq_trace_put_return);

cleanup_free:
	return netfs_put_failed_request(rreq);
}
EXPORT_SYMBOL(netfs_readahead);

/*
 * Create a buffer queue with a single occupying folio.
 */
static int netfs_create_singular_buffer(struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	struct bvecq *bq;
	size_t fsize = folio_size(folio);

	if (bvecq_buffer_init(&rreq->load_cursor, GFP_KERNEL) < 0)
		return -ENOMEM;

	bq = rreq->load_cursor.bvecq;
	bvec_set_folio(&bq->bv[bq->nr_slots++], folio, fsize, 0);
	rreq->submitted = rreq->start + fsize;
	stream->issue_from = rreq->start;
	stream->buffered = fsize;
	return 0;
}

/*
 * Read into gaps in a folio partially filled by a streaming write.
 */
static int netfs_read_gaps(struct file *file, struct folio *folio)
{
	struct netfs_io_request *rreq;
	struct netfs_io_stream *stream;
	struct address_space *mapping = folio->mapping;
	struct netfs_folio *finfo = netfs_folio_info(folio);
	struct netfs_inode *ctx = netfs_inode(mapping->host);
	struct bvecq *bq = NULL;
	struct page *sink = NULL;
	unsigned int from = finfo->dirty_offset;
	unsigned int to = from + finfo->dirty_len;
	unsigned int off = 0;
	size_t flen = folio_size(folio);
	size_t nr_bvec = flen / PAGE_SIZE + 2;
	size_t part;
	int ret;

	_enter("%lx", folio->index);

	rreq = netfs_alloc_request(mapping, file, folio_pos(folio), flen, NETFS_READ_GAPS);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto alloc_error;
	}
	stream = &rreq->io_streams[0];

	ret = netfs_begin_cache_read(rreq, ctx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto discard;

	netfs_stat(&netfs_n_rh_read_folio);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_read_gaps);

	/* Fiddle the buffer so that a gap at the beginning and/or a gap at the
	 * end get copied to, but the middle is discarded.
	 */
	ret = -ENOMEM;
	bq = bvecq_alloc_one(nr_bvec, GFP_KERNEL);
	if (!bq)
		goto discard;
	rreq->load_cursor.bvecq = bq;

	sink = alloc_page(GFP_KERNEL);
	if (!sink)
		goto discard;

	trace_netfs_folio(folio, netfs_folio_trace_read_gaps);

	for (struct bvecq *p = bq; p; p = p->next)
		p->free = true;

	if (from > 0) {
		folio_get(folio);
		bvec_set_folio(&bq->bv[bq->nr_slots++], folio, from, 0);
		off = from;
	}
	while (off < to) {
		if (bvecq_is_full(bq))
			bq = bq->next;
		part = umin(to - off, PAGE_SIZE);
		get_page(sink);
		bvec_set_page(&bq->bv[bq->nr_slots++], sink, part, 0);
		off += part;
	}
	if (to < flen) {
		if (bvecq_is_full(bq))
			bq = bq->next;
		folio_get(folio);
		bvec_set_folio(&bq->bv[bq->nr_slots++], folio, flen - to, to);
	}

	rreq->submitted = rreq->start + flen;
	stream->issue_from = rreq->start;
	stream->buffered = flen;

	netfs_read_to_pagecache(rreq);

	put_page(sink);

	ret = netfs_wait_for_read(rreq);
	if (ret >= 0) {
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}
	folio_unlock(folio);
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	return ret < 0 ? ret : 0;

discard:
	if (sink)
		put_page(sink);
	netfs_put_failed_request(rreq);
alloc_error:
	folio_unlock(folio);
	return ret;
}

/**
 * netfs_read_folio - Helper to manage a read_folio request
 * @file: The file to read from
 * @folio: The folio to read
 *
 * Fulfil a read_folio request by drawing data from the cache if
 * possible, or the netfs if not.  Space beyond the EOF is zero-filled.
 * Multiple I/O requests from different sources will get munged together.
 *
 * The calling netfs must initialise a netfs context contiguous to the vfs
 * inode before calling this.
 *
 * This is usable whether or not caching is enabled.
 */
int netfs_read_folio(struct file *file, struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	struct netfs_io_request *rreq;
	struct netfs_inode *ctx = netfs_inode(mapping->host);
	int ret;

	if (folio_test_dirty(folio)) {
		trace_netfs_folio(folio, netfs_folio_trace_read_gaps);
		return netfs_read_gaps(file, folio);
	}

	_enter("%lx", folio->index);

	rreq = netfs_alloc_request(mapping, file,
				   folio_pos(folio), folio_size(folio),
				   NETFS_READPAGE);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto alloc_error;
	}

	ret = netfs_begin_cache_read(rreq, ctx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto discard;

	netfs_stat(&netfs_n_rh_read_folio);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_readpage);

	/* Set up the output buffer */
	ret = netfs_create_singular_buffer(rreq, folio);
	if (ret < 0)
		goto discard;

	netfs_read_to_pagecache(rreq);

	ret = netfs_wait_for_read(rreq);
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	return ret < 0 ? ret : 0;

discard:
	netfs_put_failed_request(rreq);
alloc_error:
	folio_unlock(folio);
	return ret;
}
EXPORT_SYMBOL(netfs_read_folio);

/*
 * Prepare a folio for writing without reading first
 * @folio: The folio being prepared
 * @pos: starting position for the write
 * @len: length of write
 * @always_fill: T if the folio should always be completely filled/cleared
 *
 * In some cases, write_begin doesn't need to read at all:
 * - full folio write
 * - write that lies in a folio that is completely beyond EOF
 * - write that covers the folio from start to EOF or beyond it
 *
 * If any of these criteria are met, then zero out the unwritten parts
 * of the folio and return true. Otherwise, return false.
 */
static bool netfs_skip_folio_read(struct folio *folio, loff_t pos, size_t len,
				 bool always_fill)
{
	struct inode *inode = folio_inode(folio);
	loff_t i_size = i_size_read(inode);
	size_t offset = offset_in_folio(folio, pos);
	size_t plen = folio_size(folio);

	if (unlikely(always_fill)) {
		if (pos - offset + len <= i_size)
			return false; /* Page entirely before EOF */
		folio_zero_segment(folio, 0, plen);
		folio_mark_uptodate(folio);
		return true;
	}

	/* Full folio write */
	if (offset == 0 && len >= plen)
		return true;

	/* Page entirely beyond the end of the file */
	if (pos - offset >= i_size)
		goto zero_out;

	/* Write that covers from the start of the folio to EOF or beyond */
	if (offset == 0 && (pos + len) >= i_size)
		goto zero_out;

	return false;
zero_out:
	folio_zero_segments(folio, 0, offset, offset + len, plen);
	return true;
}

/**
 * netfs_write_begin - Helper to prepare for writing [DEPRECATED]
 * @ctx: The netfs context
 * @file: The file to read from
 * @mapping: The mapping to read from
 * @pos: File position at which the write will begin
 * @len: The length of the write (may extend beyond the end of the folio chosen)
 * @_folio: Where to put the resultant folio
 * @_fsdata: Place for the netfs to store a cookie
 *
 * Pre-read data for a write-begin request by drawing data from the cache if
 * possible, or the netfs if not.  Space beyond the EOF is zero-filled.
 * Multiple I/O requests from different sources will get munged together.
 *
 * The calling netfs must provide a table of operations, only one of which,
 * issue_read, is mandatory.
 *
 * The check_write_begin() operation can be provided to check for and flush
 * conflicting writes once the folio is grabbed and locked.  It is passed a
 * pointer to the fsdata cookie that gets returned to the VM to be passed to
 * write_end.  It is permitted to sleep.  It should return 0 if the request
 * should go ahead or it may return an error.  It may also unlock and put the
 * folio, provided it sets ``*foliop`` to NULL, in which case a return of 0
 * will cause the folio to be re-got and the process to be retried.
 *
 * The calling netfs must initialise a netfs context contiguous to the vfs
 * inode before calling this.
 *
 * This is usable whether or not caching is enabled.
 *
 * Note that this should be considered deprecated and netfs_perform_write()
 * used instead.
 */
int netfs_write_begin(struct netfs_inode *ctx,
		      struct file *file, struct address_space *mapping,
		      loff_t pos, unsigned int len, struct folio **_folio,
		      void **_fsdata)
{
	struct netfs_io_request *rreq;
	struct folio *folio;
	pgoff_t index = pos >> PAGE_SHIFT;
	int ret;

retry:
	folio = __filemap_get_folio(mapping, index, FGP_WRITEBEGIN,
				    mapping_gfp_mask(mapping));
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	if (ctx->ops->check_write_begin) {
		/* Allow the netfs (eg. ceph) to flush conflicts. */
		ret = ctx->ops->check_write_begin(file, pos, len, &folio, _fsdata);
		if (ret < 0) {
			trace_netfs_failure(NULL, NULL, ret, netfs_fail_check_write_begin);
			goto error;
		}
		if (!folio)
			goto retry;
	}

	if (folio_test_uptodate(folio))
		goto have_folio;

	/* If the folio is beyond the EOF, we want to clear it - unless it's
	 * within the cache granule containing the EOF, in which case we need
	 * to preload the granule.
	 */
	if (!netfs_is_cache_enabled(ctx) &&
	    netfs_skip_folio_read(folio, pos, len, false)) {
		netfs_stat(&netfs_n_rh_write_zskip);
		goto have_folio_no_wait;
	}

	rreq = netfs_alloc_request(mapping, file,
				   folio_pos(folio), folio_size(folio),
				   NETFS_READ_FOR_WRITE);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto error;
	}
	rreq->no_unlock_folio	= folio->index;
	__set_bit(NETFS_RREQ_NO_UNLOCK_FOLIO, &rreq->flags);

	ret = netfs_begin_cache_read(rreq, ctx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto error_put;

	netfs_stat(&netfs_n_rh_write_begin);
	trace_netfs_read(rreq, pos, len, netfs_read_trace_write_begin);

	/* Set up the output buffer */
	ret = netfs_create_singular_buffer(rreq, folio);
	if (ret < 0)
		goto error_put;

	netfs_read_to_pagecache(rreq);
	ret = netfs_wait_for_read(rreq);
	if (ret < 0)
		goto error;
	netfs_put_request(rreq, netfs_rreq_trace_put_return);

have_folio:
	ret = folio_wait_private_2_killable(folio);
	if (ret < 0)
		goto error;
have_folio_no_wait:
	*_folio = folio;
	_leave(" = 0");
	return 0;

error_put:
	netfs_put_failed_request(rreq);
error:
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(netfs_write_begin);

/*
 * Preload the data into a folio we're proposing to write into.
 */
int netfs_prefetch_for_write(struct file *file, struct folio *folio,
			     size_t offset, size_t len)
{
	struct netfs_io_request *rreq;
	struct address_space *mapping = folio->mapping;
	struct netfs_inode *ctx = netfs_inode(mapping->host);
	unsigned long long start = folio_pos(folio);
	size_t flen = folio_size(folio);
	int ret;

	_enter("%zx @%llx", flen, start);

	ret = -ENOMEM;

	rreq = netfs_alloc_request(mapping, file, start, flen,
				   NETFS_READ_FOR_WRITE);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto error;
	}

	rreq->no_unlock_folio = folio->index;
	__set_bit(NETFS_RREQ_NO_UNLOCK_FOLIO, &rreq->flags);
	ret = netfs_begin_cache_read(rreq, ctx);
	if (ret == -ENOMEM || ret == -EINTR || ret == -ERESTARTSYS)
		goto error_put;

	netfs_stat(&netfs_n_rh_write_begin);
	trace_netfs_read(rreq, start, flen, netfs_read_trace_prefetch_for_write);

	/* Set up the output buffer */
	ret = netfs_create_singular_buffer(rreq, folio);
	if (ret < 0)
		goto error_put;
	rreq->load_cursor.bvecq->free = true;

	netfs_read_to_pagecache(rreq);
	ret = netfs_wait_for_read(rreq);
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	return ret < 0 ? ret : 0;

error_put:
	netfs_put_failed_request(rreq);
error:
	_leave(" = %d", ret);
	return ret;
}

/**
 * netfs_buffered_read_iter - Filesystem buffered I/O read routine
 * @iocb: kernel I/O control block
 * @iter: destination for the data read
 *
 * This is the ->read_iter() routine for all filesystems that can use the page
 * cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall be
 * returned when no data can be read without waiting for I/O requests to
 * complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O requests
 * shall be made for the read or for readahead.  When no data can be read,
 * -EAGAIN shall be returned.  When readahead would be triggered, a partial,
 * possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
ssize_t netfs_buffered_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct netfs_inode *ictx = netfs_inode(inode);
	ssize_t ret;

	if (WARN_ON_ONCE((iocb->ki_flags & IOCB_DIRECT) ||
			 test_bit(NETFS_ICTX_UNBUFFERED, &ictx->flags)))
		return -EINVAL;

	ret = netfs_start_io_read(inode);
	if (ret == 0) {
		ret = filemap_read(iocb, iter, 0);
		netfs_end_io_read(inode);
	}
	return ret;
}
EXPORT_SYMBOL(netfs_buffered_read_iter);

/**
 * netfs_file_read_iter - Generic filesystem read routine
 * @iocb: kernel I/O control block
 * @iter: destination for the data read
 *
 * This is the ->read_iter() routine for all filesystems that can use the page
 * cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall be
 * returned when no data can be read without waiting for I/O requests to
 * complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O requests
 * shall be made for the read or for readahead.  When no data can be read,
 * -EAGAIN shall be returned.  When readahead would be triggered, a partial,
 * possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
ssize_t netfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_inode *ictx = netfs_inode(iocb->ki_filp->f_mapping->host);

	if ((iocb->ki_flags & IOCB_DIRECT) ||
	    test_bit(NETFS_ICTX_UNBUFFERED, &ictx->flags))
		return netfs_unbuffered_read_iter(iocb, iter);

	return netfs_buffered_read_iter(iocb, iter);
}
EXPORT_SYMBOL(netfs_file_read_iter);

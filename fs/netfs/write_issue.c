// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level (buffered) writeback.
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 *
 * To support network filesystems with local caching, we manage a situation
 * that can be envisioned like the following:
 *
 *               +---+---+-----+-----+---+----------+
 *    Folios:    |   |   |     |     |   |          |
 *               +---+---+-----+-----+---+----------+
 *
 *                 +------+------+     +----+----+
 *    Upload:      |      |      |.....|    |    |
 *  (Stream 0)     +------+------+     +----+----+
 *
 *               +------+------+------+------+------+
 *    Cache:     |      |      |      |      |      |
 *  (Stream 1)   +------+------+------+------+------+
 *
 * Where we have a sequence of folios of varying sizes that we need to overlay
 * with multiple parallel streams of I/O requests, where the I/O requests in a
 * stream may also be of various sizes (in cifs, for example, the sizes are
 * negotiated with the server; in something like ceph, they may represent the
 * sizes of storage objects).
 *
 * The sequence in each stream may contain gaps and noncontiguous subrequests
 * may be glued together into single vectored write RPCs.
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include "internal.h"

#define NOTE_UPLOAD_AVAIL	0x001	/* Upload is available */
#define NOTE_CACHE_AVAIL	0x002	/* Local cache is available */
#define NOTE_CACHE_COPY		0x004	/* Copy folio to cache */
#define NOTE_UPLOAD		0x008	/* Upload folio to server */
#define NOTE_UPLOAD_STARTED	0x010	/* Upload started */
#define NOTE_STREAMW		0x020	/* Folio is from a streaming write */
#define NOTE_DISCONTIG_BEFORE	0x040	/* Folio discontiguous with the previous folio */
#define NOTE_DISCONTIG_AFTER	0x080	/* Folio discontiguous with the next folio */
#define NOTE_TO_EOF		0x100	/* Data in folio ends at EOF */
#define NOTE_FLUSH_ANYWAY	0x200	/* Flush data, even if not hit estimated limit */

#define NOTES__KEEP_MASK (NOTE_UPLOAD_AVAIL | NOTE_CACHE_AVAIL | NOTE_UPLOAD_STARTED)

struct netfs_wb_params {
	unsigned long long	last_end;	/* End file pos of previous folio */
	unsigned long long	folio_start;	/* File pos of folio */
	unsigned int		folio_len;	/* Length of folio */
	unsigned int		dirty_offset;	/* Offset of dirty region in folio */
	unsigned int		dirty_len;	/* Length of dirty region in folio */
	unsigned int		notes;		/* Notes on applicability */
	struct bvecq_pos	dispatch_cursor; /* Folio queue anchor for issue_at */
	struct netfs_write_estimate estimates[2];
};

struct netfs_writethrough {
	struct netfs_wb_params	params;
	struct netfs_io_request	*wreq;
	struct folio		*in_progress;
};

static int netfs_prepare_write_single_buffer(struct netfs_io_subrequest *subreq,
					     unsigned int max_segs);

/*
 * Kill all dirty folios in the event of an unrecoverable error, starting with
 * a locked folio we've already obtained from writeback_iter().
 */
static void netfs_kill_dirty_pages(struct address_space *mapping,
				   struct writeback_control *wbc,
				   struct folio *folio)
{
	int error = 0;

	do {
		enum netfs_folio_trace why = netfs_folio_trace_kill;
		struct netfs_group *group = NULL;
		struct netfs_folio *finfo = NULL;
		void *priv;

		priv = folio_detach_private(folio);
		if (priv) {
			finfo = __netfs_folio_info(priv);
			if (finfo) {
				/* Kill folio from streaming write. */
				group = finfo->netfs_group;
				why = netfs_folio_trace_kill_s;
			} else {
				group = priv;
				if (group == NETFS_FOLIO_COPY_TO_CACHE) {
					/* Kill copy-to-cache folio */
					why = netfs_folio_trace_kill_cc;
					group = NULL;
				} else {
					/* Kill folio with group */
					why = netfs_folio_trace_kill_g;
				}
			}
		}

		trace_netfs_folio(folio, why);

		folio_start_writeback(folio);
		folio_unlock(folio);
		folio_end_writeback(folio);

		netfs_put_group(group);
		kfree(finfo);

	} while ((folio = writeback_iter(mapping, wbc, folio, &error)));
}

/*
 * Create a write request and set it up appropriately for the origin type.
 */
struct netfs_io_request *netfs_create_write_req(struct address_space *mapping,
						struct file *file,
						loff_t start,
						enum netfs_io_origin origin)
{
	struct netfs_io_request *wreq;
	struct netfs_inode *ictx;
	bool is_cacheable = (origin == NETFS_WRITEBACK ||
			     origin == NETFS_WRITEBACK_SINGLE ||
			     origin == NETFS_WRITETHROUGH ||
			     origin == NETFS_PGPRIV2_COPY_TO_CACHE);

	wreq = netfs_alloc_request(mapping, file, start, 0, origin);
	if (IS_ERR(wreq))
		return wreq;

	_enter("R=%x", wreq->debug_id);

	ictx = netfs_inode(wreq->inode);
	if (is_cacheable && netfs_is_cache_enabled(ictx))
		fscache_begin_write_operation(&wreq->cache_resources, netfs_i_cookie(ictx));

	wreq->cleaned_to = wreq->start;
	if (wreq->cache_resources.dio_size > 1)
		wreq->cache_coll_to = round_down(wreq->start, wreq->cache_resources.dio_size);

	wreq->io_streams[0].stream_nr		= 0;
	wreq->io_streams[0].source		= NETFS_UPLOAD_TO_SERVER;
	wreq->io_streams[0].applicable		= NOTE_UPLOAD;
	wreq->io_streams[0].estimate_write	= ictx->ops->estimate_write;
	wreq->io_streams[0].issue_write		= ictx->ops->issue_write;
	wreq->io_streams[0].collected_to	= start;
	wreq->io_streams[0].transferred		= 0;

	wreq->io_streams[1].stream_nr		= 1;
	wreq->io_streams[1].source		= NETFS_WRITE_TO_CACHE;
	wreq->io_streams[1].applicable		= NOTE_CACHE_COPY;
	wreq->io_streams[1].collected_to	= start;
	wreq->io_streams[1].transferred		= 0;
	if (fscache_resources_valid(&wreq->cache_resources)) {
		wreq->io_streams[1].avail	= true;
		wreq->io_streams[1].active	= true;
		wreq->io_streams[1].estimate_write = wreq->cache_resources.ops->estimate_write;
		wreq->io_streams[1].issue_write = wreq->cache_resources.ops->issue_write;
	}

	return wreq;
}

/*
 * Allocate and prepare a write subrequest.
 */
struct netfs_io_subrequest *netfs_alloc_write_subreq(struct netfs_io_request *wreq,
						     struct netfs_io_stream *stream)
{
	struct netfs_io_subrequest *subreq;

	subreq = netfs_alloc_subrequest(wreq);
	subreq->source		= stream->source;
	subreq->start		= stream->issue_from;
	subreq->len		= stream->buffered;
	subreq->stream_nr	= stream->stream_nr;

	_enter("R=%x[%x]", wreq->debug_id, subreq->debug_index);

	trace_netfs_sreq(subreq, netfs_sreq_trace_prepare);

	switch (stream->source) {
	case NETFS_UPLOAD_TO_SERVER:
		netfs_stat(&netfs_n_wh_upload);
		break;
	case NETFS_WRITE_TO_CACHE:
		netfs_stat(&netfs_n_wh_write);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);

	/* We add to the end of the list whilst the collector may be walking
	 * the list.  The collector only goes nextwards and uses the lock to
	 * remove entries off of the front.
	 */
	spin_lock(&wreq->lock);
	list_add_tail(&subreq->rreq_link, &stream->subrequests);
	if (list_is_first(&subreq->rreq_link, &stream->subrequests) &&
	    stream->collected_to == 0)
		stream->collected_to = subreq->start;

	spin_unlock(&wreq->lock);
	return subreq;
}

/*
 * Prepare the buffer for a buffered write.
 */
static int netfs_prepare_buffered_write_buffer(struct netfs_io_subrequest *subreq,
					       unsigned int max_segs)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	ssize_t len;

	_enter("%zx,{,%u,%u},%u",
	       subreq->len, stream->dispatch_cursor.slot, stream->dispatch_cursor.offset, max_segs);

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);

	/* If we have a write to the cache, we need to round out the first and
	 * last entries (only those as the data will be on virtually contiguous
	 * folios) to cache DIO boundaries.
	 */
	if (subreq->source == NETFS_WRITE_TO_CACHE) {
		struct bio_vec *bv;
		struct bvecq *bq;
		size_t dio_size = wreq->cache_resources.dio_size;
		size_t disp, dlen;

		len = bvecq_extract(&stream->dispatch_cursor, subreq->len, max_segs,
				    &subreq->content.bvecq);
		if (len < 0)
			return -ENOMEM;

		_debug("extract %zx/%zx", len, subreq->len);
		subreq->len = len;

		/* Round the first entry down. */
		bq = subreq->content.bvecq;
		bv = &bq->bv[0];
		disp = bv->bv_offset & (dio_size - 1);
		if (disp) {
			bv->bv_offset -= disp;
			bv->bv_len += disp;
			bq->fpos -= disp;
			subreq->start -= disp;
			subreq->len += disp;
		}

		/* Round the end of the last entry up. */
		while (bq->next)
			bq = bq->next;
		bv = &bq->bv[bq->nr_slots - 1];
		dlen = round_up(bv->bv_len, dio_size);
		if (dlen > bv->bv_len) {
			subreq->len += dlen - bv->bv_len;
			bv->bv_len = dlen;
		}
	} else {
		bvecq_pos_set(&subreq->content, &stream->dispatch_cursor);
		len = bvecq_slice(&stream->dispatch_cursor, subreq->len, max_segs,
				  &subreq->nr_segs);

		if (len < subreq->len) {
			subreq->len = len;
			trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
		}
	}

	stream->issue_from += len;
	stream->buffered   -= len;
	if (stream->buffered == 0) {
		stream->buffering = false;
		bvecq_pos_unset(&stream->dispatch_cursor);
	}
	/* Order loading the queue before updating the issue_to point */
	atomic64_set_release(&stream->issued_to, stream->issue_from);
	return 0;
}

/**
 * netfs_prepare_write_buffer - Get the buffer for a subrequest
 * @subreq: The subrequest to get the buffer for
 * @max_segs: Maximum number of segments in buffer (or INT_MAX)
 *
 * Extract a slice of buffer from the stream and attach it to the subrequest as
 * a bio_vec queue.  The maximum amount of data attached is set by
 * @subreq->len, but this may be shortened if @max_segs would be exceeded.
 */
int netfs_prepare_write_buffer(struct netfs_io_subrequest *subreq,
			       unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;

	switch (rreq->origin) {
	case NETFS_WRITEBACK:
	case NETFS_WRITETHROUGH:
		if (test_bit(NETFS_RREQ_RETRYING, &rreq->flags))
			return netfs_prepare_write_retry_buffer(subreq, max_segs);
		return netfs_prepare_buffered_write_buffer(subreq, max_segs);

	case NETFS_UNBUFFERED_WRITE:
	case NETFS_DIO_WRITE:
		return netfs_prepare_unbuffered_write_buffer(subreq, max_segs);

	case NETFS_WRITEBACK_SINGLE:
		return netfs_prepare_write_single_buffer(subreq, max_segs);

	case NETFS_PGPRIV2_COPY_TO_CACHE:
		return netfs_prepare_pgpriv2_write_buffer(subreq, max_segs);

	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}
EXPORT_SYMBOL(netfs_prepare_write_buffer);

/*
 * Issue writes for a stream.
 */
static int netfs_issue_writes(struct netfs_io_request *wreq,
			      struct netfs_io_stream *stream,
			      struct netfs_wb_params *params)
{
	struct netfs_write_estimate *estimate = &params->estimates[stream->stream_nr];

	for (;;) {
		struct netfs_io_subrequest *subreq;
		int ret;

		subreq = netfs_alloc_write_subreq(wreq, stream);
		if (!subreq)
			return -ENOMEM;

		ret = stream->issue_write(subreq);
		if (ret < 0 && ret != -EIOCBQUEUED)
			return ret;

		if (stream->buffered == 0) {
			if (stream->stream_nr == 0)
				params->notes &= ~NOTE_UPLOAD_STARTED;
			return 0;
		}

		if (!(params->notes & NOTE_FLUSH_ANYWAY)) {
			estimate->issue_at = ULLONG_MAX;
			estimate->max_segs = INT_MAX;
			stream->estimate_write(wreq, stream, estimate);
			if (stream->issue_from + stream->buffered < estimate->issue_at &&
			    estimate->max_segs > 0)
				return 0;
		}
	}
}

/*
 * Issue pending writes on a stream.
 */
static int netfs_issue_stream(struct netfs_io_request *wreq,
			      struct netfs_wb_params *params, int s)
{
	struct netfs_write_estimate *estimate = &params->estimates[s];
	struct netfs_io_stream *stream = &wreq->io_streams[s];
	unsigned long long dirty_start;
	bool discontig_before = params->notes & NOTE_DISCONTIG_BEFORE;
	int ret;

	_enter("%x", params->notes);

	/* If the current folio doesn't contribute to this stream, see if we
	 * need to flush it.
	 */
	if (!(params->notes & stream->applicable)) {
		if (!stream->buffering) {
			atomic64_set_release(&stream->issued_to,
					     params->folio_start + params->folio_len);
			return 0;
		}
		discontig_before = true;
	}

	/* Issue writes if we meet a discontiguity before the current folio.
	 * Even if the filesystem can do sparse/vectored writes, we still
	 * generate a subreq per contiguous region rather than generating
	 * separate extent lists.
	 */
	if (stream->buffering && discontig_before) {
		params->notes |= NOTE_FLUSH_ANYWAY;
		ret = netfs_issue_writes(wreq, stream, params);
		if (ret < 0)
			return ret;
		stream->buffering = false;
		params->notes &= ~NOTE_FLUSH_ANYWAY;
	}

	if (!(params->notes & stream->applicable)) {
		atomic64_set_release(&stream->issued_to,
				     params->folio_start + params->folio_len);
		return 0;
	}

	/* If we're not currently buffering on this stream, we need to get an
	 * estimate of when we need to issue a write.  It might be within the
	 * starting folio.
	 */
	dirty_start = params->folio_start + params->dirty_offset;
	if (!stream->buffering) {
		stream->buffering = true;
		stream->issue_from = dirty_start;
		bvecq_pos_set(&stream->dispatch_cursor, &params->dispatch_cursor);
		estimate->issue_at = ULLONG_MAX;
		estimate->max_segs = INT_MAX;
		stream->estimate_write(wreq, stream, estimate);
	}

	stream->buffered += params->dirty_len;
	estimate->max_segs--;

	/* Poke the filesystem to issue writes when we hit the limit it set or
	 * if the data ends before the end of the page.
	 */
	if (params->notes & NOTE_DISCONTIG_AFTER)
		params->notes |= NOTE_FLUSH_ANYWAY;
	_debug("[%u] %llx + %zx >= %llx, %u %x",
	       s, stream->issue_from, stream->buffered, estimate->issue_at,
	       estimate->max_segs, params->notes);
	if (stream->issue_from + stream->buffered >= estimate->issue_at ||
	    estimate->max_segs <= 0 ||
	    (params->notes & NOTE_FLUSH_ANYWAY)) {
		ret = netfs_issue_writes(wreq, stream, params);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * See which streams need writes issuing and issue them.
 */
static int netfs_issue_streams(struct netfs_io_request *wreq,
			       struct netfs_wb_params *params)
{
	int ret = 0, ret2;

	_enter("%x", params->notes);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		ret2 = netfs_issue_stream(wreq, params, s);
		if (ret2 < 0)
			ret = ret2;
	}
	return ret;
}

/*
 * End the issuing of writes, let the collector know we're done.
 */
static void netfs_end_issue_write(struct netfs_io_request *wreq,
				  struct netfs_wb_params *params)
{
	bool needs_poke = true;

	params->notes |= NOTE_FLUSH_ANYWAY;

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];
		int ret;

		if (stream->buffering) {
			ret = netfs_issue_writes(wreq, stream, params);
			if (ret < 0) {
				/* Leave the error somewhere the completion
				 * path can pick it up if there isn't already
				 * another error logged.
				 */
				cmpxchg(&wreq->error, 0, ret);
			}
			stream->buffering = false;
		}
	}

	smp_wmb(); /* Write subreq lists before ALL_QUEUED. */
	set_bit(NETFS_RREQ_ALL_QUEUED, &wreq->flags);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (!stream->active)
			continue;
		if (!list_empty(&stream->subrequests))
			needs_poke = false;
	}

	if (needs_poke)
		netfs_wake_collector(wreq);
}

/*
 * Queue a folio for writeback.
 */
static int netfs_queue_wb_folio(struct netfs_io_request *wreq,
				struct writeback_control *wbc,
				struct folio *folio,
				struct netfs_wb_params *params)
{
	struct netfs_group *fgroup; /* TODO: Use this with ceph */
	struct netfs_folio *finfo;
	struct bvecq *queue = wreq->load_cursor.bvecq;
	unsigned int slot;
	size_t fsize = folio_size(folio), flen = fsize, foff = 0;
	loff_t fpos = folio_pos(folio), i_size;
	int ret;

	_enter("%x", params->notes);

	/* Institute a new bvec queue segment if the current one is full or if
	 * we encounter a discontiguity.  The discontiguity break is important
	 * when it comes to bulk unlocking folios by file range.
	 */
	if (bvecq_is_full(queue) ||
	    (fpos != params->last_end && params->last_end > 0)) {
		ret = bvecq_buffer_make_space(&wreq->load_cursor, GFP_NOFS);
		if (ret < 0) {
			folio_unlock(folio);
			return ret;
		}

		queue = wreq->load_cursor.bvecq;
		queue->fpos = fpos;
		if (fpos != params->last_end)
			queue->discontig = true;
		bvecq_pos_move(&params->dispatch_cursor, queue);
		params->dispatch_cursor.slot = 0;
	}

	/* netfs_perform_write() may shift i_size around the page or from out
	 * of the page to beyond it, but cannot move i_size into or through the
	 * page since we have it locked.
	 */
	i_size = i_size_read(wreq->inode);

	if (fpos >= i_size) {
		/* mmap beyond eof. */
		_debug("beyond eof");
		folio_start_writeback(folio);
		folio_unlock(folio);
		wreq->nr_group_rel += netfs_folio_written_back(folio);
		netfs_put_group_many(wreq->group, wreq->nr_group_rel);
		wreq->nr_group_rel = 0;
		return 0;
	}

	if (fpos + fsize > wreq->i_size)
		wreq->i_size = i_size;

	fgroup = netfs_folio_group(folio);
	finfo = netfs_folio_info(folio);
	if (finfo) {
		foff = finfo->dirty_offset;
		flen = foff + finfo->dirty_len;
		params->notes |= NOTE_STREAMW;
		if (foff > 0)
			params->notes |= NOTE_DISCONTIG_BEFORE;
		if (flen < fsize)
			params->notes |= NOTE_DISCONTIG_AFTER;
	}

	if (params->last_end && fpos != params->last_end)
		params->notes |= NOTE_DISCONTIG_BEFORE;
	params->last_end = fpos + fsize;

	if (wreq->origin == NETFS_WRITETHROUGH) {
		if (flen > i_size - fpos)
			flen = i_size - fpos;
		/* EOF may be changing. */
	} else if (flen > i_size - fpos) {
		flen = i_size - fpos;
		if (!(params->notes & NOTE_STREAMW))
			folio_zero_segment(folio, flen, fsize);
		params->notes |= NOTE_TO_EOF;
	} else if (flen == i_size - fpos) {
		params->notes |= NOTE_TO_EOF;
	}
	flen -= foff;

	params->folio_start	= fpos;
	params->folio_len	= fsize;
	params->dirty_offset	= foff;
	params->dirty_len	= flen;

	_debug("folio %zx %zx %zx", foff, flen, fsize);

	/* Deal with discontinuities in the stream of dirty pages.  These can
	 * arise from a number of sources:
	 *
	 * (1) Intervening non-dirty pages from random-access writes, multiple
	 *     flushers writing back different parts simultaneously and manual
	 *     syncing.
	 *
	 * (2) Partially-written pages from write-streaming.
	 *
	 * (3) Pages that belong to a different write-back group (eg.  Ceph
	 *     snapshots).
	 *
	 * (4) Actually-clean pages that were marked for write to the cache
	 *     when they were read.  Note that these appear as a special
	 *     write-back group.
	 */
	if (fgroup == NETFS_FOLIO_COPY_TO_CACHE) {
		if (!(params->notes & NOTE_CACHE_AVAIL)) {
			trace_netfs_folio(folio, netfs_folio_trace_cancel_copy);
			goto cancel_folio;
		}
		params->notes |= NOTE_CACHE_COPY;
		trace_netfs_folio(folio, netfs_folio_trace_store_copy);
	} else if (fgroup != wreq->group) {
		/* We can't write this page to the server yet. */
		kdebug("wrong group");
		goto skip_folio;
	} else if (!(params->notes & (NOTE_UPLOAD_AVAIL | NOTE_CACHE_AVAIL))) {
		trace_netfs_folio(folio, netfs_folio_trace_cancel_store);
		goto cancel_folio_discard;
	} else {
		if (params->notes & NOTE_UPLOAD_STARTED) {
			params->notes |= NOTE_UPLOAD;
			trace_netfs_folio(folio, netfs_folio_trace_store_plus);
		} else {
			params->notes |= NOTE_UPLOAD | NOTE_UPLOAD_STARTED;
			trace_netfs_folio(folio, netfs_folio_trace_store);
		}
		if (params->notes & NOTE_CACHE_AVAIL)
			params->notes |= NOTE_CACHE_COPY;
	}

	/* Flip the page to the writeback state and unlock.  If we're called
	 * from write-through, then the page has already been put into the wb
	 * state.
	 */
	if (wreq->origin == NETFS_WRITEBACK)
		folio_start_writeback(folio);
	folio_unlock(folio);

	/* Attach the folio to the rolling buffer. */
	slot = queue->nr_slots;
	bvec_set_folio(&queue->bv[slot], folio, flen, foff);
	queue->nr_slots = slot + 1;
	wreq->load_cursor.slot = slot + 1;
	wreq->load_cursor.offset = 0;
	trace_netfs_bv_slot(queue, slot);
	trace_netfs_wback(wreq, folio, params->notes);

out:
	_leave(" = %x", params->notes);
	return 0;

skip_folio:
	ret = folio_redirty_for_writepage(wbc, folio);
	folio_unlock(folio);
	if (ret < 0)
		return ret;
	params->notes |= NOTE_DISCONTIG_BEFORE;
	goto out;
cancel_folio_discard:
	netfs_put_group(fgroup);
cancel_folio:
	folio_detach_private(folio);
	kfree(finfo);
	folio_unlock(folio);
	folio_cancel_dirty(folio);
	if (wreq->origin == NETFS_WRITETHROUGH)
		folio_end_writeback(folio);
	params->notes |= NOTE_DISCONTIG_BEFORE;
	goto out;
}

/*
 * Write some of the pending data back to the server
 */
int netfs_writepages(struct address_space *mapping,
		     struct writeback_control *wbc)
{
	struct netfs_inode *ictx = netfs_inode(mapping->host);
	struct netfs_io_request *wreq = NULL;
	struct netfs_wb_params params = {};
	struct folio *folio;
	int error = 0;

	if (!mutex_trylock(&ictx->wb_lock)) {
		if (wbc->sync_mode == WB_SYNC_NONE) {
			netfs_stat(&netfs_n_wb_lock_skip);
			return 0;
		}
		netfs_stat(&netfs_n_wb_lock_wait);
		mutex_lock(&ictx->wb_lock);
	}

	/* Need the first folio to be able to set up the op. */
	folio = writeback_iter(mapping, wbc, NULL, &error);
	if (!folio)
		goto out;

	wreq = netfs_create_write_req(mapping, NULL, folio_pos(folio), NETFS_WRITEBACK);
	if (IS_ERR(wreq)) {
		error = PTR_ERR(wreq);
		goto couldnt_start;
	}

	if (bvecq_buffer_init(&wreq->load_cursor, GFP_NOFS) < 0)
		goto nomem;
	bvecq_pos_set(&params.dispatch_cursor, &wreq->load_cursor);
	bvecq_pos_set(&wreq->collect_cursor, &wreq->load_cursor);

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &wreq->flags);
	trace_netfs_write(wreq, netfs_write_trace_writeback);
	netfs_stat(&netfs_n_wh_writepages);

	if (wreq->io_streams[1].avail)
		params.notes |= NOTE_CACHE_AVAIL;

	do {
		_debug("wbiter %lx", folio->index);

		if (netfs_folio_group(folio) != NETFS_FOLIO_COPY_TO_CACHE &&
		    unlikely(!test_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags))) {
			set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
			wreq->netfs_ops->begin_writeback(wreq);
			if (wreq->io_streams[0].avail) {
				params.notes |= NOTE_UPLOAD_AVAIL;
				/* Order setting the active flag after other fields. */
				smp_store_release(&wreq->io_streams[0].active, true);
			}
		}

		params.notes &= NOTES__KEEP_MASK;
		error = netfs_queue_wb_folio(wreq, wbc, folio, &params);
		if (error < 0)
			break;
		error = netfs_issue_streams(wreq, &params);
		if (error < 0)
			break;

		bvecq_pos_step(&params.dispatch_cursor);
	} while ((folio = writeback_iter(mapping, wbc, folio, &error)));

	netfs_end_issue_write(wreq, &params);

	mutex_unlock(&ictx->wb_lock);
	bvecq_pos_unset(&wreq->load_cursor);
	bvecq_pos_unset(&params.dispatch_cursor);
	for (int i = 0; i < NR_IO_STREAMS; i++)
		bvecq_pos_unset(&wreq->io_streams[i].dispatch_cursor);
	netfs_wake_collector(wreq);

	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	_leave(" = %d", error);
	return error;

nomem:
	error = -ENOMEM;
	netfs_put_failed_request(wreq);
couldnt_start:
	netfs_kill_dirty_pages(mapping, wbc, folio);
out:
	mutex_unlock(&ictx->wb_lock);
	_leave(" = %d", error);
	return error;
}
EXPORT_SYMBOL(netfs_writepages);

/*
 * Begin a write operation for writing through the pagecache.
 */
struct netfs_writethrough *netfs_begin_writethrough(struct kiocb *iocb, size_t len)
{
	struct netfs_writethrough *wthru = NULL;
	struct netfs_io_request *wreq = NULL;
	struct netfs_inode *ictx = netfs_inode(file_inode(iocb->ki_filp));

	wthru = kzalloc_obj(struct netfs_writethrough);
	if (!wthru)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&ictx->wb_lock);

	wreq = netfs_create_write_req(iocb->ki_filp->f_mapping, iocb->ki_filp,
				      iocb->ki_pos, NETFS_WRITETHROUGH);
	if (IS_ERR(wreq)) {
		mutex_unlock(&ictx->wb_lock);
		kfree(wthru);
		return ERR_CAST(wreq);
	}
	wthru->wreq = wreq;

	if (bvecq_buffer_init(&wreq->load_cursor, GFP_NOFS) < 0) {
		netfs_put_failed_request(wreq);
		mutex_unlock(&ictx->wb_lock);
		kfree(wthru);
		return ERR_PTR(-ENOMEM);
	}

	bvecq_pos_set(&wthru->params.dispatch_cursor, &wreq->load_cursor);
	bvecq_pos_set(&wreq->collect_cursor, &wreq->load_cursor);

	if (wreq->io_streams[1].avail)
		wthru->params.notes |= NOTE_CACHE_AVAIL;

	wreq->io_streams[0].avail = true;
	trace_netfs_write(wreq, netfs_write_trace_writethrough);
	if (!is_sync_kiocb(iocb))
		wreq->iocb = iocb;

	if (unlikely(!test_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags))) {
		set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
		/* Don't call ->begin_writeback() as ->init_request() gets file*. */
		if (wreq->io_streams[0].avail) {
			wthru->params.notes |= NOTE_UPLOAD_AVAIL;
			/* Order setting the active flag after other fields. */
			smp_store_release(&wreq->io_streams[0].active, true);
		}
	}
	return wthru;
}

/*
 * Advance the state of the write operation used when writing through the
 * pagecache.  Data has been copied into the pagecache that we need to append
 * to the request.  If we've added more than wsize then we need to create a new
 * subrequest.
 */
int netfs_advance_writethrough(struct netfs_writethrough *wthru,
			       struct writeback_control *wbc,
			       struct folio *folio, size_t copied, bool to_page_end)
{
	struct netfs_io_request *wreq = wthru->wreq;
	int ret;

	_enter("R=%x ws=%u cp=%zu tp=%u",
	       wreq->debug_id, wreq->wsize, copied, to_page_end);

	if (!wthru->in_progress) {
		if (folio_test_dirty(folio))
			/* Sigh.  mmap. */
			folio_clear_dirty_for_io(folio);

		/* We can make multiple writes to the folio... */
		folio_start_writeback(folio);
		if (wreq->len == 0)
			trace_netfs_folio(folio, netfs_folio_trace_wthru);
		else
			trace_netfs_folio(folio, netfs_folio_trace_wthru_plus);
		wthru->in_progress = folio;
	}

	wreq->len += copied;
	if (!to_page_end)
		return 0;

	wthru->in_progress = NULL;
	wthru->params.notes &= NOTES__KEEP_MASK;
	ret = netfs_queue_wb_folio(wreq, wbc, folio, &wthru->params);
	if (ret < 0)
		return ret;
	return netfs_issue_streams(wreq, &wthru->params);
}

/*
 * End a write operation used when writing through the pagecache.
 */
ssize_t netfs_end_writethrough(struct netfs_writethrough *wthru,
			       struct writeback_control *wbc)
{
	struct netfs_io_request *wreq = wthru->wreq;
	struct netfs_inode *ictx = netfs_inode(wreq->inode);
	ssize_t ret;

	_enter("R=%x", wreq->debug_id);

	if (wthru->in_progress) {
		wthru->params.notes &= NOTES__KEEP_MASK;
		ret = netfs_queue_wb_folio(wreq, wbc, wthru->in_progress, &wthru->params);
		if (ret == 0)
			ret = netfs_issue_streams(wreq, &wthru->params);
		wthru->in_progress = NULL;
	}

	netfs_end_issue_write(wreq, &wthru->params);

	mutex_unlock(&ictx->wb_lock);

	bvecq_pos_unset(&wreq->load_cursor);
	bvecq_pos_unset(&wthru->params.dispatch_cursor);
	for (int i = 0; i < NR_IO_STREAMS; i++)
		bvecq_pos_unset(&wreq->io_streams[i].dispatch_cursor);

	if (wreq->iocb)
		ret = -EIOCBQUEUED;
	else
		ret = netfs_wait_for_write(wreq);
	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	kfree(wthru);
	return ret;
}

/*
 * Prepare a buffer for a single monolithic write.
 */
static int netfs_prepare_write_single_buffer(struct netfs_io_subrequest *subreq,
					     unsigned int max_segs)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	struct bio_vec *bv;
	struct bvecq *bq;
	size_t dio_size = wreq->cache_resources.dio_size;
	size_t dlen;

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);
	bvecq_pos_set(&subreq->content, &subreq->dispatch_pos);

	/* Round the end of the last entry up. */
	bq = subreq->content.bvecq;
	while (bq->next)
		bq = bq->next;
	bv = &bq->bv[bq->nr_slots - 1];
	dlen = round_up(bv->bv_len, dio_size);
	if (dlen > bv->bv_len) {
		subreq->len += dlen - bv->bv_len;
		bv->bv_len = dlen;
	}

	stream->buffered   = 0;
	stream->issue_from = subreq->len;
	wreq->submitted    = subreq->len;
	return 0;
}

/**
 * netfs_writeback_single - Write back a monolithic payload
 * @mapping: The mapping to write from
 * @wbc: Hints from the VM
 * @iter: Data to write
 * @len: Amount of data to write
 *
 * Write a monolithic, non-pagecache object back to the server and/or
 * the cache.  There's a maximum of one subrequest per stream.
 */
int netfs_writeback_single(struct address_space *mapping,
			   struct writeback_control *wbc,
			   struct iov_iter *iter,
			   size_t len)
{
	struct netfs_io_request *wreq;
	struct netfs_inode *ictx = netfs_inode(mapping->host);
	int ret;

	_enter("%zx,%zx", iov_iter_count(iter), len);

	if (!mutex_trylock(&ictx->wb_lock)) {
		if (wbc->sync_mode == WB_SYNC_NONE) {
			netfs_stat(&netfs_n_wb_lock_skip);
			return 0;
		}
		netfs_stat(&netfs_n_wb_lock_wait);
		mutex_lock(&ictx->wb_lock);
	}

	wreq = netfs_create_write_req(mapping, NULL, 0, NETFS_WRITEBACK_SINGLE);
	if (IS_ERR(wreq)) {
		ret = PTR_ERR(wreq);
		goto couldnt_start;
	}

	wreq->len = len;

	ret = netfs_extract_iter(iter, len, INT_MAX, 0, &wreq->load_cursor.bvecq, 0);
	if (ret < 0)
		goto cleanup_free;
	if (ret < len) {
		ret = -EIO;
		goto cleanup_free;
	}

	bvecq_pos_set(&wreq->collect_cursor, &wreq->load_cursor);

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &wreq->flags);
	trace_netfs_write(wreq, netfs_write_trace_writeback_single);
	netfs_stat(&netfs_n_wh_writepages);

	if (test_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags))
		wreq->netfs_ops->begin_writeback(wreq);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_subrequest *subreq;
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (!stream->avail)
			continue;

		stream->issue_from = 0;
		stream->buffered   = len;

		subreq = netfs_alloc_write_subreq(wreq, stream);
		if (!subreq) {
			ret = -ENOMEM;
			break;
		}

		bvecq_pos_set(&stream->dispatch_cursor, &wreq->load_cursor);

		ret = stream->issue_write(subreq);
		if (ret < 0 && ret != -EIOCBQUEUED)
			netfs_write_subrequest_terminated(subreq, ret);

		bvecq_pos_unset(&stream->dispatch_cursor);
	}

	wreq->submitted = wreq->len;
	smp_wmb(); /* Write lists before ALL_QUEUED. */
	set_bit(NETFS_RREQ_ALL_QUEUED, &wreq->flags);

	mutex_unlock(&ictx->wb_lock);
	netfs_wake_collector(wreq);

	/* TODO: Might want to be async here if WB_SYNC_NONE, but then need to
	 * wait before modifying.
	 */
	ret = netfs_wait_for_write(wreq);

	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	_leave(" = %d", ret);
	return ret;

cleanup_free:
	netfs_put_failed_request(wreq);
couldnt_start:
	mutex_unlock(&ictx->wb_lock);
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(netfs_writeback_single);

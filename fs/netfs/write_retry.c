// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem write retrying.
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Prepare the write buffer for a retry.  We can't necessarily reuse the write
 * buffer from the previous run of a subrequest because the filesystem is
 * permitted to modify it (add headers/trailers, encrypt it).  Further, the
 * subrequest may now be a different size (e.g. cifs has to negotiate for
 * maximum transfer size).  Also, we can't look at *stream as that may still
 * refer to the source material being broken up into original subrequests.
 */
int netfs_prepare_write_retry_buffer(struct netfs_io_subrequest *subreq,
				     unsigned int max_segs)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	size_t len;

	bvecq_pos_set(&subreq->dispatch_pos, &wreq->retry_cursor);
	bvecq_pos_set(&subreq->content, &wreq->retry_cursor);
	len = bvecq_slice(&wreq->retry_cursor, subreq->len, max_segs, &subreq->nr_segs);

	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	stream->issue_from += len;
	stream->buffered   -= len;
	if (stream->buffered == 0)
		bvecq_pos_unset(&wreq->retry_cursor);
	return 0;
}

/*
 * Perform retries on the streams that need it.  This only has to deal with
 * buffered writes; unbuffered write retry is handled in direct_write.c.
 */
static void netfs_retry_write_stream(struct netfs_io_request *wreq,
				     struct netfs_io_stream *stream)
{
	struct list_head *next;

	_enter("R=%x[%x:]", wreq->debug_id, stream->stream_nr);

	if (list_empty(&stream->subrequests))
		return;

	if (stream->source == NETFS_UPLOAD_TO_SERVER &&
	    wreq->netfs_ops->retry_request)
		wreq->netfs_ops->retry_request(wreq, stream);

	if (unlikely(stream->failed))
		return;

	next = stream->subrequests.next;

	do {
		struct netfs_io_subrequest *subreq = NULL, *from, *to, *tmp;
		unsigned long long start, len;
		int ret;

		bvecq_pos_unset(&wreq->retry_cursor);

		/* Go through the stream and find the next span of contiguous
		 * data that we then rejig (cifs, for example, needs the wsize
		 * renegotiating) and reissue.
		 */
		from = list_entry(next, struct netfs_io_subrequest, rreq_link);
		to = from;
		start = from->start + from->transferred;
		len   = from->len   - from->transferred;

		if (test_bit(NETFS_SREQ_FAILED, &from->flags) ||
		    !test_bit(NETFS_SREQ_NEED_RETRY, &from->flags))
			goto out;

		list_for_each_continue(next, &stream->subrequests) {
			subreq = list_entry(next, struct netfs_io_subrequest, rreq_link);
			if (subreq->start + subreq->transferred != start + len ||
			    !test_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags))
				break;
			to = subreq;
			len += to->len;
		}

		/* Determine the set of buffers we're going to use.  Each
		 * subreq gets a subset of a single overall contiguous buffer.
		 */
		bvecq_pos_transfer(&wreq->retry_cursor, &from->dispatch_pos);
		bvecq_pos_advance(&wreq->retry_cursor, from->transferred);
		wreq->retry_start = start;
		wreq->retry_buffered = len;

		/* Work through the sublist. */
		subreq = from;
		list_for_each_entry_from(subreq, &stream->subrequests, rreq_link) {
			if (!wreq->retry_buffered)
				break;

			bvecq_pos_unset(&subreq->dispatch_pos);
			bvecq_pos_unset(&subreq->content);
			subreq->content.bvecq = NULL;
			subreq->content.slot = 0;
			subreq->content.offset = 0;

			__clear_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
			__clear_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
			__clear_bit(NETFS_SREQ_FAILED, &subreq->flags);
			__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);
			subreq->start		= wreq->retry_start;
			subreq->len		= wreq->retry_buffered;
			subreq->transferred	= 0;
			subreq->retry_count	+= 1;
			subreq->error		= 0;

			netfs_stat(&netfs_n_wh_retry_write_subreq);
			trace_netfs_sreq(subreq, netfs_sreq_trace_retry);
			netfs_get_subrequest(subreq, netfs_sreq_trace_get_resubmit);
			ret = stream->issue_write(subreq);
			if (ret < 0 && ret != -EIOCBQUEUED)
				netfs_write_subrequest_terminated(subreq, ret);

			if (subreq == to)
				break;
		}

		/* If we managed to use fewer subreqs, we can discard the
		 * excess; if we used the same number, then we're done.
		 */
		if (!len) {
			if (subreq == to)
				continue;
			list_for_each_entry_safe_from(subreq, tmp,
						      &stream->subrequests, rreq_link) {
				trace_netfs_sreq(subreq, netfs_sreq_trace_discard);
				list_del(&subreq->rreq_link);
				netfs_put_subrequest(subreq, netfs_sreq_trace_put_done);
				if (subreq == to)
					break;
			}
			continue;
		}

		/* We ran out of subrequests, so we need to allocate some more
		 * and insert them after.
		 */
		do {
			subreq = netfs_alloc_subrequest(wreq);
			subreq->source		= to->source;
			subreq->start		= start;
			subreq->stream_nr	= to->stream_nr;
			subreq->retry_count	= 1;

			trace_netfs_sreq_ref(wreq->debug_id, subreq->debug_index,
					     refcount_read(&subreq->ref),
					     netfs_sreq_trace_new);
			trace_netfs_sreq(subreq, netfs_sreq_trace_split);

			list_add(&subreq->rreq_link, &to->rreq_link);
			to = list_next_entry(to, rreq_link);
			trace_netfs_sreq(subreq, netfs_sreq_trace_retry);

			switch (stream->source) {
			case NETFS_UPLOAD_TO_SERVER:
				netfs_stat(&netfs_n_wh_upload);
				break;
			case NETFS_WRITE_TO_CACHE:
				netfs_stat(&netfs_n_wh_write);
				break;
			default:
				WARN_ON_ONCE(1);
			}

			ret = stream->issue_write(subreq);
			if (ret < 0 && ret != -EIOCBQUEUED)
				netfs_write_subrequest_terminated(subreq, ret);

		} while (len);

	} while (!list_is_head(next, &stream->subrequests));

out:
	bvecq_pos_unset(&wreq->retry_cursor);
}

/*
 * Perform retries on the streams that need it.  If we're doing content
 * encryption and the server copy changed due to a third-party write, we may
 * need to do an RMW cycle and also rewrite the data to the cache.
 */
void netfs_retry_writes(struct netfs_io_request *wreq)
{
	struct netfs_io_stream *stream;
	int s;

	netfs_stat(&netfs_n_wh_retry_write_req);

	/* Wait for all outstanding I/O to quiesce before performing retries as
	 * we may need to renegotiate the I/O sizes.
	 */
	set_bit(NETFS_RREQ_RETRYING, &wreq->flags);
	for (s = 0; s < NR_IO_STREAMS; s++) {
		stream = &wreq->io_streams[s];
		if (stream->active)
			netfs_wait_for_in_progress_stream(wreq, stream);
	}
	clear_bit(NETFS_RREQ_RETRYING, &wreq->flags);

	// TODO: Enc: Fetch changed partial pages
	// TODO: Enc: Reencrypt content if needed.
	// TODO: Enc: Wind back transferred point.
	// TODO: Enc: Mark cache pages for retry.

	for (s = 0; s < NR_IO_STREAMS; s++) {
		stream = &wreq->io_streams[s];
		if (stream->need_retry) {
			stream->need_retry = false;
			netfs_retry_write_stream(wreq, stream);
		}
	}

	pr_notice("Retrying\n");
}

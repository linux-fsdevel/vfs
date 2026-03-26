// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem read subrequest retrying.
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Prepare the I/O buffer on a buffered read subrequest for the filesystem to
 * use as a bvec queue.
 */
int netfs_prepare_buffered_read_retry_buffer(struct netfs_io_subrequest *subreq,
					     unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;
	size_t len;

	bvecq_pos_set(&subreq->dispatch_pos, &rreq->retry_cursor);
	bvecq_pos_set(&subreq->content, &subreq->dispatch_pos);
	len = bvecq_slice(&rreq->retry_cursor, subreq->len, max_segs,
			  &subreq->nr_segs);
	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}
	rreq->retry_buffered -= subreq->len;
	rreq->retry_start    += subreq->len;
	return 0;
}

/*
 * Reset the state of the subrequest and discard any buffering so that we can
 * retry (where this may include sending it to the server instead of the
 * cache).
 */
int netfs_reset_for_read_retry(struct netfs_io_subrequest *subreq)
{
	trace_netfs_sreq(subreq, netfs_sreq_trace_retry);

	if (subreq->retry_count > 3) {
		trace_netfs_sreq(subreq, netfs_sreq_trace_too_many_retries);
		return subreq->error;
	}

	subreq->retry_count++;
	__clear_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
	__clear_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
	__clear_bit(NETFS_SREQ_FAILED, &subreq->flags);
	__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);
	bvecq_pos_unset(&subreq->content);
	bvecq_pos_unset(&subreq->dispatch_pos);
	subreq->error = 0;
	subreq->transferred = 0;
	netfs_get_subrequest(subreq, netfs_sreq_trace_get_resubmit);
	netfs_stat(&netfs_n_wh_retry_write_subreq);
	return 0;
}

/*
 * Go through the list of failed/short reads, retrying all retryable ones.  We
 * need to switch failed cache reads to network downloads.
 */
static void netfs_retry_read_subrequests(struct netfs_io_request *rreq)
{
	struct netfs_io_subrequest *subreq;
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	struct list_head *next;
	int ret;

	_enter("R=%x", rreq->debug_id);

	if (list_empty(&stream->subrequests))
		return;

	if (rreq->netfs_ops->retry_request)
		rreq->netfs_ops->retry_request(rreq, NULL);

	/* Okay, we need to renegotiate all the download requests and flip any
	 * failed cache reads over to being download requests and negotiate
	 * those also.
	 */
	next = stream->subrequests.next;

	do {
		struct netfs_io_subrequest *from, *to, *tmp;
		unsigned long long start;
		size_t len;
		bool subreq_superfluous = false;

		bvecq_pos_unset(&rreq->retry_cursor);

		/* Go through the subreqs and find the next span of contiguous
		 * buffer that we then rejig (cifs, for example, needs the
		 * rsize renegotiating) and reissue.
		 */
		from = list_entry(next, struct netfs_io_subrequest, rreq_link);
		to = from;
		start = from->start + from->transferred;
		len   = from->len   - from->transferred;

		_debug("from R=%08x[%x] s=%llx ctl=%zx/%zx",
		       rreq->debug_id, from->debug_index,
		       from->start, from->transferred, from->len);

		if (!test_bit(NETFS_SREQ_NEED_RETRY, &from->flags)) {
			subreq = from;
			goto abandon;
		}

		list_for_each_continue(next, &stream->subrequests) {
			subreq = list_entry(next, struct netfs_io_subrequest, rreq_link);
			if (subreq->start + subreq->transferred != start + len ||
			    !test_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags))
				break;
			to = subreq;
			len += to->len;
		}

		_debug(" - range: %llx-%llx %zx", start, start + len - 1, len);

		/* Determine the set of buffers we're going to use.  Each
		 * subreq takes a subset of a single overall contiguous buffer.
		 */
		bvecq_pos_transfer(&rreq->retry_cursor, &from->dispatch_pos);
		bvecq_pos_advance(&rreq->retry_cursor, from->transferred);
		rreq->retry_start = start;
		rreq->retry_buffered = len;

		/* Work through the sublist. */
		subreq = from;
		list_for_each_entry_from(subreq, &stream->subrequests, rreq_link) {
			if (rreq->retry_buffered == 0) {
				subreq_superfluous = true;
				break;
			}
			subreq->source	= NETFS_DOWNLOAD_FROM_SERVER;
			subreq->start	= rreq->retry_start;
			subreq->len	= rreq->retry_buffered;

			ret = netfs_reset_for_read_retry(subreq);
			if (ret < 0) {
				__set_bit(NETFS_SREQ_FAILED, &subreq->flags);
				rreq->error = ret;
				goto abandon;
			}

			netfs_stat(&netfs_n_rh_download);
			ret = rreq->netfs_ops->issue_read(subreq);
			if (ret < 0 && ret != -EIOCBQUEUED) {
				if (ret == -ENOMEM)
					goto abandon;
				subreq->error = ret;
				if (ret != -EAGAIN) {
					__set_bit(NETFS_SREQ_FAILED, &subreq->flags);
					goto abandon_after;
				}
				__set_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
				netfs_read_subreq_terminated(subreq);
			}
			if (subreq == to) {
				subreq_superfluous = false;
				break;
			}
		}

		/* If we managed to use fewer subreqs, we can discard the
		 * excess; if we used the same number, then we're done.
		 */
		if (rreq->retry_buffered == 0) {
			if (!subreq_superfluous)
				continue;
			list_for_each_entry_safe_from(subreq, tmp,
						      &stream->subrequests, rreq_link) {
				trace_netfs_sreq(subreq, netfs_sreq_trace_superfluous);
				list_del(&subreq->rreq_link);
				netfs_put_subrequest(subreq, netfs_sreq_trace_put_done);
				if (subreq == to)
					break;
			}
			subreq = NULL;
			continue;
		}

		/* We ran out of subrequests, so we need to allocate some more
		 * and insert them after.  They must start with being marked
		 * for retry to switch to the retry cursor.
		 */
		do {
			subreq = netfs_alloc_subrequest(rreq);
			if (!subreq) {
				subreq = to;
				goto abandon_after;
			}
			subreq->source		= NETFS_DOWNLOAD_FROM_SERVER;
			subreq->start		= rreq->retry_start;
			subreq->len		= rreq->retry_buffered;
			subreq->stream_nr	= stream->stream_nr;
			subreq->retry_count	= 1;

			trace_netfs_sreq_ref(rreq->debug_id, subreq->debug_index,
					     refcount_read(&subreq->ref),
					     netfs_sreq_trace_new);

			list_add(&subreq->rreq_link, &to->rreq_link);
			to = list_next_entry(to, rreq_link);
			trace_netfs_sreq(subreq, netfs_sreq_trace_retry);

			netfs_stat(&netfs_n_rh_download);
			ret = rreq->netfs_ops->issue_read(subreq);
			if (ret < 0 && ret != -EIOCBQUEUED) {
				if (ret == -ENOMEM)
					goto abandon;
				subreq->error = ret;
				if (ret != -EAGAIN) {
					__set_bit(NETFS_SREQ_FAILED, &subreq->flags);
					goto abandon_after;
				}
				__set_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
				netfs_read_subreq_terminated(subreq);
			}

		} while (rreq->retry_buffered > 0);

	} while (!list_is_head(next, &stream->subrequests));

out:
	bvecq_pos_unset(&rreq->retry_cursor);
	return;

	/* If we hit an error, fail all remaining incomplete subrequests */
abandon_after:
	if (list_is_last(&subreq->rreq_link, &stream->subrequests))
		return;
	subreq = list_next_entry(subreq, rreq_link);
abandon:
	list_for_each_entry_from(subreq, &stream->subrequests, rreq_link) {
		if (!test_bit(NETFS_SREQ_FAILED, &subreq->flags) &&
		    !test_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags))
			continue;
		subreq->error = -ENOMEM;
		__set_bit(NETFS_SREQ_FAILED, &subreq->flags);
		__clear_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
	}
	goto out;
}

/*
 * Retry reads.
 */
void netfs_retry_reads(struct netfs_io_request *rreq)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];

	netfs_stat(&netfs_n_rh_retry_read_req);

	/* Wait for all outstanding I/O to quiesce before performing retries as
	 * we may need to renegotiate the I/O sizes.
	 */
	set_bit(NETFS_RREQ_RETRYING, &rreq->flags);
	netfs_wait_for_in_progress_stream(rreq, stream);
	clear_bit(NETFS_RREQ_RETRYING, &rreq->flags);

	trace_netfs_rreq(rreq, netfs_rreq_trace_resubmit);
	netfs_retry_read_subrequests(rreq);
}

/*
 * Unlock any the pages that haven't been unlocked yet due to abandoned
 * subrequests.
 */
void netfs_unlock_abandoned_read_pages(struct netfs_io_request *rreq)
{
	struct bvecq *p;

	for (p = rreq->collect_cursor.bvecq; p; p = p->next) {
		for (int slot = 0; slot < p->nr_slots; slot++) {
			if (!p->bv[slot].bv_page)
				continue;

			struct folio *folio = page_folio(p->bv[slot].bv_page);

			if (folio->index == rreq->no_unlock_folio &&
			    test_bit(NETFS_RREQ_NO_UNLOCK_FOLIO, &rreq->flags)) {
				_debug("no unlock");
				continue;
			}
			trace_netfs_folio(folio, netfs_folio_trace_abandon);
			folio_unlock(folio);
			p->bv[slot].bv_page = NULL;
		}
	}
}

// SPDX-License-Identifier: GPL-2.0-or-later
/* Iterator helpers.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/scatterlist.h>
#include <linux/netfs.h>
#include "internal.h"

/**
 * netfs_extract_iter - Extract the pages from an iterator into a bvecq
 * @orig: The original iterator
 * @orig_len: The amount of iterator to copy
 * @max_segs: Maximum number of contiguous segments
 * @fpos: Starting file position to label the bvecq with
 * @_bvecq_head: Where to cache the bvec queue
 * @extraction_flags: Flags to qualify the request
 *
 * Extract the page fragments from the given amount of the source iterator and
 * build bvec queue that refers to all of those bits.  This allows the original
 * iterator to disposed of.
 *
 * @extraction_flags can have ITER_ALLOW_P2PDMA set to request peer-to-peer DMA be
 * allowed on the pages extracted.
 *
 * On success, the amount of data in the bvec is returned, the original
 * iterator will have been advanced by the amount extracted.
 *
 * The bvecq segments are marked with indications on how to get clean up the
 * extracted fragments.
 */
ssize_t netfs_extract_iter(struct iov_iter *orig, size_t orig_len, size_t max_segs,
			   unsigned long long fpos, struct bvecq **_bvecq_head,
			   iov_iter_extraction_t extraction_flags)
{
	struct bvecq *bq_tail = NULL;
	ssize_t ret = 0;
	size_t extracted = 0, nr_pages;

	_enter("{%u,%zx},%zx", orig->iter_type, orig->count, orig_len);

	WARN_ON_ONCE(orig_len > orig->count);

	nr_pages = iov_iter_npages(orig, max_segs ?: INT_MAX);
	if (WARN_ON(nr_pages == 0) ||
	    WARN_ON(nr_pages > max_segs))
		nr_pages = max_segs;
	max_segs = nr_pages;

	do {
		struct bvecq *bq;

		if (WARN_ON(max_segs == 0))
			break;

		bq = bvecq_alloc_one(max_segs, GFP_NOFS);
		if (!bq) {
			ret = -ENOMEM;
			break;
		}
		bq->free	= user_backed_iter(orig);
		bq->unpin	= iov_iter_extract_will_pin(orig);
		bq->prev	= bq_tail;
		bq->fpos	= fpos + extracted;

		if (bq_tail)
			bq_tail->next = bq;
		else
			*_bvecq_head = bq;
		bq_tail = bq;

		if (orig_len == 0)
			break;

		struct bio_vec *bv = bq->bv;
		do {
			struct page **pages;
			ssize_t got;
			size_t offset;
			size_t space = bq->max_slots - bq->nr_slots;
			size_t bv_size = array_size(bq->max_slots, sizeof(*bv));
			size_t pg_size = array_size(space, sizeof(*pages));

			/* Put the page list at the end of the bvec list
			 * storage.  bvec elements are larger than page
			 * pointers, so as long as we work 0->last, we should
			 * be fine.
			 */
			pages = (void *)bv + bv_size - pg_size;

			got = iov_iter_extract_pages(orig, &pages, orig_len,
						     space, extraction_flags, &offset);
			if (got < 0) {
				ret = got;
				goto out;
			}

			if (got == 0) {
				pr_err("extract_pages gave nothing from %zx, %zx\n",
				       extracted, orig_len);
				ret = -EIO;
				goto out;
			}

			if (got > orig_len) {
				pr_err("extract_pages rc=%zx more than %zx\n",
				       got, orig_len);
				goto out;
			}

			extracted += got;
			orig_len -= got;

			do {
				size_t len = umin(got, PAGE_SIZE - offset);

				BUG_ON(bq->nr_slots >= bq->max_slots);

				bvec_set_page(&bq->bv[bq->nr_slots],
					      *pages++, len, offset);
				bq->nr_slots++;
				got -= len;
				offset = 0;
			} while (got > 0);
		} while (orig_len > 0 && !bvecq_is_full(bq));
	} while (orig_len > 0 && max_segs > 0);

out:
	return extracted ?: ret;
}
EXPORT_SYMBOL_GPL(netfs_extract_iter);

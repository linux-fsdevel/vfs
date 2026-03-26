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
				pr_err("extract_pages gave nothing from %zu, %zu\n",
				       extracted, orig_len);
				ret = -EIO;
				goto out;
			}

			if (got > orig_len - extracted) {
				pr_err("extract_pages rc=%zd more than %zu\n",
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

/**
 * netfs_extract_user_iter - Extract the pages from a user iterator into a bvec
 * @orig: The original iterator
 * @orig_len: The amount of iterator to copy
 * @new: The iterator to be set up
 * @extraction_flags: Flags to qualify the request
 *
 * Extract the page fragments from the given amount of the source iterator and
 * build up a second iterator that refers to all of those bits.  This allows
 * the original iterator to be disposed of.
 *
 * @extraction_flags can have ITER_ALLOW_P2PDMA set to request peer-to-peer DMA be
 * allowed on the pages extracted.
 *
 * On success, the number of elements in the bvec is returned, the original
 * iterator will have been advanced by the amount extracted.
 *
 * The iov_iter_extract_mode() function should be used to query how cleanup
 * should be performed.
 */
ssize_t netfs_extract_user_iter(struct iov_iter *orig, size_t orig_len,
				struct iov_iter *new,
				iov_iter_extraction_t extraction_flags)
{
	struct bio_vec *bv = NULL;
	struct page **pages;
	unsigned int cur_npages;
	unsigned int max_pages;
	unsigned int npages = 0;
	unsigned int i;
	ssize_t ret;
	size_t count = orig_len, offset, len;
	size_t bv_size, pg_size;

	if (WARN_ON_ONCE(!iter_is_ubuf(orig) && !iter_is_iovec(orig)))
		return -EIO;

	max_pages = iov_iter_npages(orig, INT_MAX);
	bv_size = array_size(max_pages, sizeof(*bv));
	bv = kvmalloc(bv_size, GFP_KERNEL);
	if (!bv)
		return -ENOMEM;

	/* Put the page list at the end of the bvec list storage.  bvec
	 * elements are larger than page pointers, so as long as we work
	 * 0->last, we should be fine.
	 */
	pg_size = array_size(max_pages, sizeof(*pages));
	pages = (void *)bv + bv_size - pg_size;

	while (count && npages < max_pages) {
		ret = iov_iter_extract_pages(orig, &pages, count,
					     max_pages - npages, extraction_flags,
					     &offset);
		if (unlikely(ret <= 0)) {
			ret = ret ?: -EIO;
			break;
		}

		if (ret > count) {
			pr_err("get_pages rc=%zd more than %zu\n", ret, count);
			break;
		}

		count -= ret;
		ret += offset;
		cur_npages = DIV_ROUND_UP(ret, PAGE_SIZE);

		if (npages + cur_npages > max_pages) {
			pr_err("Out of bvec array capacity (%u vs %u)\n",
			       npages + cur_npages, max_pages);
			break;
		}

		for (i = 0; i < cur_npages; i++) {
			len = ret > PAGE_SIZE ? PAGE_SIZE : ret;
			bvec_set_page(bv + npages + i, *pages++, len - offset, offset);
			ret -= len;
			offset = 0;
		}

		npages += cur_npages;
	}

	if (ret < 0 && (ret == -ENOMEM || npages == 0)) {
		for (i = 0; i < npages; i++)
			unpin_user_page(bv[i].bv_page);
		kvfree(bv);
		return ret;
	}

	iov_iter_bvec(new, orig->data_source, bv, npages, orig_len - count);
	return npages;
}
EXPORT_SYMBOL_GPL(netfs_extract_user_iter);

/*
 * Select the span of a bvec iterator we're going to use.  Limit it by both maximum
 * size and maximum number of segments.  Returns the size of the span in bytes.
 */
static size_t netfs_limit_bvec(const struct iov_iter *iter, size_t start_offset,
			       size_t max_size, size_t max_segs)
{
	const struct bio_vec *bvecs = iter->bvec;
	unsigned int nbv = iter->nr_segs, ix = 0, nsegs = 0;
	size_t len, span = 0, n = iter->count;
	size_t skip = iter->iov_offset + start_offset;

	if (WARN_ON(!iov_iter_is_bvec(iter)) ||
	    WARN_ON(start_offset > n) ||
	    n == 0)
		return 0;

	while (n && ix < nbv && skip) {
		len = bvecs[ix].bv_len;
		if (skip < len)
			break;
		skip -= len;
		n -= len;
		ix++;
	}

	while (n && ix < nbv) {
		len = min3(n, bvecs[ix].bv_len - skip, max_size);
		span += len;
		nsegs++;
		ix++;
		if (span >= max_size || nsegs >= max_segs)
			break;
		skip = 0;
		n -= len;
	}

	return min(span, max_size);
}

/*
 * Select the span of a kvec iterator we're going to use.  Limit it by both
 * maximum size and maximum number of segments.  Returns the size of the span
 * in bytes.
 */
static size_t netfs_limit_kvec(const struct iov_iter *iter, size_t start_offset,
			       size_t max_size, size_t max_segs)
{
	const struct kvec *kvecs = iter->kvec;
	unsigned int nkv = iter->nr_segs, ix = 0, nsegs = 0;
	size_t len, span = 0, n = iter->count;
	size_t skip = iter->iov_offset + start_offset;

	if (WARN_ON(!iov_iter_is_kvec(iter)) ||
	    WARN_ON(start_offset > n) ||
	    n == 0)
		return 0;

	while (n && ix < nkv && skip) {
		len = kvecs[ix].iov_len;
		if (skip < len)
			break;
		skip -= len;
		n -= len;
		ix++;
	}

	while (n && ix < nkv) {
		len = min3(n, kvecs[ix].iov_len - skip, max_size);
		span += len;
		nsegs++;
		ix++;
		if (span >= max_size || nsegs >= max_segs)
			break;
		skip = 0;
		n -= len;
	}

	return min(span, max_size);
}

/*
 * Select the span of an xarray iterator we're going to use.  Limit it by both
 * maximum size and maximum number of segments.  It is assumed that segments
 * can be larger than a page in size, provided they're physically contiguous.
 * Returns the size of the span in bytes.
 */
static size_t netfs_limit_xarray(const struct iov_iter *iter, size_t start_offset,
				 size_t max_size, size_t max_segs)
{
	struct folio *folio;
	unsigned int nsegs = 0;
	loff_t pos = iter->xarray_start + iter->iov_offset;
	pgoff_t index = pos / PAGE_SIZE;
	size_t span = 0, n = iter->count;

	XA_STATE(xas, iter->xarray, index);

	if (WARN_ON(!iov_iter_is_xarray(iter)) ||
	    WARN_ON(start_offset > n) ||
	    n == 0)
		return 0;
	max_size = min(max_size, n - start_offset);

	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		size_t offset, flen, len;
		if (xas_retry(&xas, folio))
			continue;
		if (WARN_ON(xa_is_value(folio)))
			break;
		if (WARN_ON(folio_test_hugetlb(folio)))
			break;

		flen = folio_size(folio);
		offset = offset_in_folio(folio, pos);
		len = min(max_size, flen - offset);
		span += len;
		nsegs++;
		if (span >= max_size || nsegs >= max_segs)
			break;
	}

	rcu_read_unlock();
	return min(span, max_size);
}

/*
 * Select the span of a folio queue iterator we're going to use.  Limit it by
 * both maximum size and maximum number of segments.  Returns the size of the
 * span in bytes.
 */
static size_t netfs_limit_folioq(const struct iov_iter *iter, size_t start_offset,
				 size_t max_size, size_t max_segs)
{
	const struct folio_queue *folioq = iter->folioq;
	unsigned int nsegs = 0;
	unsigned int slot = iter->folioq_slot;
	size_t span = 0, n = iter->count;

	if (WARN_ON(!iov_iter_is_folioq(iter)) ||
	    WARN_ON(start_offset > n) ||
	    n == 0)
		return 0;
	max_size = umin(max_size, n - start_offset);

	if (slot >= folioq_nr_slots(folioq)) {
		folioq = folioq->next;
		slot = 0;
	}

	start_offset += iter->iov_offset;
	do {
		size_t flen = folioq_folio_size(folioq, slot);

		if (start_offset < flen) {
			span += flen - start_offset;
			nsegs++;
			start_offset = 0;
		} else {
			start_offset -= flen;
		}
		if (span >= max_size || nsegs >= max_segs)
			break;

		slot++;
		if (slot >= folioq_nr_slots(folioq)) {
			folioq = folioq->next;
			slot = 0;
		}
	} while (folioq);

	return umin(span, max_size);
}

size_t netfs_limit_iter(const struct iov_iter *iter, size_t start_offset,
			size_t max_size, size_t max_segs)
{
	if (iov_iter_is_folioq(iter))
		return netfs_limit_folioq(iter, start_offset, max_size, max_segs);
	if (iov_iter_is_bvec(iter))
		return netfs_limit_bvec(iter, start_offset, max_size, max_segs);
	if (iov_iter_is_xarray(iter))
		return netfs_limit_xarray(iter, start_offset, max_size, max_segs);
	if (iov_iter_is_kvec(iter))
		return netfs_limit_kvec(iter, start_offset, max_size, max_segs);
	BUG();
}
EXPORT_SYMBOL(netfs_limit_iter);

// SPDX-License-Identifier: GPL-2.0-only
/* Buffering helpers for bvec queues
 *
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include "internal.h"

void bvecq_dump(const struct bvecq *bq)
{
	int b = 0;

	for (; bq; bq = bq->next, b++) {
		int skipz = 0;

		pr_notice("BQ[%u] %u/%u fp=%llx\n", b, bq->nr_slots, bq->max_slots, bq->fpos);
		for (int s = 0; s < bq->nr_slots; s++) {
			const struct bio_vec *bv = &bq->bv[s];

			if (!bv->bv_page && !bv->bv_len && skipz < 2) {
				skipz = 1;
				continue;
			}
			if (skipz == 1)
				pr_notice("BQ[%u:00-%02u] ...\n", b, s - 1);
			skipz = 2;
			pr_notice("BQ[%u:%02u] %10lx %04x %04x %u\n",
				  b, s,
				  bv->bv_page ? page_to_pfn(bv->bv_page) : 0,
				  bv->bv_offset, bv->bv_len,
				  bv->bv_page ? page_count(bv->bv_page) : 0);
		}
	}
}
EXPORT_SYMBOL(bvecq_dump);

/**
 * bvecq_alloc_one - Allocate a single bvecq node with unpopulated slots
 * @nr_slots: Number of slots to allocate
 * @gfp: The allocation constraints.
 *
 * Allocate a single bvecq node and initialise the header.  A number of inline
 * slots are also allocated, rounded up to fit after the header in a power-of-2
 * slab object of up to 512 bytes (up to 29 slots on a 64-bit cpu).  The slot
 * array is not initialised.
 *
 * Return: The node pointer or NULL on allocation failure.
 */
struct bvecq *bvecq_alloc_one(size_t nr_slots, gfp_t gfp)
{
	struct bvecq *bq;
	const size_t max_size = 512;
	const size_t max_slots = (max_size - sizeof(*bq)) / sizeof(bq->__bv[0]);
	size_t part = umin(nr_slots, max_slots);
	size_t size = roundup_pow_of_two(struct_size(bq, __bv, part));

	bq = kmalloc(size, gfp);
	if (bq) {
		*bq = (struct bvecq) {
			.ref		= REFCOUNT_INIT(1),
			.bv		= bq->__bv,
			.inline_bv	= true,
			.max_slots	= (size - sizeof(*bq)) / sizeof(bq->__bv[0]),
		};
		netfs_stat(&netfs_n_bvecq);
	}
	return bq;
}
EXPORT_SYMBOL(bvecq_alloc_one);

/**
 * bvecq_alloc_chain - Allocate an unpopulated bvecq chain
 * @nr_slots: Number of slots to allocate
 * @gfp: The allocation constraints.
 *
 * Allocate a chain of bvecq nodes providing at least the requested cumulative
 * number of slots.
 *
 * Return: The first node pointer or NULL on allocation failure.
 */
struct bvecq *bvecq_alloc_chain(size_t nr_slots, gfp_t gfp)
{
	struct bvecq *head = NULL, *tail = NULL;

	_enter("%zu", nr_slots);

	for (;;) {
		struct bvecq *bq;

		bq = bvecq_alloc_one(nr_slots, gfp);
		if (!bq)
			goto oom;

		if (tail) {
			tail->next = bq;
			bq->prev = tail;
		} else {
			head = bq;
		}
		tail = bq;
		if (tail->max_slots >= nr_slots)
			break;
		nr_slots -= tail->max_slots;
	}

	return head;
oom:
	bvecq_put(head);
	return NULL;
}
EXPORT_SYMBOL(bvecq_alloc_chain);

/**
 * bvecq_alloc_buffer - Allocate a bvecq chain and populate with buffers
 * @size: Target size of the buffer (can be 0 for an empty buffer)
 * @pre_slots: Number of preamble slots to set aside
 * @gfp: The allocation constraints.
 *
 * Allocate a chain of bvecq nodes and populate the slots with sufficient pages
 * to provide at least the requested amount of space, leaving the first
 * @pre_slots slots unset.  The pages allocated may be compound pages larger
 * than PAGE_SIZE and thus occupy fewer slots.  The pages have their refcounts
 * set to 1 and can be passed to MSG_SPLICE_PAGES.
 *
 * Return: The first node pointer or NULL on allocation failure.
 */
struct bvecq *bvecq_alloc_buffer(size_t size, unsigned int pre_slots, gfp_t gfp)
{
	struct bvecq *head = NULL, *tail = NULL, *p = NULL;
	size_t count = DIV_ROUND_UP(size, PAGE_SIZE);

	_enter("%zx,%zx,%u", size, count, pre_slots);

	do {
		struct page **pages;
		int want, got;

		p = bvecq_alloc_one(umin(count, 32 - 3), gfp);
		if (!p)
			goto oom;

		p->free = true;

		if (tail) {
			tail->next = p;
			p->prev = tail;
		} else {
			head = p;
		}
		tail = p;
		if (!count)
			break;

		pages = (struct page **)&p->bv[p->max_slots];
		pages -= p->max_slots - pre_slots;
		memset(pages, 0, (p->max_slots - pre_slots) * sizeof(pages[0]));

		want = umin(count, p->max_slots - pre_slots);
		got = alloc_pages_bulk(gfp, want, pages);
		if (got < want) {
			for (int i = 0; i < got; i++)
				__free_page(pages[i]);
			goto oom;
		}

		tail->nr_slots = pre_slots + got;
		for (int i = 0; i < got; i++) {
			int j = pre_slots + i;

			set_page_count(pages[i], 1);
			bvec_set_page(&tail->bv[j], pages[i], PAGE_SIZE, 0);
		}

		count -= got;
		pre_slots = 0;
	} while (count > 0);

	return head;
oom:
	bvecq_put(head);
	return NULL;
}
EXPORT_SYMBOL(bvecq_alloc_buffer);

/*
 * Free the page pointed to be a segment as necessary.
 */
static void bvecq_free_seg(struct bvecq *bq, unsigned int seg)
{
	if (!bq->free ||
	    !bq->bv[seg].bv_page)
		return;

	if (bq->unpin)
		unpin_user_page(bq->bv[seg].bv_page);
	else
		__free_page(bq->bv[seg].bv_page);
}

/**
 * bvecq_put - Put a ref on a bvec queue
 * @bq: The start of the folio queue to free
 *
 * Put the ref(s) on the nodes in a bvec queue, freeing up the node and the
 * page fragments it points to as the refcounts become zero.
 */
void bvecq_put(struct bvecq *bq)
{
	struct bvecq *next;

	for (; bq; bq = next) {
		if (!refcount_dec_and_test(&bq->ref))
			break;
		for (int seg = 0; seg < bq->nr_slots; seg++)
			bvecq_free_seg(bq, seg);
		next = bq->next;
		netfs_stat_d(&netfs_n_bvecq);
		kfree(bq);
	}
}
EXPORT_SYMBOL(bvecq_put);

/**
 * bvecq_expand_buffer - Allocate buffer space into a bvec queue
 * @_buffer: Pointer to the bvecq chain to expand (may point to a NULL; updated).
 * @_cur_size: Current size of the buffer (updated).
 * @size: Target size of the buffer.
 * @gfp: The allocation constraints.
 */
int bvecq_expand_buffer(struct bvecq **_buffer, size_t *_cur_size, ssize_t size, gfp_t gfp)
{
	struct bvecq *tail = *_buffer;
	const size_t max_slots = 32;

	size = round_up(size, PAGE_SIZE);
	if (*_cur_size >= size)
		return 0;

	if (tail)
		while (tail->next)
			tail = tail->next;

	do {
		struct page *page;
		int order = 0;

		if (!tail || bvecq_is_full(tail)) {
			struct bvecq *p;

			p = bvecq_alloc_one(max_slots, gfp);
			if (!p)
				return -ENOMEM;
			if (tail) {
				tail->next = p;
				p->prev = tail;
			} else {
				*_buffer = p;
			}
			tail = p;
		}

		if (size - *_cur_size > PAGE_SIZE)
			order = umin(ilog2(size - *_cur_size) - PAGE_SHIFT,
				     MAX_PAGECACHE_ORDER);

		page = alloc_pages(gfp | __GFP_COMP, order);
		if (!page && order > 0)
			page = alloc_pages(gfp | __GFP_COMP, 0);
		if (!page)
			return -ENOMEM;

		bvec_set_page(&tail->bv[tail->nr_slots++], page, PAGE_SIZE << order, 0);
		*_cur_size += PAGE_SIZE << order;
	} while (*_cur_size < size);

	return 0;
}
EXPORT_SYMBOL(bvecq_expand_buffer);

/**
 * bvecq_shorten_buffer - Shorten a bvec queue buffer
 * @bq: The start of the buffer to shorten
 * @slot: The slot to start from
 * @size: The size to retain
 *
 * Shorten the content of a bvec queue down to the minimum number of segments,
 * starting at the specified segment, to retain the specified size.
 *
 * Return: 0 if successful; -EMSGSIZE if there is insufficient content.
 */
int bvecq_shorten_buffer(struct bvecq *bq, unsigned int slot, size_t size)
{
	ssize_t retain = size;

	/* Skip through the segments we want to keep. */
	for (; bq; bq = bq->next) {
		for (; slot < bq->nr_slots; slot++) {
			retain -= bq->bv[slot].bv_len;
			if (retain < 0)
				goto found;
		}
		slot = 0;
	}
	if (WARN_ON_ONCE(retain > 0))
		return -EMSGSIZE;
	return 0;

found:
	/* Shorten the entry to be retained and clean the rest of this bvecq. */
	bq->bv[slot].bv_len += retain;
	slot++;
	for (int i = slot; i < bq->nr_slots; i++)
		bvecq_free_seg(bq, i);
	bq->nr_slots = slot;

	/* Free the queue tail. */
	bvecq_put(bq->next);
	bq->next = NULL;
	return 0;
}
EXPORT_SYMBOL(bvecq_shorten_buffer);

/**
 * bvecq_buffer_init - Initialise a buffer and set position
 * @pos: The position to point at the new buffer.
 * @gfp: The allocation constraints.
 *
 * Initialise a rolling buffer.  We allocate an unpopulated bvecq node to so
 * that the pointers can be independently driven by the producer and the
 * consumer.
 *
 * Return 0 if successful; -ENOMEM on allocation failure.
 */
int bvecq_buffer_init(struct bvecq_pos *pos, gfp_t gfp)
{
	struct bvecq *bq;

	bq = bvecq_alloc_one(13, gfp);
	if (!bq)
		return -ENOMEM;

	pos->bvecq  = bq; /* Comes with a ref. */
	pos->slot   = 0;
	pos->offset = 0;
	return 0;
}

/**
 * bvecq_buffer_make_space - Start a new bvecq node in a buffer
 * @pos: The position of the last node.
 * @gfp: The allocation constraints.
 *
 * Add a new node on to the buffer chain at the specified position, either
 * because the previous one is full or because we have a discontiguity to
 * contend with, and update @pos to point to it.
 *
 * Return: 0 if successful; -ENOMEM on allocation failure.
 */
int bvecq_buffer_make_space(struct bvecq_pos *pos, gfp_t gfp)
{
	struct bvecq *bq, *head = pos->bvecq;

	bq = bvecq_alloc_one(14, gfp);
	if (!bq)
		return -ENOMEM;
	bq->prev = head;

	pos->bvecq = bvecq_get(bq);
	pos->slot = 0;
	pos->offset = 0;

	/* Make sure the initialisation is stored before the next pointer.
	 *
	 * [!] NOTE: After we set head->next, the consumer is at liberty to
	 * immediately delete the old head.
	 */
	smp_store_release(&head->next, bq);
	bvecq_put(head);
	return 0;
}

/**
 * bvecq_pos_advance - Advance a bvecq position
 * @pos: The position to advance.
 * @amount: The amount of bytes to advance by.
 *
 * Advance the specified bvecq position by @amount bytes.  @pos is updated and
 * bvecq ref counts may have been manipulated.  If the position hits the end of
 * the queue, then it is left pointing beyond the last slot of the last bvecq
 * so that it doesn't break the chain.
 */
void bvecq_pos_advance(struct bvecq_pos *pos, size_t amount)
{
	struct bvecq *bq = pos->bvecq;
	unsigned int slot = pos->slot;
	size_t offset = pos->offset;

	if (slot >= bq->nr_slots) {
		bq = bq->next;
		slot = 0;
	}

	while (amount) {
		const struct bio_vec *bv = &bq->bv[slot];
		size_t part = umin(bv->bv_len - offset, amount);

		if (likely(part < bv->bv_len)) {
			offset += part;
			break;
		}
		amount -= part;
		offset = 0;
		slot++;
		if (slot >= bq->nr_slots) {
			if (!bq->next)
				break;
			bq = bq->next;
			slot = 0;
		}
	}

	pos->slot   = slot;
	pos->offset = offset;
	bvecq_pos_move(pos, bq);
}

/**
 * bvecq_zero - Clear memory starting at the bvecq position.
 * @pos: The position in the bvecq chain to start clearing.
 * @amount: The number of bytes to clear.
 *
 * Clear memory fragments pointed to by a bvec queue.  @pos is updated and
 * bvecq ref counts may have been manipulated.  If the position hits the end of
 * the queue, then it is left pointing beyond the last slot of the last bvecq
 * so that it doesn't break the chain.
 *
 * Return: The number of bytes cleared.
 */
ssize_t bvecq_zero(struct bvecq_pos *pos, size_t amount)
{
	struct bvecq *bq = pos->bvecq;
	unsigned int slot = pos->slot;
	ssize_t cleared = 0;
	size_t offset = pos->offset;

	if (WARN_ON_ONCE(!bq))
		return 0;

	if (slot >= bq->nr_slots) {
		bq = bq->next;
		if (WARN_ON_ONCE(!bq))
			return 0;
		slot = 0;
	}

	do {
		const struct bio_vec *bv = &bq->bv[slot];

		if (offset < bv->bv_len) {
			size_t part = umin(amount - cleared, bv->bv_len - offset);

			memzero_page(bv->bv_page, bv->bv_offset + offset, part);

			offset += part;
			cleared += part;
		}

		if (offset >= bv->bv_len) {
			offset = 0;
			slot++;
			if (slot >= bq->nr_slots) {
				if (!bq->next)
					break;
				bq = bq->next;
				slot = 0;
			}
		}
	} while (cleared < amount);

	bvecq_pos_move(pos, bq);
	pos->slot = slot;
	pos->offset = offset;
	return cleared;
}

/**
 * bvecq_slice - Find a slice of a bvecq queue
 * @pos: The position to start at.
 * @max_size: The maximum size of the slice (or ULONG_MAX).
 * @max_segs: The maximum number of segments in the slice (or INT_MAX).
 * @_nr_segs: Where to put the number of segments (updated).
 *
 * Determine the size and number of segments that can be obtained the next
 * slice of bvec queue up to the maximum size and segment count specified.  The
 * slice is also limited if a discontiguity is found.
 *
 * @pos is updated to the end of the slice.  If the position hits the end of
 * the queue, then it is left pointing beyond the last slot of the last bvecq
 * so that it doesn't break the chain.
 *
 * Return: The number of bytes in the slice.
 */
size_t bvecq_slice(struct bvecq_pos *pos, size_t max_size,
		   unsigned int max_segs, unsigned int *_nr_segs)
{
	struct bvecq *bq;
	unsigned int slot = pos->slot, nsegs = 0;
	size_t size = 0;
	size_t offset = pos->offset;

	bq = pos->bvecq;
	for (;;) {
		for (; slot < bq->nr_slots; slot++) {
			const struct bio_vec *bvec = &bq->bv[slot];

			if (offset < bvec->bv_len && bvec->bv_page) {
				size_t part = umin(bvec->bv_len - offset, max_size);

				size += part;
				offset += part;
				max_size -= part;
				nsegs++;
				if (!max_size || nsegs >= max_segs)
					goto out;
			}
			offset = 0;
		}

		/* pos->bvecq isn't allowed to go NULL as the queue may get
		 * extended and we would lose our place.
		 */
		if (!bq->next)
			break;
		slot = 0;
		bq = bq->next;
		if (bq->discontig && size > 0)
			break;
	}

out:
	*_nr_segs = nsegs;
	if (slot == bq->nr_slots && bq->next) {
		bq = bq->next;
		slot = 0;
		offset = 0;
	}
	bvecq_pos_move(pos, bq);
	pos->slot = slot;
	pos->offset = offset;
	return size;
}

/**
 * bvecq_extract - Extract a slice of a bvecq queue into a new bvecq queue
 * @pos: The position to start at.
 * @max_size: The maximum size of the slice (or ULONG_MAX).
 * @max_segs: The maximum number of segments in the slice (or INT_MAX).
 * @to: Where to put the extraction bvecq chain head (updated).
 *
 * Allocate a new bvecq and extract into it memory fragments from a slice of
 * bvec queue, starting at @pos.  The slice is also limited if a discontiguity
 * is found.  No refs are taken on the page.
 *
 * @pos is updated to the end of the slice.  If the position hits the end of
 * the queue, then it is left pointing beyond the last slot of the last bvecq
 * so that it doesn't break the chain.
 *
 * If successful, *@to is set to point to the head of the newly allocated chain
 * and the caller inherits a ref to it.
 *
 * Return: The number of bytes extracted; -ENOMEM on allocation failure or -EIO
 * if no segments were available to extract.
 */
ssize_t bvecq_extract(struct bvecq_pos *pos, size_t max_size,
		      unsigned int max_segs, struct bvecq **to)
{
	struct bvecq_pos tmp_pos;
	struct bvecq *src, *dst = NULL;
	unsigned int slot = pos->slot, nsegs;
	ssize_t extracted = 0;
	size_t offset = pos->offset, amount;

	*to = NULL;
	if (WARN_ON_ONCE(!max_segs))
		max_segs = INT_MAX;

	bvecq_pos_set(&tmp_pos, pos);
	amount = bvecq_slice(&tmp_pos, max_size, max_segs, &nsegs);
	bvecq_pos_unset(&tmp_pos);
	if (nsegs == 0)
		return -EIO;

	dst = bvecq_alloc_chain(nsegs, GFP_KERNEL);
	if (!dst)
		return -ENOMEM;
	*to = dst;
	max_segs = nsegs;
	nsegs = 0;

	/* Transcribe the segments */
	src = pos->bvecq;
	for (;;) {
		for (; slot < src->nr_slots; slot++) {
			const struct bio_vec *sv = &src->bv[slot];
			struct bio_vec *dv = &dst->bv[dst->nr_slots];

			_debug("EXTR BQ=%x[%x] off=%zx am=%zx p=%lx",
			       src->priv, slot, offset, amount, page_to_pfn(sv->bv_page));

			if (offset < sv->bv_len && sv->bv_page) {
				size_t part = umin(sv->bv_len - offset, amount);

				bvec_set_page(dv, sv->bv_page, part,
					      sv->bv_offset + offset);
				extracted += part;
				amount -= part;
				offset += part;
				trace_netfs_bv_slot(dst, dst->nr_slots);
				dst->nr_slots++;
				nsegs++;
				if (bvecq_is_full(dst))
					dst = dst->next;
				if (nsegs >= max_segs)
					goto out;
				if (amount == 0)
					goto out;
			}
			offset = 0;
		}

		/* pos->bvecq isn't allowed to go NULL as the queue may get
		 * extended and we would lose our place.
		 */
		if (!src->next)
			break;
		slot = 0;
		src = src->next;
		if (src->discontig && extracted > 0)
			break;
	}

out:
	if (slot == src->nr_slots && src->next) {
		src = src->next;
		slot = 0;
		offset = 0;
	}
	bvecq_pos_move(pos, src);
	pos->slot = slot;
	pos->offset = offset;
	return extracted;
}

/**
 * bvecq_load_from_ra - Allocate a bvecq chain and load from readahead
 * @pos: Blank position object to attach the new chain to.
 * @ractl: The readahead control context.
 *
 * Decant the set of folios to be read from the readahead context into a bvecq
 * chain.  Each folio occupies one bio_vec element.
 *
 * Return: Amount of data loaded or -ENOMEM on allocation failure.
 */
ssize_t bvecq_load_from_ra(struct bvecq_pos *pos, struct readahead_control *ractl)
{
	XA_STATE(xas, &ractl->mapping->i_pages, ractl->_index);
	struct folio *folio;
	struct bvecq *bq;
	size_t loaded = 0;

	bq = bvecq_alloc_chain(ractl->_nr_folios, GFP_NOFS);
	if (!bq)
		return -ENOMEM;

	pos->bvecq  = bq;
	pos->slot   = 0;
	pos->offset = 0;

	rcu_read_lock();

	xas_for_each(&xas, folio, ractl->_index + ractl->_nr_pages - 1) {
		size_t len;

		if (xas_retry(&xas, folio))
			continue;
		VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

		len = folio_size(folio);
		bvec_set_folio(&bq->bv[bq->nr_slots++], folio, len, 0);
		loaded += len;
		trace_netfs_folio(folio, netfs_folio_trace_read);

		if (bq->nr_slots >= bq->max_slots) {
			bq = bq->next;
			if (!bq)
				break;
		}
	}

	rcu_read_unlock();

	ractl->_index += ractl->_nr_pages;
	ractl->_nr_pages = 0;
	return loaded;
}

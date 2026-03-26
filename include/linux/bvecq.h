/* SPDX-License-Identifier: GPL-2.0 */
/* Implementation of a segmented queue of bio_vec[].
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_BVECQ_H
#define _LINUX_BVECQ_H

#include <linux/bvec.h>

/*
 * Segmented bio_vec queue.
 *
 * These can be linked together to form messages of indefinite length and
 * iterated over with an ITER_BVECQ iterator.  The list is non-circular; next
 * and prev are NULL at the ends.
 *
 * The bv pointer points to the bio_vec array; this may be __bv if allocated
 * together.  The caller is responsible for determining whether or not this is
 * the case as the array pointed to by bv may be follow on directly from the
 * bvecq by accident of allocation (ie. ->bv == ->__bv is *not* sufficient to
 * determine this).
 *
 * The file position and discontiguity flag allow non-contiguous data sets to
 * be chained together, but still teased apart without the need to convert the
 * info in the bio_vec back into a folio pointer.
 */
struct bvecq {
	struct bvecq	*next;		/* Next bvec in the list or NULL */
	struct bvecq	*prev;		/* Prev bvec in the list or NULL */
	unsigned long long fpos;	/* File position */
	refcount_t	ref;
	u32		priv;		/* Private data */
	u16		nr_slots;	/* Number of elements in bv[] used */
	u16		max_slots;	/* Number of elements allocated in bv[] */
	bool		inline_bv:1;	/* T if __bv[] is being used */
	bool		free:1;		/* T if the pages need freeing */
	bool		unpin:1;	/* T if the pages need unpinning, not freeing */
	bool		discontig:1;	/* T if not contiguous with previous bvecq */
	struct bio_vec	*bv;		/* Pointer to array of page fragments */
	struct bio_vec	__bv[];		/* Default array (if ->inline_bv) */
};

/*
 * Position in a bio_vec queue.  The bvecq holds a ref on the queue segment it
 * points to.
 */
struct bvecq_pos {
	struct bvecq		*bvecq;		/* The first bvecq */
	unsigned int		offset;		/* The offset within the starting slot */
	u16			slot;		/* The starting slot */
};

void bvecq_dump(const struct bvecq *bq);
struct bvecq *bvecq_alloc_one(size_t nr_slots, gfp_t gfp);
struct bvecq *bvecq_alloc_chain(size_t nr_slots, gfp_t gfp);
struct bvecq *bvecq_alloc_buffer(size_t size, unsigned int pre_slots, gfp_t gfp);
void bvecq_put(struct bvecq *bq);
int bvecq_expand_buffer(struct bvecq **_buffer, size_t *_cur_size, ssize_t size, gfp_t gfp);
int bvecq_shorten_buffer(struct bvecq *bq, unsigned int slot, size_t size);
int bvecq_buffer_init(struct bvecq_pos *pos, gfp_t gfp);
int bvecq_buffer_make_space(struct bvecq_pos *pos, gfp_t gfp);
void bvecq_pos_advance(struct bvecq_pos *pos, size_t amount);
ssize_t bvecq_zero(struct bvecq_pos *pos, size_t amount);
size_t bvecq_slice(struct bvecq_pos *pos, size_t max_size,
		   unsigned int max_segs, unsigned int *_nr_segs);
ssize_t bvecq_extract(struct bvecq_pos *pos, size_t max_size,
		      unsigned int max_segs, struct bvecq **to);
ssize_t bvecq_load_from_ra(struct bvecq_pos *pos, struct readahead_control *ractl);

/**
 * bvecq_get - Get a ref on a bvecq
 * @bq: The bvecq to get a ref on
 */
static inline struct bvecq *bvecq_get(struct bvecq *bq)
{
	refcount_inc(&bq->ref);
	return bq;
}

/**
 * bvecq_is_full - Determine if a bvecq is full
 * @bvecq: The object to query
 *
 * Return: true if full; false if not.
 */
static inline bool bvecq_is_full(const struct bvecq *bvecq)
{
	return bvecq->nr_slots >= bvecq->max_slots;
}

/**
 * bvecq_pos_set - Set one position to be the same as another
 * @pos: The position object to set
 * @at: The source position.
 *
 * Set @pos to have the same position as @at.  This may take a ref on the
 * bvecq pointed to.
 */
static inline void bvecq_pos_set(struct bvecq_pos *pos, const struct bvecq_pos *at)
{
	*pos = *at;
	bvecq_get(pos->bvecq);
}

/**
 * bvecq_pos_unset - Unset a position
 * @pos: The position object to unset
 *
 * Unset @pos.  This does any needed ref cleanup.
 */
static inline void bvecq_pos_unset(struct bvecq_pos *pos)
{
	bvecq_put(pos->bvecq);
	pos->bvecq = NULL;
	pos->slot = 0;
	pos->offset = 0;
}

/**
 * bvecq_pos_transfer - Transfer one position to another, clearing the first
 * @pos: The position object to set
 * @from: The source position to clear.
 *
 * Set @pos to have the same position as @from and then clear @from.  This may
 * transfer a ref on the bvecq pointed to.
 */
static inline void bvecq_pos_transfer(struct bvecq_pos *pos, struct bvecq_pos *from)
{
	*pos = *from;
	from->bvecq = NULL;
	from->slot = 0;
	from->offset = 0;
}

/**
 * bvecq_pos_move - Update a position to a new bvecq
 * @pos: The position object to update.
 * @to: The new bvecq to point at.
 *
 * Update @pos to point to @to if it doesn't already do so.  This may
 * manipulate refs on the bvecqs pointed to.
 */
static inline void bvecq_pos_move(struct bvecq_pos *pos, struct bvecq *to)
{
	struct bvecq *old = pos->bvecq;

	if (old != to) {
		pos->bvecq = bvecq_get(to);
		bvecq_put(old);
	}
}

/**
 * bvecq_pos_step - Step a position to the next slot if possible
 * @pos: The position object to step.
 *
 * Update @pos to point to the next slot in the queue if not at the end.  This
 * may manipulate refs on the bvecqs pointed to.
 *
 * Return: true if successful, false if was at the end.
 */
static inline bool bvecq_pos_step(struct bvecq_pos *pos)
{
	struct bvecq *bq = pos->bvecq;

	pos->slot++;
	pos->offset = 0;
	if (pos->slot <= bq->nr_slots)
		return true;
	if (!bq->next)
		return false;
	bvecq_pos_move(pos, bq->next);
	return true;
}

/**
 * bvecq_delete_spent - Delete the bvecq at the front if possible
 * @pos: The position object to update.
 *
 * Delete the used up bvecq at the front of the queue that @pos points to if it
 * is not the last node in the queue; if it is the last node in the queue, it
 * is kept so that the queue doesn't become detached from the other end.  This
 * may manipulate refs on the bvecqs pointed to.
 */
static inline struct bvecq *bvecq_delete_spent(struct bvecq_pos *pos)
{
	struct bvecq *spent = pos->bvecq;
	/* Read the contents of the queue node after the pointer to it. */
	struct bvecq *next = smp_load_acquire(&spent->next);

	if (!next)
		return NULL;
	next->prev = NULL;
	spent->next = NULL;
	bvecq_put(spent);
	pos->bvecq = next; /* We take spent's ref */
	pos->slot = 0;
	pos->offset = 0;
	return next;
}

#endif /* _LINUX_BVECQ_H */

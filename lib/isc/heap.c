/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file
 * Heap implementation of priority queues adapted from the following:
 *
 *	\li "Introduction to Algorithms," Cormen, Leiserson, and Rivest,
 *	MIT Press / McGraw Hill, 1990, ISBN 0-262-03141-8, chapter 7.
 *
 *	\li "Algorithms," Second Edition, Sedgewick, Addison-Wesley, 1988,
 *	ISBN 0-201-06673-4, chapter 11.
 */

#include <stdbool.h>

#include <isc/heap.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/string.h> /* Required for memmove. */
#include <isc/util.h>

/*@{*/
/*%
 * Note: to make heap_parent and heap_left easy to compute, the first
 * element of the heap array is not used; i.e. heap subscripts are 1-based,
 * not 0-based.  The parent is index/2, and the left-child is index*2.
 * The right child is index*2+1.
 */
#define heap_parent(i) ((i) >> 1)
#define heap_left(i)   ((i) << 1)
/*@}*/

#define SIZE_INCREMENT 1024

#define HEAP_MAGIC    ISC_MAGIC('H', 'E', 'A', 'P')
#define VALID_HEAP(h) ISC_MAGIC_VALID(h, HEAP_MAGIC)

/*%
 * When the heap is in a consistent state, the following invariant
 * holds true: for every element i > 1, heap_parent(i) has a priority
 * higher than or equal to that of i.
 */
#ifdef ISC_HEAP_CHECK
#define HEAPCONDITION(i) \
	((i) == 1 ||     \
	 !heap->compare(heap->array[(i)], heap->array[heap_parent(i)]))
#else
#define HEAPCONDITION(i) true
#endif

/*% ISC heap structure. */
struct isc_heap {
	unsigned int magic;
	isc_mem_t *mctx;
	size_t size;
	size_t size_increment;
	size_t last;
	void **array;
	isc_heapcompare_t compare;
	isc_heapindex_t index;
};

#ifdef ISC_HEAP_CHECK
static void
heap_check(isc_heap_t *heap) {
	unsigned int i;
	for (i = 1; i <= heap->last; i++) {
		INSIST(HEAPCONDITION(i));
	}
}
#else /* ifdef ISC_HEAP_CHECK */
#define heap_check(x) (void)0
#endif /* ifdef ISC_HEAP_CHECK */

void
isc_heap_create(isc_mem_t *mctx, isc_heapcompare_t compare, isc_heapindex_t idx,
		unsigned int size_increment, isc_heap_t **heapp) {
	isc_heap_t *heap;

	REQUIRE(heapp != NULL && *heapp == NULL);
	REQUIRE(compare != NULL);

	heap = isc_mem_get(mctx, sizeof(*heap));
	*heap = (isc_heap_t){
		.size = 0,
		.size_increment = (size_increment == 0) ? SIZE_INCREMENT
							: size_increment,
		.compare = compare,
		.index = idx,
		.magic = HEAP_MAGIC,
	};

	isc_mem_attach(mctx, &heap->mctx);

	*heapp = heap;
}

void
isc_heap_destroy(isc_heap_t **heapp) {
	isc_heap_t *heap;

	REQUIRE(heapp != NULL);
	heap = *heapp;
	*heapp = NULL;
	REQUIRE(VALID_HEAP(heap));

	if (heap->array != NULL) {
		isc_mem_put(heap->mctx, heap->array,
			    heap->size * sizeof(heap->array[0]));
	}
	heap->magic = 0;
	isc_mem_putanddetach(&heap->mctx, heap, sizeof(*heap));
}

static void
upsize(isc_heap_t *heap) {
	size_t new_size = heap->size + heap->size_increment;
	heap->array = isc_mem_reget(heap->mctx, heap->array,
				    heap->size * sizeof(heap->array[0]),
				    new_size * sizeof(heap->array[0]));
	heap->size = new_size;
}

static void
downsize(isc_heap_t *heap) {
	INSIST(heap->size - heap->size_increment > heap->last);

	size_t new_size = heap->size - heap->size_increment;
	heap->array = isc_mem_reget(heap->mctx, heap->array,
				    heap->size * sizeof(heap->array[0]),
				    new_size * sizeof(heap->array[0]));
	heap->size = new_size;
}

static void
store(isc_heap_t *heap, size_t i, void *elt) {
	heap->array[i] = elt;
	if (heap->index != NULL) {
		(heap->index)(heap->array[i], i);
	}
}

static void
float_up(isc_heap_t *heap, size_t i, void *elt) {
	for (size_t j = heap_parent(i);
	     i > 1 && heap->compare(elt, heap->array[j]);
	     i = j, j = heap_parent(i))
	{
		store(heap, i, heap->array[j]);
	}
	store(heap, i, elt);

	INSIST(HEAPCONDITION(i));
	heap_check(heap);
}

static void
sink_down(isc_heap_t *heap, size_t i, void *elt) {
	for (size_t j = heap_left(i); j <= heap->last; i = j, j = heap_left(i))
	{
		/* Find the smallest of the (at most) two children. */
		if (j < heap->last &&
		    heap->compare(heap->array[j + 1], heap->array[j]))
		{
			j++;
		}
		if (heap->compare(elt, heap->array[j])) {
			break;
		}
		store(heap, i, heap->array[j]);
	}
	store(heap, i, elt);

	INSIST(HEAPCONDITION(i));
	heap_check(heap);
}

void
isc_heap_insert(isc_heap_t *heap, void *elt) {
	unsigned int new_last;

	REQUIRE(VALID_HEAP(heap));

	heap_check(heap);
	new_last = heap->last + 1;
	RUNTIME_CHECK(new_last > 0); /* overflow check */
	if (new_last >= heap->size) {
		upsize(heap);
	}
	heap->last = new_last;

	float_up(heap, new_last, elt);
}

void
isc_heap_delete(isc_heap_t *heap, unsigned int idx) {
	void *elt;
	bool less;

	REQUIRE(VALID_HEAP(heap));
	REQUIRE(idx >= 1 && idx <= heap->last);

	heap_check(heap);
	if (heap->index != NULL) {
		(heap->index)(heap->array[idx], 0);
	}

	if (heap->size > 2 * heap->size_increment &&
	    heap->last < heap->size - 2 * heap->size_increment)
	{
		downsize(heap);
	}

	if (idx == heap->last) {
		heap->array[heap->last] = NULL;
		heap->last--;
		heap_check(heap);
	} else {
		elt = heap->array[heap->last];
		heap->array[heap->last] = NULL;
		heap->last--;

		less = heap->compare(elt, heap->array[idx]);
		heap->array[idx] = elt;
		if (less) {
			float_up(heap, idx, heap->array[idx]);
		} else {
			sink_down(heap, idx, heap->array[idx]);
		}
	}
}

void
isc_heap_increased(isc_heap_t *heap, unsigned int idx) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(idx >= 1 && idx <= heap->last);

	float_up(heap, idx, heap->array[idx]);
}

void
isc_heap_decreased(isc_heap_t *heap, unsigned int idx) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(idx >= 1 && idx <= heap->last);

	sink_down(heap, idx, heap->array[idx]);
}

void *
isc_heap_element(isc_heap_t *heap, unsigned int idx) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(idx >= 1);

	heap_check(heap);
	if (idx <= heap->last) {
		return (heap->array[idx]);
	}
	return (NULL);
}

void
isc_heap_foreach(isc_heap_t *heap, isc_heapaction_t action, void *uap) {
	unsigned int i;

	REQUIRE(VALID_HEAP(heap));
	REQUIRE(action != NULL);

	for (i = 1; i <= heap->last; i++) {
		(action)(heap->array[i], uap);
	}
}

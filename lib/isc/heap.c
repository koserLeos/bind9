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
#include <isc/overflow.h>
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

#define HEAP_MAGIC    ISC_MAGIC('H', 'E', 'A', 'P')
#define VALID_HEAP(h) ISC_MAGIC_VALID(h, HEAP_MAGIC)

/*%
 * When the heap is in a consistent state, the following invariant
 * holds true: for every element i > 1, heap_parent(i) has a priority
 * higher than or equal to that of i.
 */
#define HEAPCONDITION(i) \
	((i) == 1 ||     \
	 !heap->compare(heap->array[(i)], heap->array[heap_parent(i)]))

/*% ISC heap structure. */
struct isc_heap {
	unsigned int magic;
	isc_mem_t *mctx;
	size_t size;
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
#define heap_check(x)
#endif /* ifdef ISC_HEAP_CHECK */

void
isc_heap_create(isc_mem_t *mctx, isc_heapcompare_t compare, isc_heapindex_t idx,
		unsigned int size_increment ISC_ATTR_UNUSED,
		isc_heap_t **heapp) {
	REQUIRE(heapp != NULL && *heapp == NULL);
	REQUIRE(compare != NULL);

	isc_heap_t *heap = isc_mem_get(mctx, sizeof(*heap));
	*heap = (isc_heap_t){
		.magic = HEAP_MAGIC,
		.compare = compare,
		.index = idx,
		.size = 1024,
		.array = isc_mem_cget(mctx, 1024, sizeof(heap->array[0])),
	};

	isc_mem_attach(mctx, &heap->mctx);

	*heapp = heap;
}

void
isc_heap_destroy(isc_heap_t **heapp) {
	REQUIRE(heapp != NULL);
	REQUIRE(VALID_HEAP(*heapp));

	isc_heap_t *heap = *heapp;
	*heapp = NULL;

	heap->magic = 0;

	isc_mem_cput(heap->mctx, heap->array, heap->size,
		     sizeof(heap->array[0]));
	isc_mem_putanddetach(&heap->mctx, heap, sizeof(*heap));
}

static void
resize(isc_heap_t *heap, size_t new_size) {
	REQUIRE(heap->size != 0);
	REQUIRE(new_size != heap->size);

	heap->array = isc_mem_creget(heap->mctx, heap->array, heap->size,
				     new_size, sizeof(heap->array[0]));
	heap->size = new_size;
}

static void
float_up(isc_heap_t *heap, unsigned int i, void *elt) {
	for (size_t p = heap_parent(i);
	     i > 1 && heap->compare(elt, heap->array[p]);
	     i = p, p = heap_parent(i))
	{
		heap->array[i] = heap->array[p];
		if (heap->index != NULL) {
			(heap->index)(heap->array[i], i);
		}
	}
	heap->array[i] = elt;
	if (heap->index != NULL) {
		(heap->index)(heap->array[i], i);
	}

	INSIST(HEAPCONDITION(i));
	heap_check(heap);
}

static void
sink_down(isc_heap_t *heap, unsigned int i, void *elt) {
	unsigned int j, size, half_size;
	size = heap->last;
	half_size = size / 2;
	while (i <= half_size) {
		/* Find the smallest of the (at most) two children. */
		j = heap_left(i);
		if (j < size &&
		    heap->compare(heap->array[j + 1], heap->array[j]))
		{
			j++;
		}
		if (heap->compare(elt, heap->array[j])) {
			break;
		}
		heap->array[i] = heap->array[j];
		if (heap->index != NULL) {
			(heap->index)(heap->array[i], i);
		}
		i = j;
	}
	heap->array[i] = elt;
	if (heap->index != NULL) {
		(heap->index)(heap->array[i], i);
	}

	INSIST(HEAPCONDITION(i));
	heap_check(heap);
}

void
isc_heap_insert(isc_heap_t *heap, void *elt) {
	REQUIRE(VALID_HEAP(heap));

	size_t new_last;

	heap_check(heap);
	new_last = heap->last + 1;
	RUNTIME_CHECK(new_last > 0); /* overflow check */
	if (new_last >= heap->size) {
		resize(heap, ISC_CHECKED_MUL(heap->size, 2));
	}
	heap->last = new_last;

	float_up(heap, new_last, elt);
}

void
isc_heap_delete(isc_heap_t *heap, unsigned int idx) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(idx >= 1 && idx <= heap->last);

	heap_check(heap);
	if (heap->index != NULL) {
		(heap->index)(heap->array[idx], 0);
	}
	if (idx == heap->last) {
		heap->array[heap->last] = NULL;
		heap->last--;
		heap_check(heap);
	} else {
		void *elt = heap->array[heap->last];
		heap->array[heap->last] = NULL;
		heap->last--;

		bool less = heap->compare(elt, heap->array[idx]);
		heap->array[idx] = elt;
		if (less) {
			float_up(heap, idx, heap->array[idx]);
		} else {
			sink_down(heap, idx, heap->array[idx]);
		}
	}

	if (heap->size >= 2048 && heap->last < heap->size / 3) {
		resize(heap, heap->size / 2);
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
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(action != NULL);

	for (size_t i = 1; i <= heap->last; i++) {
		(action)(heap->array[i], uap);
	}
}

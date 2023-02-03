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

/* ! \file */

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/heap.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/util.h>

#include <tests/isc.h>

#define mctx heap_mctx
#include "../heap.c"
#undef mctx

struct e {
	uint32_t value;
	unsigned int index;
};

static bool
compare(void *p1, void *p2) {
	struct e *e1 = p1;
	struct e *e2 = p2;

	return (e1->value < e2->value);
}

static void
idx(void *p, unsigned int i) {
	struct e *e = p;

	e->index = i;
}

/* test isc_heap_delete() */
ISC_RUN_TEST_IMPL(isc_heap_basic) {
	isc_heap_t *heap = NULL;
	struct e e1 = { .value = 100 };

	UNUSED(state);

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	isc_heap_insert(heap, &e1);
	assert_int_equal(e1.index, 1);

	isc_heap_delete(heap, e1.index);
	assert_int_equal(e1.index, 0);

	isc_heap_destroy(&heap);
	assert_null(heap);
}

#define INSERTS	  10000
#define INCREMENT 64

ISC_RUN_TEST_IMPL(isc_heap_random) {
	isc_heap_t *heap = NULL;
	size_t count = 0;

	isc_heap_create(mctx, compare, idx, INCREMENT, &heap);
	assert_non_null(heap);

	/* Insert couple of random entries */
	for (size_t i = 0; i < INSERTS; i++) {
		struct e *e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){ .value = isc_random32() };
		isc_heap_insert(heap, e);
		count++;
	}

	/* Check if we upsized the heap to the expected size */
	assert_int_equal(heap->size, (INSERTS / INCREMENT + 1) * INCREMENT);

	/* Check the order and delete the entries */
	uint32_t value = 0;
	struct e *e = NULL;
	while ((e = isc_heap_element(heap, 1)) != NULL) {
		assert_int_equal(e->index, 1);
		assert_true(e->value >= value);

		value = e->value;

		isc_heap_delete(heap, e->index);
		isc_mem_put(mctx, e, sizeof(*e));
		count--;
	}
	assert_int_equal(count, 0);

	/* Check if we downsized the heap to the expected size */
	assert_int_equal(heap->size, INCREMENT * 2);

	isc_heap_destroy(&heap);
	assert_null(heap);
}

static void
free_e(struct e *e, size_t *count) {
	(*count)--;
	isc_mem_put(mctx, e, sizeof(*e));
}

ISC_RUN_TEST_IMPL(isc_heap_foreach) {
	isc_heap_t *heap = NULL;
	size_t count = 0;

	isc_heap_create(mctx, compare, NULL, INCREMENT, &heap);
	assert_non_null(heap);

	/* Insert couple of random entries */
	for (size_t i = 0; i < INSERTS; i++) {
		struct e *e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){ .value = isc_random32() };
		isc_heap_insert(heap, e);
		count++;
	}

	isc_heap_foreach(heap, (isc_heapaction_t)free_e, &count);
	assert_int_equal(count, 0);

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_heap_basic)
ISC_TEST_ENTRY(isc_heap_random)
ISC_TEST_ENTRY(isc_heap_foreach)

ISC_TEST_LIST_END

ISC_TEST_MAIN

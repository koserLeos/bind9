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

#include <inttypes.h>
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

/* Don't reorder */

#define mctx __mctx
#include "heap.c"
#undef mctx

#define NROUNDS 100000

struct e {
	uint64_t value;
	uint32_t index;
};

static bool
compare(void *p1, void *p2) {
	REQUIRE(p1 != NULL);
	REQUIRE(p2 != NULL);

	struct e *e1 = p1;
	struct e *e2 = p2;

	return (e1->value < e2->value);
}

static void
idx(void *p, unsigned int i) {
	REQUIRE(p != NULL);

	struct e *e = p;

	e->index = i;
}

ISC_RUN_TEST_IMPL(isc_heap_create) {
	isc_heap_t *heap = NULL;

	expect_assert_failure(isc_heap_create(mctx, NULL, idx, 0, &heap));

	isc_heap_create(mctx, compare, NULL, 0, &heap);
	assert_non_null(heap);

	expect_assert_failure(isc_heap_create(mctx, compare, NULL, 0, &heap));

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_RUN_TEST_IMPL(isc_heap_destroy) {
	isc_heap_t *heap = NULL;

	expect_assert_failure(isc_heap_destroy(NULL));
	expect_assert_failure(isc_heap_destroy(&heap));

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);
	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_RUN_TEST_IMPL(isc_heap_insert) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;

	expect_assert_failure(isc_heap_insert(NULL, NULL));

	/*
	 * OK, this is kind of weird, but we actually allow storing NULLs on the
	 * heap, so the first insert will not fail, no matter of the contents as
	 * there's no comparison as we don't have the `index` function set here.
	 */
	isc_heap_create(mctx, compare, NULL, 0, &heap);
	assert_non_null(heap);

	isc_heap_insert(heap, NULL);
	expect_assert_failure(isc_heap_insert(heap, NULL));

	isc_heap_destroy(&heap);
	assert_null(heap);

	/*
	 * With the index function set to `idx()`, the `idx()` will get called
	 * on the NULL pointers and trigger an assertion failure there.
	 */
	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	expect_assert_failure(isc_heap_insert(heap, NULL));

	isc_heap_destroy(&heap);
	assert_null(heap);

	/* Test without the index function */
	isc_heap_create(mctx, compare, NULL, 0, &heap);
	assert_non_null(heap);

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){
			.value = i,
		};

		isc_heap_insert(heap, e);
	}

	while ((e = isc_heap_element(heap, 1)) != NULL) {
		isc_heap_delete(heap, 1);
		isc_mem_put(mctx, e, sizeof(*e));
	}

	isc_heap_destroy(&heap);
	assert_null(heap);

	/* Test with index function */
	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){
			.value = i,
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
	}

	while ((e = isc_heap_element(heap, 1)) != NULL) {
		isc_heap_delete(heap, 1);
		assert_int_equal(e->index, 0);
		isc_mem_put(mctx, e, sizeof(*e));
	}

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_RUN_TEST_IMPL(isc_heap_element) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;

	expect_assert_failure(isc_heap_element(NULL, 1));

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	expect_assert_failure(isc_heap_element(heap, 0));

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));

		*e = (struct e){
			.value = i,
		};

		isc_heap_insert(heap, e);
	}

	e = isc_heap_element(heap, NROUNDS + 1);
	assert_null(e);

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_heap_element(heap, i + 1);
		assert_non_null(e);

		isc_mem_put(mctx, e, sizeof(*e));
	}

	isc_heap_destroy(&heap);
	assert_null(heap);
}

/* test isc_heap_delete() */
ISC_RUN_TEST_IMPL(isc_heap_delete) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;

	expect_assert_failure(isc_heap_delete(NULL, 1));

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));

		*e = (struct e){
			.value = i,
		};

		isc_heap_insert(heap, e);
	}

	expect_assert_failure(isc_heap_delete(heap, 0));
	expect_assert_failure(isc_heap_delete(heap, NROUNDS + 1));

	for (size_t i = NROUNDS; i > 0; i--) {
		assert_true(i <= heap->last);
		e = isc_heap_element(heap, i);
		assert_non_null(e);

		isc_heap_delete(heap, i);
		isc_mem_put(mctx, e, sizeof(*e));
	}

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_RUN_TEST_IMPL(isc_heap_increased) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;
	struct e *es = isc_mem_cget(mctx, NROUNDS, sizeof(*es));
	size_t i;

	expect_assert_failure(isc_heap_element(NULL, 1));

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	expect_assert_failure(isc_heap_element(heap, 0));

	for (i = 0, e = &es[i]; i < NROUNDS; i++) {
		*e = (struct e){
			.value = i,
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
	}

	for (i = 0, e = &es[i]; i < NROUNDS; i++) {
		e->value += isc_random32();
		isc_heap_increased(heap, e->index);
	}

	uint32_t oldvalue = 0;
	for (i = 0; i < NROUNDS; i++) {
		e = isc_heap_element(heap, 1);
		assert_non_null(e);
		isc_heap_delete(heap, 1);

		assert_true(oldvalue <= e->value);
		oldvalue = e->value;
	}

	isc_heap_destroy(&heap);
	assert_null(heap);

	isc_mem_cput(mctx, es, NROUNDS, sizeof(*es));
}

ISC_RUN_TEST_IMPL(isc_heap_decreased) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;
	struct e *es = isc_mem_cget(mctx, NROUNDS, sizeof(*es));
	size_t i;

	expect_assert_failure(isc_heap_element(NULL, 1));

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	expect_assert_failure(isc_heap_element(heap, 0));

	for (i = 0, e = &es[i]; i < NROUNDS; i++) {
		*e = (struct e){
			.value = UINT32_MAX + i,
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
	}

	for (i = 0, e = &es[i]; i < NROUNDS; i++) {
		e->value -= isc_random32();
		isc_heap_decreased(heap, e->index);
	}

	uint32_t oldvalue = 0;
	for (i = 0; i < NROUNDS; i++) {
		e = isc_heap_element(heap, 1);
		assert_non_null(e);
		isc_heap_delete(heap, 1);

		assert_true(oldvalue <= e->value);
		oldvalue = e->value;
	}

	isc_heap_destroy(&heap);
	assert_null(heap);

	isc_mem_cput(mctx, es, NROUNDS, sizeof(*es));
}

ISC_RUN_TEST_IMPL(isc_heap_random) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;
	uint64_t oldvalue = 0;

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	/* First, insert N random elements */
	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){
			.value = isc_random32(),
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
	}

	oldvalue = 0;
	for (size_t i = 1; i <= NROUNDS; i++) {
		e = isc_heap_element(heap, i);
		assert_non_null(e);
		assert_true(oldvalue <= e->value);
	}

	for (size_t i = 0; i < NROUNDS * 100; i++) {
		int op = isc_random_uniform(4);
		switch (op) {
		case 0:
			e = isc_mem_get(mctx, sizeof(*e));
			*e = (struct e){
				.value = isc_random32(),
			};

			isc_heap_insert(heap, e);
			assert_int_not_equal(e->index, 0);
			break;
		case 1:
			e = isc_heap_element(
				heap, isc_random_uniform(heap->last) + 1);
			assert_non_null(e);
			isc_heap_delete(heap, e->index);
			isc_mem_put(mctx, e, sizeof(*e));
			break;
		case 2:
			e = isc_heap_element(
				heap, isc_random_uniform(heap->last) + 1);
			assert_non_null(e);
			if (e->value < UINT32_MAX) {
				e->value++;
			}
			isc_heap_increased(heap, e->index);
			break;
		case 3:
			e = isc_heap_element(
				heap, isc_random_uniform(heap->last) + 1);
			assert_non_null(e);
			if (e->value > 0) {
				e->value--;
			}
			isc_heap_decreased(heap, e->index);
			break;
		default:
			UNREACHABLE();
		}
	}

	oldvalue = 0;
	while ((e = isc_heap_element(heap, 1)) != NULL) {
		isc_heap_delete(heap, 1);
		assert_int_equal(e->index, 0);
		assert_true(oldvalue < e->value);
		isc_mem_put(mctx, e, sizeof(*e));
	}

	isc_heap_destroy(&heap);
	assert_null(heap);
}

static void
dispose(void *p, void *uap ISC_ATTR_UNUSED) {
	struct e *e = p;

	assert_non_null(e);
	isc_mem_free(mctx, e);
}

ISC_RUN_TEST_IMPL(isc_heap_foreach) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	for (size_t i = 0; i < NROUNDS; i++) {
		e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){
			.value = isc_random32(),
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
	}

	expect_assert_failure(isc_heap_foreach(NULL, dispose, NULL));
	expect_assert_failure(isc_heap_foreach(heap, NULL, NULL));

	isc_heap_foreach(heap, dispose, NULL);

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_RUN_TEST_IMPL(isc_heap_resize) {
	isc_heap_t *heap = NULL;
	struct e *e = NULL;
	size_t expected_size = 1024;
	size_t count = 0;

	isc_heap_create(mctx, compare, idx, 0, &heap);
	assert_non_null(heap);

	for (size_t i = 0; i < NROUNDS; i++) {
		assert_int_equal(heap->size, expected_size);

		e = isc_mem_get(mctx, sizeof(*e));
		*e = (struct e){
			.value = isc_random32(),
		};

		isc_heap_insert(heap, e);
		assert_int_not_equal(e->index, 0);
		count++;

		if (count >= expected_size) {
			expected_size *= 2;
		}
	}

	/* Make sure we counted our expected size just right */
	assert_int_equal(heap->size, 1 << (64 - __builtin_clzll(count)));

	for (size_t i = NROUNDS; i > 0; i--) {
		assert_int_equal(heap->size, expected_size);

		e = isc_heap_element(heap, 1);
		assert_non_null(e);

		isc_heap_delete(heap, 1);
		count--;

		isc_mem_put(mctx, e, sizeof(*e));

		if (expected_size > 1024 && count < expected_size / 3) {
			expected_size /= 2;
		}
	}

	assert_int_equal(heap->size, 1024);

	isc_heap_destroy(&heap);
	assert_null(heap);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_heap_create)
ISC_TEST_ENTRY(isc_heap_destroy)
ISC_TEST_ENTRY(isc_heap_insert)
ISC_TEST_ENTRY(isc_heap_element)
ISC_TEST_ENTRY(isc_heap_delete)
ISC_TEST_ENTRY(isc_heap_increased)
ISC_TEST_ENTRY(isc_heap_decreased)
ISC_TEST_ENTRY(isc_heap_random)
ISC_TEST_ENTRY(isc_heap_foreach)
ISC_TEST_ENTRY(isc_heap_resize)

ISC_TEST_LIST_END

ISC_TEST_MAIN

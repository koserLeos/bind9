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

#include <isc/mem.h>
#include <isc/skiplist.h>
#include <isc/util.h>

#include <tests/isc.h>

struct entry {
	uint32_t drift;
	uint32_t ttl;
};

static struct entry entries[] = {
	{ .drift = 0, .ttl = 10 }, { .drift = 0, .ttl = 20 },
	{ .drift = 0, .ttl = 30 }, { .drift = 0, .ttl = 40 },
	{ .drift = 0, .ttl = 50 }, { .drift = 0, .ttl = 60 },
	{ .drift = 0, .ttl = 70 }, { .drift = 0, .ttl = 80 },
	{ .drift = 0, .ttl = 90 }, { .drift = 0, .ttl = 99 },
};

static struct entry entries_drift[] = {
	{ .drift = 5, .ttl = 10 }, { .drift = 5, .ttl = 20 },
	{ .drift = 5, .ttl = 30 }, { .drift = 5, .ttl = 40 },
	{ .drift = 5, .ttl = 50 }, { .drift = 5, .ttl = 60 },
	{ .drift = 5, .ttl = 70 }, { .drift = 5, .ttl = 80 },
	{ .drift = 5, .ttl = 90 }, { .drift = 5, .ttl = 99 },
};

static void
fill_entries_driftless(isc_skiplist_t *slist) {
	uint64_t index;

	for (size_t i = 0; i < ARRAY_SIZE(entries); i++) {
		index = isc_skiplist_insert(slist, &entries[i]);
		assert_int_not_equal(index, 0);
	}
}

static void
fill_entries_drift(isc_skiplist_t *slist) {
	uint64_t index;

	for (size_t i = 0; i < ARRAY_SIZE(entries_drift); i++) {
		index = isc_skiplist_insert(slist, &entries_drift[i]);
		assert_int_not_equal(index, 0);
	}
}

static uint32_t
get_key(void *value) {
	REQUIRE(value != NULL);
	return ((struct entry *)value)->ttl;
}

static bool
remove_direct(void *user, void *value, uint32_t range) {
	struct entry *e = value;

	REQUIRE(user == NULL && value != NULL);
	REQUIRE(value != NULL);

	assert_in_range(e->ttl, 0, range);

	return true;
}

static bool
remove_drifting(void *user, void *value, uint32_t range) {
	struct entry *e;

	REQUIRE(value != NULL);
	REQUIRE(user == NULL);

	e = value;

	assert_in_range(e->ttl, 0, range);

	return e->ttl + e->drift < range;
}

ISC_RUN_TEST_IMPL(isc_skiplist_create) {
	isc_skiplist_t *slist = NULL;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_RUN_TEST_IMPL(isc_skiplist_insert_single) {
	isc_skiplist_t *slist = NULL;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	isc_skiplist_insert(slist, &entries[0]);

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_RUN_TEST_IMPL(isc_skiplist_insert) {
	isc_skiplist_t *slist = NULL;
	size_t i;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	for (i = 0; i < ARRAY_SIZE(entries); i++) {
		isc_skiplist_insert(slist, &entries[i]);
	}

	for (i = 0; i < ARRAY_SIZE(entries); i++) {
		isc_skiplist_insert(slist, &entries_drift[i]);
	}

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_RUN_TEST_IMPL(isc_skiplist_insert_make_duplicate) {
	isc_skiplist_t *slist = NULL;
	uint64_t index1, index2;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	index1 = isc_skiplist_insert(slist, &entries[0]);
	index2 = isc_skiplist_insert(slist, &entries[0]);
	assert_int_not_equal(index1, index2);

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_RUN_TEST_IMPL(isc_skiplist_delete) {
	isc_skiplist_t *slist = NULL;
	isc_result_t result;
	uint64_t index;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	index = isc_skiplist_insert(slist, &entries[0]);
	assert_int_not_equal(index, 0);

	result = isc_skiplist_delete(slist, &entries[0], index);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_skiplist_delete(slist, &entries[1], index);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_RUN_TEST_IMPL(isc_skiplist_poprange) {
	isc_skiplist_t *slist = NULL;
	size_t removed;

	isc_skiplist_create(mctx, get_key, &slist);
	assert_non_null(slist);

	fill_entries_drift(slist);
	fill_entries_driftless(slist);

	removed = isc_skiplist_poprange(slist, 51, 0, NULL, remove_direct);
	assert_int_equal(removed, 10);

	removed = isc_skiplist_poprange(slist, 51, 0, NULL, remove_drifting);
	assert_int_equal(removed, 0);

	fill_entries_drift(slist);
	fill_entries_driftless(slist);

	removed = isc_skiplist_poprange(slist, 51, 0, NULL, remove_drifting);
	assert_int_equal(removed, 9);

	removed = isc_skiplist_poprange(slist, 100, 15, NULL, remove_direct);
	assert_int_equal(removed, 15);

	removed = isc_skiplist_poprange(slist, 100, 0, NULL, remove_direct);
	assert_int_equal(removed, 6);

	isc_skiplist_destroy(&slist);
	assert_null(slist);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_skiplist_create)
ISC_TEST_ENTRY(isc_skiplist_insert_single)
ISC_TEST_ENTRY(isc_skiplist_insert_make_duplicate)
ISC_TEST_ENTRY(isc_skiplist_insert)
ISC_TEST_ENTRY(isc_skiplist_delete)
ISC_TEST_ENTRY(isc_skiplist_poprange)
ISC_TEST_LIST_END

ISC_TEST_MAIN

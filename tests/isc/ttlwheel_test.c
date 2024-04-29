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
#include <isc/ttlwheel.h>
#include <isc/util.h>

#include <tests/isc.h>

struct e {
	isc_stdtime_t prev;
};

static void
noop_action(void *user, void *data) {
	UNUSED(user);

	assert_non_null(data);
}

/* test isc_ttlwheel_create() */
ISC_RUN_TEST_IMPL(isc_ttlwheel_create) {
	isc_ttlwheel_t *wheel = NULL;

	isc_ttlwheel_create(mctx, 10, &wheel);
	assert_non_null(wheel);

	isc_ttlwheel_destroy(&wheel);
	assert_null(wheel);
}

/* test isc_ttlwheel_insert() */
ISC_RUN_TEST_IMPL(isc_ttlwheel_insert) {
	isc_ttlwheel_t *wheel = NULL;
	struct e element;
	uint64_t index;

	isc_ttlwheel_create(mctx, 10, &wheel);
	assert_non_null(wheel);

	index = isc_ttlwheel_insert(wheel, 5, &element);
	assert_int_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 10, &element);
	assert_int_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &element);
	assert_int_not_equal(index, 0);

	isc_ttlwheel_destroy(&wheel);
	assert_null(wheel);
}

/* test isc_ttlwheel_poprange() */
ISC_RUN_TEST_IMPL(isc_ttlwheel_poprange) {
	isc_ttlwheel_t *wheel = NULL;
	uint64_t index;
	size_t removed;
	struct e e;

	e = (struct e){
		.prev = 0,
	};

	isc_ttlwheel_create(mctx, 10, &wheel);
	assert_non_null(wheel);

	index = isc_ttlwheel_insert(wheel, 5, &e);
	assert_int_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &e);
	assert_int_not_equal(index, 0);

	removed = isc_ttlwheel_poprange(wheel, 20, 1, NULL, noop_action);
	assert_int_equal(removed, 1);

	isc_ttlwheel_destroy(&wheel);
	assert_null(wheel);
}

ISC_RUN_TEST_IMPL(isc_ttlwheel_epoch_move) {
	isc_ttlwheel_t *wheel = NULL;
	uint64_t index;
	size_t cleaned;

	isc_ttlwheel_create(mctx, 10, &wheel);
	assert_non_null(wheel);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 16, &index);
	assert_int_not_equal(index, 0);

	index = isc_ttlwheel_insert(wheel, 15, &index);
	assert_int_not_equal(index, 0);

	cleaned = isc_ttlwheel_poprange(wheel, 20, 5, NULL, noop_action);
	assert_int_equal(cleaned, 5);

	cleaned = isc_ttlwheel_poprange(wheel, 20, 0, NULL, noop_action);
	assert_int_equal(cleaned, 2);

	isc_ttlwheel_destroy(&wheel);
	assert_null(wheel);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_ttlwheel_create)
ISC_TEST_ENTRY(isc_ttlwheel_insert)
ISC_TEST_ENTRY(isc_ttlwheel_poprange)
ISC_TEST_ENTRY(isc_ttlwheel_epoch_move)
ISC_TEST_LIST_END

ISC_TEST_MAIN

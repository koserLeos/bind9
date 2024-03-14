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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <isc/heap.h>
#include <isc/random.h>
#include <isc/time.h>

#include <dns/name.h>

static bool
compare(void *a0, void *b0) {
	uint32_t a = *(uint32_t *)a0;
	uint32_t b = *(uint32_t *)b0;

	return (a > b);
}

static void
time_isc_heap(uint32_t *buf, const size_t count) {
	isc_mem_t *mctx = NULL;
	isc_heap_t *heap = NULL;
	isc_time_t start;
	isc_time_t finish;

	isc_mem_create(&mctx);
	isc_heap_create(mctx, compare, NULL, 1024, &heap);

	start = isc_time_now_hires();

	for (size_t i = 0; i < count; i++) {
		isc_heap_insert(heap, &buf[i]);
	}

	finish = isc_time_now_hires();

	uint64_t microseconds = isc_time_microdiff(&finish, &start);
	printf("%0.2f us per isc_heap insert\n", (double)microseconds / count);
	fflush(stdout);

	start = isc_time_now_hires();

	for (size_t i = 0; i < count; i++) {
		(void)isc_heap_element(heap, 1);
		isc_heap_delete(heap, 1);
	}

	finish = isc_time_now_hires();

	microseconds = isc_time_microdiff(&finish, &start);
	printf("%0.2f us per isc_heap dequeue (element+delete)\n",
	       (double)microseconds / count);
	fflush(stdout);

	isc_heap_destroy(&heap);
	isc_mem_destroy(&mctx);
}

#define NROUNDS 10000000

int
main(void) {
	uint32_t *items = calloc(NROUNDS, sizeof(items[0]));

	isc_random_buf(items, NROUNDS * sizeof(items[0]));

	time_isc_heap(items, NROUNDS);

	free(items);
}

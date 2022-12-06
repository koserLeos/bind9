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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/ascii.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>

#include "old.h"

static uint32_t
old_bench(dns_decompress_t *dctx, isc_buffer_t *source) {
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	uint32_t count = 0;

	while (isc_buffer_remaininglength(source) > 0) {
		result = old_name_fromwire(name, source, dctx, NULL);
		if (result != ISC_R_SUCCESS) {
			isc_buffer_forward(source, 1);
		}
		count++;
	}
	return (count);
}

static uint32_t
new_bench(dns_decompress_t *dctx, isc_buffer_t *source) {
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	uint32_t count = 0;

	while (isc_buffer_remaininglength(source) > 0) {
		result = dns_name_fromwire(name, source, dctx, NULL);
		if (result != ISC_R_SUCCESS) {
			isc_buffer_forward(source, 1);
		}
		count++;
	}
	return (count);
}

static void
oldnew_bench(const uint8_t *data, size_t size) {
	dns_decompress_t dctx;
	isc_buffer_t source;

	isc_buffer_constinit(&source, data, size);
	isc_buffer_add(&source, size);
	isc_buffer_setactive(&source, size);
	dns_decompress_init(&dctx, &source);
	isc_time_t s1;
	isc_time_now_hires(&s1);
	uint32_t n1 = old_bench(&dctx, &source);
	isc_time_t e1;
	isc_time_now_hires(&e1);
	dns_decompress_invalidate(&dctx);

	isc_buffer_first(&source);
	isc_buffer_setactive(&source, size);
	dns_decompress_init(&dctx, &source);
	isc_time_t s2;
	isc_time_now_hires(&s2);
	uint32_t n2 = new_bench(&dctx, &source);
	isc_time_t e2;
	isc_time_now_hires(&e2);
	dns_decompress_invalidate(&dctx);

	double t1 = (double)isc_time_microdiff(&e1, &s1);
	double t2 = (double)isc_time_microdiff(&e2, &s2);
	printf("  old %u / %f ms; %f / us\n", n1, t1 / 1000.0, n1 / t1);
	printf("  new %u / %f ms; %f / us\n", n2, t2 / 1000.0, n2 / t2);
	printf("  old/new %f or %f\n", t1 / t2, t2 / t1);
}

#define NAMES 1000
static uint8_t buf[1024 * NAMES];

int
main(void) {
	unsigned int p;

	printf("random buffer\n");
	isc_random_buf(buf, sizeof(buf));
	oldnew_bench(buf, sizeof(buf));

	p = 0;
	for (unsigned int name = 0; name < NAMES; name++) {
		unsigned int start = p;
		unsigned int prev = p;
		buf[p++] = 0;
		for (unsigned int label = 0; label < 127; label++) {
			unsigned int ptr = prev - start;
			prev = p;
			buf[p++] = 1;
			buf[p++] = 'a';
			buf[p++] = 0xC0 | (ptr >> 8);
			buf[p++] = 0xFF & ptr;
		}
	}
	printf("127 compression pointers\n");
	oldnew_bench(buf, p);

	p = 0;
	for (unsigned int name = 0; name < NAMES; name++) {
		for (unsigned int label = 0; label < 127; label++) {
			buf[p++] = 1;
			buf[p++] = 'a';
		}
		buf[p++] = 0;
	}
	printf("127 sequential labels\n");
	oldnew_bench(buf, p);

	p = 0;
	for (unsigned int name = 0; name < NAMES; name++) {
		for (unsigned int label = 0; label < 4; label++) {
			buf[p++] = 62;
			for (unsigned int c = 0; c < 62; c++) {
				buf[p++] = 'a';
			}
		}
		buf[p++] = 0;
	}
	printf("4 long sequential labels\n");
	oldnew_bench(buf, p);
}

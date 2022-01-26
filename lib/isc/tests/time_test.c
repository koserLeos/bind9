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

#if HAVE_CMOCKA

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>

#include "../time.c"

#define MAX_N  TIME_S_MAX
#define MAX_NS (NS_PER_S - 1)

static void
isc_interval_basic_test(void **state) {
	isc_interval_t i = { 0, 0 };

	UNUSED(state);

	assert_true(isc_interval_iszero(&i));

	isc_interval_set(&i, MAX_N, MAX_NS);
	assert_int_equal(i.seconds, MAX_N);
	assert_int_equal(i.nanoseconds, MAX_NS);

	isc_interval_set(&i, 1, NS_PER_MS * 2);
	assert_int_equal(isc_interval_ms(&i), MS_PER_S + 2);

	expect_assert_failure(isc_interval_set(NULL, 0, 0));
	expect_assert_failure(isc_interval_set(&i, 0, MAX_NS + 1));

	expect_assert_failure(isc_interval_iszero(NULL));
}

static void
isc_time_basic_test(void **state) {
	isc_time_t t = { 0, 0 };

	UNUSED(state);

	assert_true(isc_time_isepoch(&t));

	isc_time_set(&t, MAX_N, MAX_NS);
	assert_int_equal(t.seconds, MAX_N);
	assert_int_equal(t.nanoseconds, MAX_NS);

	assert_int_equal(isc_time_seconds(&t), t.seconds);
	assert_int_equal(isc_time_nanoseconds(&t), t.nanoseconds);

	isc_time_settoepoch(&t);
	assert_int_equal(t.seconds, 0);
	assert_int_equal(t.nanoseconds, 0);
	assert_true(isc_time_isepoch(&t));

	expect_assert_failure(isc_time_set(NULL, 0, 0));
	expect_assert_failure(isc_time_set(&t, 0, MAX_NS + 1));

	expect_assert_failure(isc_time_settoepoch(NULL));
	expect_assert_failure(isc_time_isepoch(NULL));
	expect_assert_failure(isc_time_isepoch(&(isc_time_t){ 0, MAX_NS + 1 }));

	expect_assert_failure(isc_time_seconds(NULL));
	expect_assert_failure(isc_time_seconds(&(isc_time_t){ 0, MAX_NS + 1 }));

	expect_assert_failure(isc_time_nanoseconds(NULL));
	expect_assert_failure(
		isc_time_nanoseconds(&(isc_time_t){ 0, MAX_NS + 1 }));
}

static void
isc_time_now_test(void **state) {
	isc_time_t t1 = { 0, 0 };
	isc_time_t t2 = { 0, 0 };
	time_t tm;

	UNUSED(state);

	tm = time(NULL);
	isc_time_now(&t1);
	nanosleep(&(struct timespec){ 1, 0 }, NULL);
	isc_time_now(&t2);

	assert_true(t1.seconds >= tm);
	assert_true(t2.seconds >= tm);

	assert_int_not_equal(t1.seconds, 0);
	assert_int_not_equal(t2.seconds, 0);
	assert_int_equal(isc_time_compare(&t2, &t1), 1);
	assert_int_equal(t2.seconds - t1.seconds, 1);

	tm = time(NULL);
	isc_time_now_hires(&t1);
	nanosleep(&(struct timespec){ 0, NS_PER_US }, NULL);
	isc_time_now_hires(&t2);

	assert_true(t1.seconds >= tm);
	assert_true(t2.seconds >= tm);
	assert_true(isc_time_microdiff(&t2, &t1) >= 1);
	assert_true(isc_time_microdiff(&t2, &t1) < US_PER_S);

	expect_assert_failure(isc_time_now(NULL));
	expect_assert_failure(isc_time_now_hires(NULL));
}

struct time_vectors {
	isc_time_t a;
	isc_interval_t b;
	isc_time_t r;
	isc_result_t result;
};

const struct time_vectors vectors_add[8] = {
	{ { 0, 0 }, { 0, 0 }, { 0, 0 }, ISC_R_SUCCESS },
	{ { 0, MAX_NS }, { 0, MAX_NS }, { 1, MAX_NS - 1 }, ISC_R_SUCCESS },
	{ { 0, NS_PER_S / 2 }, { 0, NS_PER_S / 2 }, { 1, 0 }, ISC_R_SUCCESS },
	{ { MAX_N, MAX_NS }, { 0, 0 }, { MAX_N, MAX_NS }, ISC_R_SUCCESS },
	{ { MAX_N, 0 }, { 0, MAX_NS }, { MAX_N, MAX_NS }, ISC_R_SUCCESS },
	{ { MAX_N, 0 }, { 1, 0 }, { 0, 0 }, ISC_R_RANGE },
	{ { MAX_N, MAX_NS }, { 0, 1 }, { 0, 0 }, ISC_R_RANGE },
	{ { MAX_N / 2 + 1, NS_PER_S / 2 },
	  { MAX_N / 2, NS_PER_S / 2 },
	  { 0, 0 },
	  ISC_R_RANGE },
};

const struct time_vectors vectors_sub[7] = {
	{ { 0, 0 }, { 0, 0 }, { 0, 0 }, ISC_R_SUCCESS },
	{ { 1, 0 }, { 0, MAX_NS }, { 0, 1 }, ISC_R_SUCCESS },
	{ { 1, NS_PER_S / 2 },
	  { 0, MAX_NS },
	  { 0, NS_PER_S / 2 + 1 },
	  ISC_R_SUCCESS },
	{ { MAX_N, MAX_NS }, { MAX_N, 0 }, { 0, MAX_NS }, ISC_R_SUCCESS },
	{ { 0, 0 }, { 1, 0 }, { 0, 0 }, ISC_R_RANGE },
	{ { 0, 0 }, { 0, MAX_NS }, { 0, 0 }, ISC_R_RANGE },
};

static void
isc_time_add_test(void **state) {
	UNUSED(state);

	for (size_t i = 0; i < ARRAY_SIZE(vectors_add); i++) {
		isc_time_t r = { MAX_N, MAX_N };
		isc_result_t result = isc_time_add(&(vectors_add[i].a),
						   &(vectors_add[i].b), &r);
		assert_int_equal(result, vectors_add[i].result);
		if (result != ISC_R_SUCCESS) {
			continue;
		}

		assert_int_equal(r.seconds, vectors_add[i].r.seconds);
		assert_int_equal(r.nanoseconds, vectors_add[i].r.nanoseconds);
	}

	expect_assert_failure((void)isc_time_add(&(isc_time_t){ 0, MAX_NS + 1 },
						 &(isc_interval_t){ 0, 0 },
						 &(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_add(
		&(isc_time_t){ 0, 0 }, &(isc_interval_t){ 0, MAX_NS + 1 },
		&(isc_time_t){ 0, 0 }));

	expect_assert_failure((void)isc_time_add((isc_time_t *)NULL,
						 &(isc_interval_t){ 0, 0 },
						 &(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_add(&(isc_time_t){ 0, 0 },
						 (isc_interval_t *)NULL,
						 &(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_add(
		&(isc_time_t){ 0, 0 }, &(isc_interval_t){ 0, 0 }, NULL));
}

static void
isc_time_sub_test(void **state) {
	UNUSED(state);

	for (size_t i = 0; i < ARRAY_SIZE(vectors_sub); i++) {
		isc_time_t r = { UINT_MAX, UINT_MAX };
		isc_result_t result = isc_time_subtract(
			&(vectors_sub[i].a), &(vectors_sub[i].b), &r);
		assert_int_equal(result, vectors_sub[i].result);
		if (result != ISC_R_SUCCESS) {
			continue;
		}
		assert_int_equal(r.seconds, vectors_sub[i].r.seconds);
		assert_int_equal(r.nanoseconds, vectors_sub[i].r.nanoseconds);
	}

	expect_assert_failure((void)isc_time_subtract(
		&(isc_time_t){ 0, MAX_NS + 1 }, &(isc_interval_t){ 0, 0 },
		&(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_subtract(
		&(isc_time_t){ 0, 0 }, &(isc_interval_t){ 0, MAX_NS + 1 },
		&(isc_time_t){ 0, 0 }));

	expect_assert_failure((void)isc_time_subtract((isc_time_t *)NULL,
						      &(isc_interval_t){ 0, 0 },
						      &(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_subtract(&(isc_time_t){ 0, 0 },
						      (isc_interval_t *)NULL,
						      &(isc_time_t){ 0, 0 }));
	expect_assert_failure((void)isc_time_subtract(
		&(isc_time_t){ 0, 0 }, &(isc_interval_t){ 0, 0 }, NULL));
}

struct compare_vectors {
	isc_time_t a;
	isc_time_t b;
	int64_t r;
};

const struct compare_vectors vectors_compare[] = {
	{ { 0, 0 }, { 0, 0 }, 0 },
	{ { 1, 0 }, { 0, 0 }, 1 },
	{ { 0, 0 }, { 1, 0 }, -1 },

	{ { 0, 1 }, { 0, 1 }, 0 },
	{ { 0, 1 }, { 0, 0 }, 1 },
	{ { 0, 0 }, { 0, 1 }, -1 },

	{ { 0, 0 }, { MAX_N, MAX_NS }, -1 },
	{ { MAX_N, MAX_NS }, { 0, 0 }, 1 },
	{ { MAX_N, MAX_NS }, { MAX_N, MAX_NS }, 0 },

	{ { 1, 0 }, { 0, MAX_NS }, 1 },
	{ { 0, MAX_NS }, { 1, 0 }, -1 }
};

static void
isc_time_compare_test(void **state) {
	UNUSED(state);

	for (size_t i = 0; i < ARRAY_SIZE(vectors_compare); i++) {
		int r = isc_time_compare(&(vectors_compare[i].a),
					 &(vectors_compare[i].b));
		assert_int_equal(vectors_compare[i].r, r);
	}

	/* Invalid first argument */
	expect_assert_failure((void)isc_time_compare((isc_time_t *)NULL,
						     &(isc_time_t){ 0, 0 }));

	expect_assert_failure((void)isc_time_compare(
		&(isc_time_t){ 0, MAX_NS + 1 }, &(isc_time_t){ 0, 0 }));

	/* Invalid second argument */
	expect_assert_failure((void)isc_time_compare(&(isc_time_t){ 0, 0 },
						     (isc_time_t *)NULL));

	expect_assert_failure((void)isc_time_compare(
		&(isc_time_t){ 0, 0 }, &(isc_time_t){ 0, MAX_NS + 1 }));
}

#define MAX_NS_PER_US	 (MAX_NS / NS_PER_US)
#define MAX_MICRODIFF_N	 (MAX_N + 0LL)
#define MAX_MICRODIFF_US (MAX_N + 0LL) * US_PER_S

const struct compare_vectors vectors_microdiff[] = {
	{ { 0, 0 }, { 0, 0 }, 0 },
	{ { 1, 0 }, { 0, 0 }, 1 * US_PER_S },
	{ { 0, 0 }, { 1, 0 }, 0 },

	{ { 0, 1 }, { 0, 1 }, 0 },
	{ { 0, 1 }, { 0, 0 }, 0 },
	{ { 0, 0 }, { 0, 1 }, 0 },

	{ { 0, NS_PER_US }, { 0, NS_PER_US }, 0 },
	{ { 0, NS_PER_US }, { 0, 0 }, 1 },
	{ { 0, 0 }, { 0, NS_PER_US }, 0 },

	{ { 0, 0 }, { MAX_MICRODIFF_N, MAX_NS }, 0 },
	{ { MAX_MICRODIFF_N, MAX_NS },
	  { 0, 0 },
	  MAX_MICRODIFF_US + MAX_NS_PER_US },
	{ { MAX_MICRODIFF_N, MAX_NS }, { MAX_MICRODIFF_N, MAX_NS }, 0 },

	{ { 1, 0 }, { 0, MAX_NS }, 0 },
	{ { 0, MAX_NS }, { 1, 0 }, 0 }
};

static void
isc_time_microdiff_test(void **state) {
	UNUSED(state);

	for (size_t i = 0; i < ARRAY_SIZE(vectors_microdiff); i++) {
		int64_t r = isc_time_microdiff(&(vectors_microdiff[i].a),
					       &(vectors_microdiff[i].b));
		assert_int_equal(vectors_microdiff[i].r, r);
	}

	/* Invalid first argument */
	expect_assert_failure((void)isc_time_microdiff((isc_time_t *)NULL,
						       &(isc_time_t){ 0, 0 }));

	expect_assert_failure((void)isc_time_microdiff(
		&(isc_time_t){ 0, MAX_NS + 1 }, &(isc_time_t){ 0, 0 }));

	/* Invalid second argument */
	expect_assert_failure((void)isc_time_microdiff(&(isc_time_t){ 0, 0 },
						       (isc_time_t *)NULL));

	expect_assert_failure((void)isc_time_microdiff(
		&(isc_time_t){ 0, 0 }, &(isc_time_t){ 0, MAX_NS + 1 }));
}

static void
isc_time_formattimestamp_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATTIMESTAMP_SIZE];

	UNUSED(state);

	/*
	 * The second least population is at UTC+08:45 that covers village of
	 * Eucla and other villages in Australia with a population of around
	 * 200. The area is surrounded by signs to remind you to turn your
	 * clocks, but it is unofficial so it might not comply either.
	 */
	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	memset(buf, 'X', sizeof(buf));
	isc_time_formattimestamp(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);

	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formattimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "01-Jan-1970 08:45:00.000");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formattimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "13-Dec-2015 18:31:40.123");

	expect_assert_failure(isc_time_formattimestamp(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formattimestamp(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formattimestamp(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formattimestamp(&t, buf, sizeof(buf) - 1));
}

/* parse http time stamp */
static void
isc_time_parsehttptimestamp_test(void **state) {
	isc_time_t t, x;
	char buf[ISC_FORMATHTTPTIMESTAMP_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	isc_time_formathttptimestamp(&t, buf, sizeof(buf));
	assert_int_equal(isc_time_parsehttptimestamp(buf, &x), ISC_R_SUCCESS);
	assert_int_equal(isc_time_seconds(&t), isc_time_seconds(&x));

	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formathttptimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "Thu, 01 Jan 1970 00:00:00 GMT");
	assert_int_equal(isc_time_parsehttptimestamp(buf, &x), ISC_R_SUCCESS);
	assert_int_equal(isc_time_seconds(&t), isc_time_seconds(&x));

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formathttptimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "Sun, 13 Dec 2015 09:46:40 GMT");
	assert_int_equal(isc_time_parsehttptimestamp(buf, &x), ISC_R_SUCCESS);
	assert_int_equal(isc_time_seconds(&t), isc_time_seconds(&x));

	expect_assert_failure(
		isc_time_formathttptimestamp(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formathttptimestamp(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formathttptimestamp(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formathttptimestamp(&t, buf, sizeof(buf) - 1));

	expect_assert_failure(isc_time_parsehttptimestamp(buf, NULL));
	expect_assert_failure(isc_time_parsehttptimestamp(NULL, &t));
}

/* print UTC in ISO8601 */
static void
isc_time_formatISO8601_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ssZ */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');
	assert_int_equal(buf[19], 'Z');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T00:00:00Z");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formatISO8601(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T09:46:40Z");

	expect_assert_failure(isc_time_formatISO8601(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601(&t, NULL, 0));
	expect_assert_failure(isc_time_formatISO8601(&t, buf, sizeof(buf) - 1));
}

/* print UTC in ISO8601 with milliseconds */
static void
isc_time_formatISO8601ms_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601MS_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ss.sssZ */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601ms(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');
	assert_int_equal(buf[19], '.');
	assert_int_equal(buf[23], 'Z');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601ms(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T00:00:00.000Z");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formatISO8601ms(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T09:46:40.123Z");

	expect_assert_failure(isc_time_formatISO8601ms(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601ms(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601ms(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatISO8601ms(&t, buf, sizeof(buf) - 1));
}

/* print UTC in ISO8601 with microseconds */
static void
isc_time_formatISO8601us_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601US_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now_hires(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ss.ssssssZ */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601us(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');
	assert_int_equal(buf[19], '.');
	assert_int_equal(buf[26], 'Z');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601us(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T00:00:00.000000Z");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123456000);
	isc_time_formatISO8601us(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T09:46:40.123456Z");

	expect_assert_failure(isc_time_formatISO8601us(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601us(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601us(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatISO8601us(&t, buf, sizeof(buf) - 1));
}

/* print local time in ISO8601 */
static void
isc_time_formatISO8601L_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601L_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ss */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601L(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601L(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T08:45:00");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formatISO8601L(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T18:31:40");

	expect_assert_failure(isc_time_formatISO8601L(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601L(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601L(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatISO8601L(&t, buf, sizeof(buf) - 1));
}

/* print local time in ISO8601 with milliseconds */
static void
isc_time_formatISO8601Lms_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601LMS_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ss.sss */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601Lms(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');
	assert_int_equal(buf[19], '.');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601Lms(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T08:45:00.000");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formatISO8601Lms(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T18:31:40.123");

	expect_assert_failure(
		isc_time_formatISO8601Lms(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601Lms(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601Lms(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatISO8601Lms(&t, buf, sizeof(buf) - 1));
}

/* print local time in ISO8601 with microseconds */
static void
isc_time_formatISO8601Lus_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATISO8601LUS_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now_hires(&t);

	/* check formatting: yyyy-mm-ddThh:mm:ss.ssssss */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatISO8601Lus(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);
	assert_int_equal(buf[4], '-');
	assert_int_equal(buf[7], '-');
	assert_int_equal(buf[10], 'T');
	assert_int_equal(buf[13], ':');
	assert_int_equal(buf[16], ':');
	assert_int_equal(buf[19], '.');

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatISO8601Lus(&t, buf, sizeof(buf));
	assert_string_equal(buf, "1970-01-01T08:45:00.000000");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123456000);
	isc_time_formatISO8601Lus(&t, buf, sizeof(buf));
	assert_string_equal(buf, "2015-12-13T18:31:40.123456");

	expect_assert_failure(
		isc_time_formatISO8601Lus(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601Lus(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatISO8601Lus(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatISO8601Lus(&t, buf, sizeof(buf) - 1));
}

/* print UTC time as yyyymmddhhmmsssss */
static void
isc_time_formatshorttimestamp_test(void **state) {
	isc_time_t t = { 0, 0 };
	char buf[ISC_FORMATSHORTTIMESTAMP_SIZE];

	UNUSED(state);

	setenv("TZ", "Australia/Eucla", 1);
	isc_time_now(&t);

	/* check formatting: yyyymmddhhmmsssss */
	memset(buf, 'X', sizeof(buf));
	isc_time_formatshorttimestamp(&t, buf, sizeof(buf));
	assert_int_equal(strlen(buf), sizeof(buf) - 1);

	/* check time conversion correctness */
	memset(buf, 'X', sizeof(buf));
	isc_time_settoepoch(&t);
	isc_time_formatshorttimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "19700101000000000");

	memset(buf, 'X', sizeof(buf));
	isc_time_set(&t, 1450000000, 123000000);
	isc_time_formatshorttimestamp(&t, buf, sizeof(buf));
	assert_string_equal(buf, "20151213094640123");

	expect_assert_failure(
		isc_time_formatshorttimestamp(NULL, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatshorttimestamp(
		&(isc_time_t){ 0, MAX_NS + 1 }, buf, sizeof(buf)));
	expect_assert_failure(isc_time_formatshorttimestamp(&t, NULL, 0));
	expect_assert_failure(
		isc_time_formatshorttimestamp(&t, buf, sizeof(buf) - 1));
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(isc_interval_basic_test),
		cmocka_unit_test(isc_time_basic_test),
		cmocka_unit_test(isc_time_now_test),
		cmocka_unit_test(isc_time_add_test),
		cmocka_unit_test(isc_time_sub_test),
		cmocka_unit_test(isc_time_compare_test),
		cmocka_unit_test(isc_time_microdiff_test),
		cmocka_unit_test(isc_time_formattimestamp_test),
		cmocka_unit_test(isc_time_parsehttptimestamp_test),
		cmocka_unit_test(isc_time_formatISO8601_test),
		cmocka_unit_test(isc_time_formatISO8601ms_test),
		cmocka_unit_test(isc_time_formatISO8601us_test),
		cmocka_unit_test(isc_time_formatISO8601L_test),
		cmocka_unit_test(isc_time_formatISO8601Lms_test),
		cmocka_unit_test(isc_time_formatISO8601Lus_test),
		cmocka_unit_test(isc_time_formatshorttimestamp_test),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */

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

/*! \file */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h> /* Required for struct timeval on some platforms. */
#include <syslog.h>
#include <time.h>

#include <isc/log.h>
#include <isc/print.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#define NS_PER_S  1000000000 /*%< Nanoseconds per second. */
#define NS_PER_US 1000	     /*%< Nanoseconds per microsecond. */
#define NS_PER_MS 1000000    /*%< Nanoseconds per millisecond. */
#define MS_PER_S  1000	     /*%< Milliseonds per second. */

#if defined(CLOCK_REALTIME)
#define CLOCKSOURCE_HIRES CLOCK_REALTIME
#endif /* #if defined(CLOCK_REALTIME) */

#if defined(CLOCK_REALTIME_COARSE)
#define CLOCKSOURCE CLOCK_REALTIME_COARSE
#elif defined(CLOCK_REALTIME_FAST)
#define CLOCKSOURCE CLOCK_REALTIME_FAST
#else /* if defined(CLOCK_REALTIME_COARSE) */
#define CLOCKSOURCE CLOCK_REALTIME
#endif /* if defined(CLOCK_REALTIME_COARSE) */

#if !defined(CLOCKSOURCE_HIRES)
#define CLOCKSOURCE_HIRES CLOCKSOURCE
#endif /* #ifndef CLOCKSOURCE_HIRES */

/*%
 *** Intervals
 ***/

#if !defined(UNIT_TESTING)
static const isc_interval_t zero_interval = { 0, 0 };
const isc_interval_t *const isc_interval_zero = &zero_interval;
#endif

void
isc_interval_set(isc_interval_t *i, uint64_t seconds, uint64_t nanoseconds) {
	REQUIRE(i != NULL);
	REQUIRE(nanoseconds < NS_PER_S);

	i->seconds = seconds;
	i->nanoseconds = nanoseconds;
}

bool
isc_interval_iszero(const isc_interval_t *i) {
	REQUIRE(i != NULL);
	REQUIRE(i->nanoseconds < NS_PER_S);

	return (i->seconds == 0 && i->nanoseconds == 0);
}

uint64_t
isc_interval_ms(const isc_interval_t *i) {
	REQUIRE(i != NULL);
	REQUIRE(i->nanoseconds < NS_PER_S);

	return ((i->seconds * MS_PER_S) + (i->nanoseconds / NS_PER_MS));
}

/***
 *** Absolute Times
 ***/

#if !defined(UNIT_TESTING)
static const isc_time_t epoch = { 0, 0 };
const isc_time_t *const isc_time_epoch = &epoch;
#endif

void
isc_time_set(isc_time_t *t, uint64_t seconds, uint64_t nanoseconds) {
	REQUIRE(t != NULL);
	REQUIRE(nanoseconds < NS_PER_S);

	t->seconds = seconds;
	t->nanoseconds = nanoseconds;
}

void
isc_time_settoepoch(isc_time_t *t) {
	REQUIRE(t != NULL);

	t->seconds = 0;
	t->nanoseconds = 0;
}

bool
isc_time_isepoch(const isc_time_t *t) {
	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);

	return (t->seconds == 0 && t->nanoseconds == 0);
}

/* It will be some time before we switch to 128-time */
STATIC_ASSERT(sizeof(time_t) <= 8,
	      "BIND 9 is not ready for time_t larger than 64-bits");

static inline void
time_now(isc_time_t *t, clockid_t clock) {
	struct timespec ts;

	REQUIRE(t != NULL);

	if (clock_gettime(clock, &ts) == -1) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(errno, strbuf, sizeof(strbuf));
		isc_error_fatal(__FILE__, __LINE__, "clock_gettime failed: %s",
				strbuf);
	}

	INSIST(ts.tv_sec >= 0);
	INSIST(ts.tv_nsec >= 0);
	INSIST(ts.tv_nsec < NS_PER_S);

	t->seconds = ts.tv_sec;
	t->nanoseconds = ts.tv_nsec;
}

void
isc_time_now_hires(isc_time_t *t) {
	return (time_now(t, CLOCKSOURCE_HIRES));
}

void
isc_time_now(isc_time_t *t) {
	return (time_now(t, CLOCKSOURCE));
}

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, const isc_interval_t *i) {
	isc_time_t now;

	REQUIRE(t != NULL);
	REQUIRE(i != NULL);
	INSIST(i->nanoseconds < NS_PER_S);

	isc_time_now(&now);
	return (isc_time_add(&now, i, t));
}

int
isc_time_compare(const isc_time_t *t1, const isc_time_t *t2) {
	REQUIRE(t1 != NULL && t2 != NULL);
	INSIST(t1->nanoseconds < NS_PER_S && t2->nanoseconds < NS_PER_S);

	if (t1->seconds < t2->seconds) {
		return (-1);
	}
	if (t1->seconds > t2->seconds) {
		return (1);
	}
	if (t1->nanoseconds < t2->nanoseconds) {
		return (-1);
	}
	if (t1->nanoseconds > t2->nanoseconds) {
		return (1);
	}
	return (0);
}

isc_result_t
isc_time_add(const isc_time_t *t, const isc_interval_t *i, isc_time_t *result) {
	REQUIRE(t != NULL && i != NULL && result != NULL);
	REQUIRE(t->nanoseconds < NS_PER_S && i->nanoseconds < NS_PER_S);

	/* Seconds */
#if HAVE_BUILTIN_OVERFLOW
	if (__builtin_uaddll_overflow(t->seconds, i->seconds, &result->seconds))
	{
		return (ISC_R_RANGE);
	}
#else
	if (t->seconds > UINT64_MAX - i->seconds) {
		return (ISC_R_RANGE);
	}
	result->seconds = t->seconds + i->seconds;
#endif

	/* Nanoseconds */
	result->nanoseconds = t->nanoseconds + i->nanoseconds;
	if (result->nanoseconds >= NS_PER_S) {
		if (result->seconds == UINT64_MAX) {
			return (ISC_R_RANGE);
		}
		result->nanoseconds -= NS_PER_S;
		result->seconds++;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_subtract(const isc_time_t *t, const isc_interval_t *i,
		  isc_time_t *result) {
	REQUIRE(t != NULL && i != NULL && result != NULL);
	REQUIRE(t->nanoseconds < NS_PER_S && i->nanoseconds < NS_PER_S);

	/* Seconds */
#if HAVE_BUILTIN_OVERFLOW
	if (__builtin_usubll_overflow(t->seconds, i->seconds, &result->seconds))
	{
		return (ISC_R_RANGE);
	}
#else
	if (t->seconds < i->seconds) {
		return (ISC_R_RANGE);
	}
	result->seconds = t->seconds - i->seconds;
#endif

	/* Nanoseconds */
	if (t->nanoseconds >= i->nanoseconds) {
		result->nanoseconds = t->nanoseconds - i->nanoseconds;
	} else {
		if (result->seconds == 0) {
			return (ISC_R_RANGE);
		}
		result->seconds--;
		result->nanoseconds = NS_PER_S + t->nanoseconds -
				      i->nanoseconds;
	}

	return (ISC_R_SUCCESS);
}

uint64_t
isc_time_microdiff(const isc_time_t *t1, const isc_time_t *t2) {
	REQUIRE(t1 != NULL && t2 != NULL);
	INSIST(t1->nanoseconds < NS_PER_S && t2->nanoseconds < NS_PER_S);

	if (t1->seconds <= t2->seconds) {
		return (0);
	}

	if (t1->nanoseconds < t2->nanoseconds) {
		/* Adjustment for the nanosecond */
		if (t1->seconds - t2->seconds <= 1) {
			return (0);
		}

		return (t1->seconds - t2->seconds - 1);
	}

	return (t1->seconds - t2->seconds);
}

uint64_t
isc_time_seconds(const isc_time_t *t) {
	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);

	return ((uint32_t)t->seconds);
}

uint64_t
isc_time_nanoseconds(const isc_time_t *t) {
	REQUIRE(t != NULL);

	ENSURE(t->nanoseconds < NS_PER_S);

	return ((uint64_t)t->nanoseconds);
}

typedef struct tm *(*isc__time_func)(const time_t *restrict,
				     struct tm *restrict);

static size_t
time_format(const isc_time_t *t, char *buf, size_t len, const char *format,
	    isc__time_func time_r) {
	time_t now;
	struct tm tm_s, *tm = &tm_s;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	if ((uint64_t)now != t->seconds) {
		return (0);
	}

	tm = (*time_r)(&now, tm);

	return (strftime(buf, len, format, tm));
}

static void
time_format_ms(const isc_time_t *t, char *buf, size_t len, const char *prefix,
	       const char *suffix) {
	if (len < 5) {
		/* Not enough space to print "." + 0-999 range + "Z" */
		return;
	}
	snprintf(buf, len, "%s%03" PRIu64 "%s", prefix,
		 t->nanoseconds / NS_PER_MS, suffix);
}

static void
time_format_us(const isc_time_t *t, char *buf, size_t len, const char *prefix,
	       const char *suffix) {
	if (len < 8) {
		/* Not enough space to print "." + 0-999999 range + "Z" */
		return;
	}

	snprintf(buf, len, "%s%06" PRIu64 "%s", prefix,
		 t->nanoseconds / NS_PER_US, suffix);
}

void
isc_time_formattimestamp(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%d-%b-%Y %X", localtime_r);
	if (flen == 0) {
		strlcpy(buf, "99-Bad-9999 99:99:99.999", len);
		return;
	}

	time_format_ms(t, buf + flen, len - flen, ".", "");
}

void
isc_time_formathttptimestamp(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%a, %d %b %Y %H:%M:%S GMT", gmtime_r);
	if (flen == 0) {
		strlcpy(buf, "Bad, 99 Bad 9999 99:99:99 GMT", len);
		return;
	}
}
isc_result_t
isc_time_parsehttptimestamp(char *buf, isc_time_t *t) {
	struct tm t_tm;
	time_t when;
	char *p;

	REQUIRE(buf != NULL);
	REQUIRE(t != NULL);

	p = strptime(buf, "%a, %d %b %Y %H:%M:%S", &t_tm);
	if (p == NULL) {
		return (ISC_R_UNEXPECTED);
	}
	when = timegm(&t_tm);
	if (when == -1) {
		return (ISC_R_UNEXPECTED);
	}
	isc_time_set(t, when, 0);
	return (ISC_R_SUCCESS);
}

void
isc_time_formatISO8601L(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%S", localtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99", len);
		return;
	}
}

void
isc_time_formatISO8601Lms(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%S", localtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99.999", len);
		return;
	}

	time_format_ms(t, buf + flen, len - flen, ".", "");
}

void
isc_time_formatISO8601Lus(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%S", localtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99.999999", len);
		return;
	}

	time_format_us(t, buf + flen, len - flen, ".", "");
}

void
isc_time_formatISO8601(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%SZ", gmtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99", len);
		return;
	}
}

void
isc_time_formatISO8601ms(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	/* Skip the "Z" at the end, it will be appended later */
	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%S", gmtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99.999Z", len);
		return;
	}

	time_format_ms(t, buf + flen, len - flen, ".", "Z");
}

void
isc_time_formatISO8601us(const isc_time_t *t, char *buf, unsigned int len) {
	size_t flen;

	/* Skip the "Z" at the end, it will be appended later */
	flen = time_format(t, buf, len, "%Y-%m-%dT%H:%M:%S", gmtime_r);
	if (flen == 0) {
		strlcpy(buf, "9999-Bad-99T99:99:99.999999Z", len);
		return;
	}

	time_format_us(t, buf + flen, len - flen, ".", "Z");
}

void
isc_time_formatshorttimestamp(const isc_time_t *t, char *buf,
			      unsigned int len) {
	size_t flen;

	flen = time_format(t, buf, len, "%Y%m%d%H%M%S", gmtime_r);
	if (flen == 0) {
		strlcpy(buf, "99999999999999999", len);
		return;
	}

	time_format_ms(t, buf + flen, len - flen, "", "");
}

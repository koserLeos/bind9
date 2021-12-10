/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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
#include <unistd.h>

#include <isc/condition.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#ifdef ISC_TRACK_PTHREADS_OBJECTS

#include <stdlib.h>

struct isc_condition_tracker {
	ISC_LINK(isc_condition_tracker_t) link;
	const char *file;
	int line;
};

static pthread_mutex_t conditionslock = PTHREAD_MUTEX_INITIALIZER;
static ISC_LIST(isc_condition_tracker_t) conditions = { NULL, NULL };

void
isc_condition_init_track(isc_condition_t *c, const char *file, int line) {
	isc__condition_init(&c->cond);

	c->tracker = malloc(sizeof(*c->tracker));
	INSIST(c->tracker != NULL);
	c->tracker->file = file;
	c->tracker->line = line;

	pthread_mutex_lock(&conditionslock);
	ISC_LIST_INITANDAPPEND(conditions, c->tracker, link);
	pthread_mutex_unlock(&conditionslock);
}

isc_result_t
isc_condition_destroy_track(isc_condition_t *c) {
	INSIST(c->tracker != NULL);

	pthread_mutex_lock(&conditionslock);
	ISC_LIST_UNLINK(conditions, c->tracker, link);
	pthread_mutex_unlock(&conditionslock);

	free(c->tracker);
	c->tracker = NULL;

	return (isc__condition_destroy(&c->cond));
}

void
isc_condition_check_track(void) {
	pthread_mutex_lock(&conditionslock);
	if (!ISC_LIST_EMPTY(conditions)) {
		isc_condition_tracker_t *t;
		fprintf(stderr,
			"isc_condition_init/isc_condition_destroy mismatch\n");
		for (t = ISC_LIST_HEAD(conditions); t != NULL;
		     t = ISC_LIST_NEXT(t, link)) {
			fprintf(stderr, "condition %s:%d\n", t->file, t->line);
		}

		abort();
	}
	pthread_mutex_unlock(&conditionslock);
}

#endif

isc_result_t
isc_condition_waituntil(isc_condition_t *c, isc_mutex_t *m, isc_time_t *t) {
	int presult;
	isc_result_t result;
	struct timespec ts;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(c != NULL && m != NULL && t != NULL);

	/*
	 * POSIX defines a timespec's tv_sec as time_t.
	 */
	result = isc_time_secondsastimet(t, &ts.tv_sec);

	/*
	 * If we have a range error ts.tv_sec is most probably a signed
	 * 32 bit value.  Set ts.tv_sec to INT_MAX.  This is a kludge.
	 */
	if (result == ISC_R_RANGE) {
		ts.tv_sec = INT_MAX;
	} else if (result != ISC_R_SUCCESS) {
		return (result);
	}

	/*!
	 * POSIX defines a timespec's tv_nsec as long.  isc_time_nanoseconds
	 * ensures its return value is < 1 billion, which will fit in a long.
	 */
	ts.tv_nsec = (long)isc_time_nanoseconds(t);

	do {
		pthread_cond_t *cond;
		pthread_mutex_t *mutex;

#ifdef ISC_TRACK_PTHREADS_OBJECTS
		cond = &c->cond;
#else  /* ISC_TRACK_PTHREADS_OBJECTS */
		cond = c;
#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#ifdef ISC_TRACK_PTHREADS_OBJECTS
		mutex = &m->mutex;
#else  /* ISC_TRACK_PTHREADS_OBJECTS */
		mutex = m;
#endif /* ISC_TRACK_PTHREADS_OBJECTS */

		presult = pthread_cond_timedwait(cond, mutex, &ts);
		if (presult == 0) {
			return (ISC_R_SUCCESS);
		}
		if (presult == ETIMEDOUT) {
			return (ISC_R_TIMEDOUT);
		}
	} while (presult == EINTR);

	strerror_r(presult, strbuf, sizeof(strbuf));
	UNEXPECTED_ERROR(__FILE__, __LINE__,
			 "pthread_cond_timedwait() returned %s", strbuf);
	return (ISC_R_UNEXPECTED);
}

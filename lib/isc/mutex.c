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
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

#ifdef ISC_TRACK_PTHREADS_OBJECTS

#include <stdlib.h>

struct isc_mutex_tracker {
	ISC_LINK(isc_mutex_tracker_t) link;
	const char *file;
	int line;
};

static pthread_mutex_t mutexeslock = PTHREAD_MUTEX_INITIALIZER;
static ISC_LIST(isc_mutex_tracker_t) mutexes = { NULL, NULL };

void
isc_mutex_init_track(isc_mutex_t *m, const char *file, int line) {
	RUNTIME_CHECK(pthread_mutex_init(&m->mutex, NULL) == 0);

	m->tracker = malloc(sizeof(*m->tracker));
	INSIST(m->tracker != NULL);
	m->tracker->file = file;
	m->tracker->line = line;

	pthread_mutex_lock(&mutexeslock);
	ISC_LIST_INITANDAPPEND(mutexes, m->tracker, link);
	pthread_mutex_unlock(&mutexeslock);
}

void
isc_mutex_destroy_track(isc_mutex_t *m) {
	INSIST(m->tracker != NULL);
	pthread_mutex_lock(&mutexeslock);
	ISC_LIST_UNLINK(mutexes, m->tracker, link);
	pthread_mutex_unlock(&mutexeslock);
	free(m->tracker);
	m->tracker = NULL;
	RUNTIME_CHECK(pthread_mutex_destroy(&m->mutex) == 0);
}

void
isc_mutex_check_track(void) {
	pthread_mutex_lock(&mutexeslock);
	if (!ISC_LIST_EMPTY(mutexes)) {
		isc_mutex_tracker_t *t;
		fprintf(stderr, "isc_mutex_init/isc_mutext_destroy mismatch\n");
		for (t = ISC_LIST_HEAD(mutexes); t != NULL;
		     t = ISC_LIST_NEXT(t, link)) {
			fprintf(stderr, "mutex %s:%d\n", t->file, t->line);
		}

		abort();
	}
	pthread_mutex_unlock(&mutexeslock);
}

#else /* ISC_TRACK_PTHREADS_OBJECTS */

#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
static bool attr_initialized = false;
static pthread_mutexattr_t attr;
static isc_once_t once_attr = ISC_ONCE_INIT;

static void
initialize_attr(void) {
	RUNTIME_CHECK(pthread_mutexattr_init(&attr) == 0);
	RUNTIME_CHECK(pthread_mutexattr_settype(
			      &attr, PTHREAD_MUTEX_ADAPTIVE_NP) == 0);
	attr_initialized = true;
}
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */

void
isc_mutex_init_location(isc_mutex_t *mp, const char *file, unsigned int line) {
	int err;

#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
	isc_result_t result = ISC_R_SUCCESS;
	result = isc_once_do(&once_attr, initialize_attr);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	err = pthread_mutex_init(mp, &attr);
#else  /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
	err = pthread_mutex_init(mp, NULL);
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
	if (err != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}
}

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

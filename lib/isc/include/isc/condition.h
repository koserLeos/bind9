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

#pragma once

/*! \file */

#include <errno.h>

#include <isc/error.h>
#include <isc/lang.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/types.h>

#ifdef ISC_TRACK_PTHREADS_OBJECTS

typedef struct isc_condition_tracker isc_condition_tracker_t;

typedef struct {
	pthread_cond_t		 cond;
	isc_condition_tracker_t *tracker;
} isc_condition_t;

void
isc_condition_init_track(isc_condition_t *c, const char *file, int line);

isc_result_t
isc_condition_destroy_track(isc_condition_t *);

void
isc_condition_check_track(void);

#define isc_condition_init(cond) \
	isc_condition_init_track(cond, __FILE__, __LINE__)
#define isc_condition_wait(cp, mp) \
	isc__condition_wait(&(cp)->cond, &(mp)->mutex)
#define isc_condition_signal(cp)    isc__condition_signal(&(cp)->cond)
#define isc_condition_broadcast(cp) isc__condition_broadcast(&(cp)->cond)
#define isc_condition_destroy(cp)   isc_condition_destroy_track(cp)

#else /* ISC_TRACK_PTHREADS_OBJECTS */

typedef pthread_cond_t isc_condition_t;

#define isc_condition_init(cond)    isc__condition_init(cond)
#define isc_condition_wait(cp, mp)  isc__condition_wait(cp, mp)
#define isc_condition_signal(cp)    isc__condition_signal(cp)
#define isc_condition_broadcast(cp) isc__condition_broadcast(cp)
#define isc_condition_destroy(cp)   isc__condition_destroy(cp)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__condition_init(cond)                               \
	if (pthread_cond_init(cond, NULL) != 0) {               \
		char isc_condition_strbuf[ISC_STRERRORSIZE];    \
		strerror_r(errno, isc_condition_strbuf,         \
			   sizeof(isc_condition_strbuf));       \
		isc_error_fatal(__FILE__, __LINE__,             \
				"pthread_cond_init failed: %s", \
				isc_condition_strbuf);          \
	}

#define isc__condition_wait(cp, mp)                           \
	((pthread_cond_wait((cp), (mp)) == 0) ? ISC_R_SUCCESS \
					      : ISC_R_UNEXPECTED)

#define isc__condition_signal(cp) \
	((pthread_cond_signal((cp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc__condition_broadcast(cp) \
	((pthread_cond_broadcast((cp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc__condition_destroy(cp) \
	((pthread_cond_destroy((cp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

ISC_LANG_BEGINDECLS

isc_result_t
isc_condition_waituntil(isc_condition_t *, isc_mutex_t *, isc_time_t *);

ISC_LANG_ENDDECLS

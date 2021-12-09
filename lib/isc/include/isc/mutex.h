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

#include <pthread.h>
#include <stdio.h>

#include <isc/lang.h>
#include <isc/result.h> /* for ISC_R_ codes */

ISC_LANG_BEGINDECLS

#ifdef ISC_TRACK_PTHREADS_OBJECTS

typedef struct {
	pthread_mutex_t mutex;
	void	     *tracker;
} isc_mutex_t;

void
isc_mutex_init_track(isc_mutex_t *m);

void
isc_mutex_destroy_track(isc_mutex_t *m);

#define isc_mutex_init(mp)    isc_mutex_init_track(mp)
#define isc_mutex_lock(mp)    isc__mutex_lock(&(mp)->mutex)
#define isc_mutex_unlock(mp)  isc__mutex_unlock(&(mp)->mutex)
#define isc_mutex_trylock(mp) isc__mutex_trylock(&(mp)->mutex)
#define isc_mutex_destroy(mp) isc_mutex_destroy_track(mp)

#else /* ISC_TRACK_PTHREADS_OBJECTS */

typedef pthread_mutex_t isc_mutex_t;

void
isc_mutex_init_location(isc_mutex_t *mp, const char *file, unsigned int line);

#define isc_mutex_init(mp)    isc_mutex_init_location((mp), __FILE__, __LINE__)
#define isc_mutex_lock(mp)    isc__mutex_lock(mp)
#define isc_mutex_unlock(mp)  isc__mutex_unlock(mp)
#define isc_mutex_trylock(mp) isc__mutex_trylock(mp)
#define isc_mutex_destroy(mp) RUNTIME_CHECK(pthread_mutex_destroy((mp)) == 0)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc__mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc__mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_LOCKBUSY)

ISC_LANG_ENDDECLS

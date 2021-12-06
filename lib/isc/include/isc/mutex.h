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

/* DROPME */
#define ISC_MUTEX_DEBUG 1

/*!
 * Define ISC_MUTEX_PROFILE to turn on profiling of mutexes by line.  When
 * enabled, isc_mutex_stats() can be used to print a table showing the
 * number of times each type of mutex was locked and the amount of time
 * waiting to obtain the lock.
 */
#ifndef ISC_MUTEX_PROFILE
#define ISC_MUTEX_PROFILE 0
#endif /* ifndef ISC_MUTEX_PROFILE */

#if defined(ISC_MUTEX_DEBUG)

typedef pthread_mutex_t isc_mutex_t;

#define isc_mutex_init(mp) \
	isc_mutex_init_debug((mp), __func__, __FILE__, __LINE__)
#define isc_mutex_destroy(mp) \
	isc_mutex_destroy_debug((mp), __func__, __FILE__, __LINE__)
void
isc_mutex_init_debug(isc_mutex_t *mp, const char *func, const char *file,
		     unsigned int line);

void
isc_mutex_destroy_debug(isc_mutex_t *mp, const char *func, const char *file,
			unsigned int line);

#elif ISC_MUTEX_PROFILE

typedef struct isc_mutexstats isc_mutexstats_t;

typedef struct {
	pthread_mutex_t	  mutex; /*%< The actual mutex. */
	isc_mutexstats_t *stats; /*%< Mutex statistics. */
} isc_mutex_t;

#define isc_mutex_init(mp) isc_mutex_init_profile((mp), __FILE__, __LINE__)
#define isc_mutex_destroy(mp) \
	RUNTIME_CHECK(pthread_mutex_destroy((&(mp)->mutex)) == 0)

void
isc_mutex_init_profile(isc_mutex_t *mp, const char *_file, int _line);

#else

typedef pthread_mutex_t isc_mutex_t;

#define isc_mutex_init(mp)    isc__mutex_init((mp), __FILE__, __LINE__)
void
isc__mutex_init(isc_mutex_t *mp, const char *file, unsigned int line);
#define isc_mutex_destroy(mp) RUNTIME_CHECK(pthread_mutex_destroy((mp)) == 0)

#endif

#if ISC_MUTEX_PROFILE

#define isc_mutex_lock(mp) isc_mutex_lock_profile((mp), __FILE__, __LINE__)
isc_result_t
isc_mutex_lock_profile(isc_mutex_t *mp, const char *_file, int _line);

#define isc_mutex_unlock(mp) isc_mutex_unlock_profile((mp), __FILE__, __LINE__)
isc_result_t
isc_mutex_unlock_profile(isc_mutex_t *mp, const char *_file, int _line);

#define isc_mutex_trylock(mp)                                         \
	((pthread_mutex_trylock((&(mp)->mutex)) == 0) ? ISC_R_SUCCESS \
						      : ISC_R_LOCKBUSY)

#define isc_mutex_stats(fp) isc_mutex_statsprofile(fp);
void
isc_mutex_statsprofile(FILE *fp);

#else

#define isc_mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_LOCKBUSY)

#define isc_mutex_stats(fp)

#endif

ISC_LANG_ENDDECLS

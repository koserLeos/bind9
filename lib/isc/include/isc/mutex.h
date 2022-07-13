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

#pragma once

/*! \file */

#include <pthread.h>
#include <stdio.h>

#include <isc/lang.h>
#include <isc/result.h> /* for ISC_R_ codes */

ISC_LANG_BEGINDECLS

typedef pthread_mutex_t isc_mutex_t;

void
isc__mutex_init(isc_mutex_t *mp);

#define isc_mutex_init(mp) isc__mutex_init((mp))

#define isc_mutex_lock(mp) RUNTIME_CHECK(pthread_mutex_lock((mp)) == 0)

#define isc_mutex_unlock(mp) RUNTIME_CHECK(pthread_mutex_unlock((mp)) == 0)

#define isc_mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_LOCKBUSY)

#define isc_mutex_destroy(mp) RUNTIME_CHECK(pthread_mutex_destroy((mp)) == 0)

ISC_LANG_ENDDECLS

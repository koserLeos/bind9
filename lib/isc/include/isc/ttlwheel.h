/*
 * Copyright (C) Internet Systems Consortium, Inc. (`ISC`)
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

#include <stdint.h>

#include <isc/stdtime.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

typedef struct isc_ttlwheel isc_ttlwheel_t;

typedef void (*isc_ttlwheel_popaction_t)(void *user, void *data);

void
isc_ttlwheel_create(isc_mem_t *mctx, isc_stdtime_t now,
		    isc_ttlwheel_t **wheelp);
/*%<
 * Creates a new TTL wheel.
 *
 * Requires:
 * \li	`mctx` is valid.
 * \li	`now` is the starting point where TTL wheel will start expiring from.
 * \li	`wheelp != NULL && *wheelp == NULL`
 *
 * Ensures:
 * \li `*wheelp` is a pointer to a valid isc_ttlwheel_t.
 */

void
isc_ttlwheel_destroy(isc_ttlwheel_t **wheelp);
/*%<
 * Destroys a TTL wheel.
 *
 * Requires:
 * \li `wheelp != NULL` and `*wheel` points to a valid isc_ttlwheel_t.
 */

isc_stdtime_t
isc_ttlwheel_epoch(isc_ttlwheel_t *wheel);
/*%<
 * Returns the epoch.
 *
 * Requires:
 * \li	`wheel` is not NULL and `*wheel` points to a valid isc_ttlwheel_t.
 */

uint64_t
isc_ttlwheel_insert(isc_ttlwheel_t *wheel, isc_stdtime_t ttl, void *data);
/*%<
 * Inserts a new element into the TTL wheel.
 *
 * Requires:
 * \li	`wheel` is not NULL and `*wheel` points to a valid isc_ttlwheel_t.
 * \li	`ttl` is not UINT32_MAX.
 * \li	`data` is not NULL.
 *
 * Returns:
 * \li	0 if the entry has already expired according to the TTL wheel.
 * \li	The index of the entry otherwise.
 */

enum isc_result
isc_ttlwheel_update(isc_ttlwheel_t *wheel, uint64_t index, isc_stdtime_t ttl);
/*%<
 * Deletes an entry from the TTL wheel, by element index.
 *
 * Requires:
 * \li	`wheel` is not NULL and `*wheel` points to a valid isc_ttlwheel_t.
 * \li	`index` is a valid element index, as provided by isc_ttlwheel_insert.
 * \li	`ttl` is
 *
 * Returns:
 * \li	#ISC_R_SUCCESS			on success
 * \li	#ISC_R_IGNORE			the new ttl is already expired
 *
 * Note:
 * \li	The index doesn't change.
 */

void
isc_ttlwheel_delete(isc_ttlwheel_t *wheel, uint64_t index);
/*%<
 * Deletes an entry from the TTL wheel, by element index.
 *
 * Requires:
 * \li	`wheel` is not NULL and `*wheel` points to a valid isc_ttlwheel_t.
 * \li	`index` is a valid element index, as provided by isc_ttlwheel_insert.
 */

size_t
isc_ttlwheel_poprange(isc_ttlwheel_t *wheel, isc_stdtime_t now, size_t limit,
		      void *user, isc_ttlwheel_popaction_t action);
/*%<
 * Iterates over the TTL wheel, removing expired entries up to the
 * specified limit.
 *
 * Requires:
 * \li	`wheel` is not NULL and `*wheel` points to a valid isc_ttlwheel_t.
 * \li	`limit` is the amount of entries to iterate at most.
 * \li	`action` is not NULL, and is a function which takes two arguments.
 *	The first is `user` as provided to isc_ttlwheel_poprange, and the second
 *	is a void * that represents the element.
 * \li	`user` is a caller-provided argument and may be NULL.
 *
 * Returns:
 * \li	The amount of entries expired.
 */

ISC_LANG_ENDDECLS

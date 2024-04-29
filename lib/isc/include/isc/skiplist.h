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

/*! \file isc/skiplist.h */

#pragma once

/*
 * Skiplist for items that keep track of their value.
 */

#include <isc/types.h>

typedef struct isc_skiplist isc_skiplist_t;

typedef bool (*isc_skiplist_popaction_t)(void *user, void *value, uint32_t);
typedef uint32_t (*isc_skiplist_key_fn_t)(void *);

ISC_LANG_BEGINDECLS

void
isc_skiplist_create(isc_mem_t *mctx, isc_skiplist_key_fn_t key_fn,
		    isc_skiplist_t **slistp);
/*%
 * Create skiplist at *slistp, using memory context
 *
 * Requires:
 * \li	'slistp' is not NULL and '*slistp' is NULL.
 * \li	'mctx' is a valid memory context.
 *
 */

void
isc_skiplist_destroy(isc_skiplist_t **slistp);
/*%
 * Destroy skiplist, freeing everything
 *
 * Requires:
 * \li	'*slist' is valid skiplist
 */

uint32_t
isc_skiplist_insert(isc_skiplist_t *slist, void *value);
/*%
 * Insert
 *
 * Requires
 * \li	`value` is not NULL and returns a non `UINT32_MAX` key from the
 * function.
 *
 * Note:
 * \li The index value can safetly be discarded if neither `isc_skiplist_delete`
 * nor `isc_skiplist_update` is used and elements are interacted exclusively
 * through `isc_skiplist_poprange`.
 */

uint64_t
isc_skiplist_update(isc_skiplist_t *slist, void *value, uint32_t new_key,
		    uint64_t index);
/*%
 *
 */

isc_result_t
isc_skiplist_delete(isc_skiplist_t *slist, void *value, uint32_t index);

size_t
isc_skiplist_poprange(isc_skiplist_t *slist, uint32_t range, size_t limit,
		      void *user, isc_skiplist_popaction_t action);

ISC_LANG_ENDDECLS

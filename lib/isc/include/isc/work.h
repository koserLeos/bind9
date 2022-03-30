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

#include <stdlib.h>

#include <isc/lang.h>
#include <isc/loop.h>

void
isc_queue_work(isc_loop_t *loop, isc_work_cb work_cb,
	       isc_after_work_cb after_work_cb, void *cbarg);

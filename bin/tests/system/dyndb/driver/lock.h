/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef LOCK_H_
#define LOCK_H_

#include "instance.h"
#include "util.h"

void
run_exclusive_enter(sample_instance_t *inst, isc_result_t *statep);

void
run_exclusive_exit(sample_instance_t *inst, isc_result_t state);

#endif /* LOCK_H_ */

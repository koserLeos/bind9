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

#include <config.h>

#include <isc/util.h>

#include <dns/log.h>

#include "log.h"

void
log_write(int level, const char *format, ...) {
	va_list args;

	va_start(args, format);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		       level, format, args);
	va_end(args);
}

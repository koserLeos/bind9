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

#ifndef _LD_LOG_H_
#define _LD_LOG_H_

#include <isc/error.h>
#include <dns/log.h>
#include <dns/result.h>

#define fatal_error(...) \
	isc_error_fatal(__FILE__, __LINE__, __VA_ARGS__)

#define log_error_r(fmt, ...) \
	log_error(fmt ": %s", ##__VA_ARGS__, dns_result_totext(result))

#define log_error(format, ...)	\
	log_write(ISC_LOG_ERROR, format, ##__VA_ARGS__)

#define log_info(format, ...)	\
	log_write(ISC_LOG_INFO, format, ##__VA_ARGS__)

void
log_write(int level, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);

#endif /* !_LD_LOG_H_ */

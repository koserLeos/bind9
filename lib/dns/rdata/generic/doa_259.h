/*
 * Copyright (C) 2017, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_DOA_259_H
#define GENERIC_DOA_259_H 1

typedef struct dns_rdata_doa {
	dns_rdatacommon_t	common;
	isc_mem_t *		mctx;
	unsigned char *		mediatype;
	unsigned char *		data;
	isc_uint32_t		enterprise;
	isc_uint32_t		type;
	isc_uint16_t		data_len;
	isc_uint8_t		location;
	isc_uint8_t		mediatype_len;
} dns_rdata_doa_t;

#endif /* GENERIC_DOA_259_H */

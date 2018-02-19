/*
 * Copyright (C) 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_AVC_258_H
#define GENERIC_AVC_258_H 1

typedef dns_rdata_txt_string_t dns_rdata_avc_string_t;

typedef struct dns_rdata_avc {
	dns_rdatacommon_t       common;
	isc_mem_t               *mctx;
	unsigned char           *data;
	isc_uint16_t            length;
	/* private */
	isc_uint16_t            offset;
} dns_rdata_avc_t;

/*
 * ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS are already done
 * via rdatastructpre.h and rdatastructsuf.h.
 */
#endif /* GENERIC_AVC_258_H */

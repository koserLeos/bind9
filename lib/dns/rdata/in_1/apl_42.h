/*
 * Copyright (C) 2002, 2004, 2005, 2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef IN_1_APL_42_H
#define IN_1_APL_42_H 1

/* $Id: apl_42.h,v 1.6 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_apl_ent {
	isc_boolean_t	negative;
	isc_uint16_t	family;
	isc_uint8_t	prefix;
	isc_uint8_t	length;
	unsigned char	*data;
} dns_rdata_apl_ent_t;

typedef struct dns_rdata_in_apl {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	/* type & class specific elements */
	unsigned char           *apl;
	isc_uint16_t            apl_len;
	/* private */
	isc_uint16_t            offset;
} dns_rdata_in_apl_t;

/*
 * ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS are already done
 * via rdatastructpre.h and rdatastructsuf.h.
 */

isc_result_t
dns_rdata_apl_first(dns_rdata_in_apl_t *);

isc_result_t
dns_rdata_apl_next(dns_rdata_in_apl_t *);

isc_result_t
dns_rdata_apl_current(dns_rdata_in_apl_t *, dns_rdata_apl_ent_t *);

unsigned int
dns_rdata_apl_count(const dns_rdata_in_apl_t *apl);

#endif /* IN_1_APL_42_H */

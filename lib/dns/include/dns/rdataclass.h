/*
 * Copyright (C) 1998-2001, 2004-2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: rdataclass.h,v 1.24 2007/06/19 23:47:17 tbox Exp $ */

#ifndef DNS_RDATACLASS_H
#define DNS_RDATACLASS_H 1

/*! \file dns/rdataclass.h */

#include <isc/lang.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

isc_result_t
dns_rdataclass_fromtext(dns_rdataclass_t *classp, isc_textregion_t *source);
/*%<
 * Convert the text 'source' refers to into a DNS class.
 *
 * Requires:
 *\li	'classp' is a valid pointer.
 *
 *\li	'source' is a valid text region.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS			on success
 *\li	#DNS_R_UNKNOWN			class is unknown
 */

isc_result_t
dns_rdataclass_totext(dns_rdataclass_t rdclass, isc_buffer_t *target);
/*%<
 * Put a textual representation of class 'rdclass' into 'target'.
 *
 * Requires:
 *\li	'rdclass' is a valid class.
 *
 *\li	'target' is a valid text buffer.
 *
 * Ensures,
 *	if the result is success:
 *\li		The used space in 'target' is updated.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS			on success
 *\li	#ISC_R_NOSPACE			target buffer is too small
 */

isc_result_t
dns_rdataclass_tounknowntext(dns_rdataclass_t rdclass, isc_buffer_t *target);
/*%<
 * Put textual RFC3597 CLASSXXXX representation of class 'rdclass' into
 * 'target'.
 *
 * Requires:
 *\li	'rdclass' is a valid class.
 *
 *\li	'target' is a valid text buffer.
 *
 * Ensures,
 *	if the result is success:
 *\li		The used space in 'target' is updated.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS			on success
 *\li	#ISC_R_NOSPACE			target buffer is too small
 */

void
dns_rdataclass_format(dns_rdataclass_t rdclass,
		      char *array, unsigned int size);
/*%<
 * Format a human-readable representation of the class 'rdclass'
 * into the character array 'array', which is of size 'size'.
 * The resulting string is guaranteed to be null-terminated.
 */

#define DNS_RDATACLASS_FORMATSIZE sizeof("CLASS65535")
/*%<
 * Minimum size of array to pass to dns_rdataclass_format().
 */

ISC_LANG_ENDDECLS

#endif /* DNS_RDATACLASS_H */

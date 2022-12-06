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

/*! \file */

#include <dns/fixedname.h>

void
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_name_init(&fixed->name, fixed->offsets);
	isc_buffer_init(&fixed->buffer, fixed->data, DNS_NAME_MAXWIRE);
	dns_name_setbuffer(&fixed->name, &fixed->buffer);
	fixed->hash = 0;
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate(&fixed->name);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return (&fixed->name);
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return (dns_fixedname_name(fixed));
}

void
dns_fixedname_hash(dns_fixedname_t *fixed) {
	fixed->hash = dns_name_hash(&fixed->name, false);
}

bool
dns_fixedname_equal(dns_fixedname_t *fixed1, dns_fixedname_t *fixed2) {
	return (fixed1->hash == fixed2->hash &&
		dns_name_equal(&fixed1->name, &fixed2->name));
}

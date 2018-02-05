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

#ifndef ZONE_H_
#define ZONE_H_

isc_result_t
create_zone(sample_instance_t * const inst, dns_name_t * const name,
	    dns_zone_t ** const rawp);

isc_result_t
activate_zone(sample_instance_t *inst, dns_zone_t *raw);

#endif /* ZONE_H_ */

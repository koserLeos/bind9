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

/*
 * Sync PTR records
 *
 * Copyright (C) 2014-2015  Red Hat ; see COPYRIGHT for license
 */

#ifndef SYNCPTR_H_
#define SYNCPTR_H_

#include <dns/diff.h>
isc_result_t
syncptrs(sample_instance_t *inst, dns_name_t *name, dns_rdataset_t *rdataset,
	 dns_diffop_t op);

#endif /* SYNCPTR_H_ */

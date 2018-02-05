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

/**
 * Database API implementation.
 *
 * Copyright (C) 2015  Red Hat ; see COPYRIGHT for license
 */

#ifndef DB_H_
#define DB_H_

isc_result_t
create_db(isc_mem_t *mctx, dns_name_t *origin, dns_dbtype_t type,
	  dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	  void *driverarg, dns_db_t **dbp);

#endif /* DB_H_ */

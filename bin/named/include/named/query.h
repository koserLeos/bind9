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

#ifndef NAMED_QUERY_H
#define NAMED_QUERY_H 1

/*! \file */

#include <isc/types.h>
#include <isc/buffer.h>
#include <isc/netaddr.h>

#include <dns/rdataset.h>
#include <dns/rpz.h>
#include <dns/types.h>

#include <named/types.h>

/*% nameserver database version structure */
typedef struct ns_dbversion {
	dns_db_t			*db;
	dns_dbversion_t			*version;
	isc_boolean_t			acl_checked;
	isc_boolean_t			queryok;
	ISC_LINK(struct ns_dbversion)	link;
} ns_dbversion_t;

/*% nameserver query structure */
struct ns_query {
	unsigned int			attributes;
	unsigned int			restarts;
	isc_boolean_t			timerset;
	dns_name_t *			qname;
	dns_name_t *			origqname;
	dns_rdatatype_t			qtype;
	unsigned int			dboptions;
	unsigned int			fetchoptions;
	dns_db_t *			gluedb;
	dns_db_t *			authdb;
	dns_zone_t *			authzone;
	isc_boolean_t			authdbset;
	isc_boolean_t			isreferral;
	isc_mutex_t			fetchlock;
	dns_fetch_t *			fetch;
	dns_fetch_t *			prefetch;
	dns_rpz_st_t *			rpz_st;
	isc_bufferlist_t		namebufs;
	ISC_LIST(ns_dbversion_t)	activeversions;
	ISC_LIST(ns_dbversion_t)	freeversions;
	dns_rdataset_t *		dns64_aaaa;
	dns_rdataset_t *		dns64_sigaaaa;
	isc_boolean_t *			dns64_aaaaok;
	unsigned int			dns64_aaaaoklen;
	unsigned int			dns64_options;
	unsigned int			dns64_ttl;
	struct {
		dns_db_t *      	db;
		dns_zone_t *      	zone;
		dns_dbnode_t *      	node;
		dns_rdatatype_t   	qtype;
		dns_name_t *		fname;
		dns_fixedname_t		fixed;
		isc_result_t		result;
		dns_rdataset_t *	rdataset;
		dns_rdataset_t *	sigrdataset;
		isc_boolean_t		authoritative;
		isc_boolean_t		is_zone;
	} redirect;

	isc_result_t			resp_result;
	dns_fixedname_t			fname;
};

#define NS_QUERYATTR_RECURSIONOK	0x0001
#define NS_QUERYATTR_CACHEOK		0x0002
#define NS_QUERYATTR_PARTIALANSWER	0x0004
#define NS_QUERYATTR_NAMEBUFUSED	0x0008
#define NS_QUERYATTR_RECURSING		0x0010
#define NS_QUERYATTR_CACHEGLUEOK	0x0020
#define NS_QUERYATTR_QUERYOKVALID	0x0040
#define NS_QUERYATTR_QUERYOK		0x0080
#define NS_QUERYATTR_WANTRECURSION	0x0100
#define NS_QUERYATTR_SECURE		0x0200
#define NS_QUERYATTR_NOAUTHORITY	0x0400
#define NS_QUERYATTR_NOADDITIONAL	0x0800
#define NS_QUERYATTR_CACHEACLOKVALID	0x1000
#define NS_QUERYATTR_CACHEACLOK		0x2000
#define NS_QUERYATTR_DNS64		0x4000
#define NS_QUERYATTR_DNS64EXCLUDE	0x8000
#define NS_QUERYATTR_RRL_CHECKED	0x10000
#define NS_QUERYATTR_REDIRECT		0x20000

isc_result_t
ns_query_init(ns_client_t *client);

void
ns_query_free(ns_client_t *client);

void
ns_query_start(ns_client_t *client);

void
ns_query_cancel(ns_client_t *client);

void
ns_query_incstats(ns_client_t *client, isc_statscounter_t counter);

#endif /* NAMED_QUERY_H */

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

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/ncache.h>
#include <dns/result.h>

#include <isc/mem.h>
#include <isc/util.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* NXDOMAIN message for nxdomain.example.org./A:

    Transaction ID: 0x0371
    Flags: 0x8503 Standard query response, No such name
	1... .... .... .... = Response: Message is a response
	.000 0... .... .... = Opcode: Standard query (0)
	.... .1.. .... .... = Authoritative: Server is an authority for domain
	.... ..0. .... .... = Truncated: Message is not truncated
	.... ...1 .... .... = Recursion desired: Do query recursively
	.... .... 0... .... = Recursion available: Server can't do recursive queries
	.... .... .0.. .... = Z: reserved (0)
	.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
	.... .... ...0 .... = Non-authenticated data: Unacceptable
	.... .... .... 0011 = Reply code: No such name (3)
    Questions: 1
    Answer RRs: 0
    Authority RRs: 1
    Additional RRs: 1
    Queries
	nxdomain.example.org: type A, class IN
	    Name: nxdomain.example.org
	    [Name Length: 20]
	    [Label Count: 3]
	    Type: A (Host Address) (1)
	    Class: IN (0x0001)
    Authoritative nameservers
	example.org: type SOA, class IN, mname sns.dns.icann.org
	    Name: example.org
	    Type: SOA (Start Of a zone of Authority) (6)
	    Class: IN (0x0001)
	    Time to live: 3600
	    Data length: 42
	    Primary name server: sns.dns.icann.org
	    Responsible authority's mailbox: noc.dns.icann.org
	    Serial Number: 2015082600
	    Refresh Interval: 7200 (2 hours)
	    Retry Interval: 3600 (1 hour)
	    Expire limit: 1209600 (14 days)
	    Minimum TTL: 3600 (1 hour)
    Additional records
	<Root>: type OPT
	    Name: <Root>
	    Type: OPT (41)
	    UDP payload size: 4096
	    Higher bits in extended RCODE: 0x00
	    EDNS0 version: 0
	    Z: 0x0000
		0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
		.000 0000 0000 0000 = Reserved: 0x0000
	    Data length: 0
*/
static unsigned char nxdomain_message[] = {
	0x03, 0x71, 0x85, 0x03, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x08, 0x6e, 0x78, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x07, 0x65, 0x78,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72,
	0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x15,
	0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
	0x00, 0x2a, 0x03, 0x73, 0x6e, 0x73, 0x03, 0x64,
	0x6e, 0x73, 0x05, 0x69, 0x63, 0x61, 0x6e, 0x6e,
	0xc0, 0x1d, 0x03, 0x6e, 0x6f, 0x63, 0xc0, 0x36,
	0x78, 0x1b, 0xb8, 0x68, 0x00, 0x00, 0x1c, 0x20,
	0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00,
	0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x29, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* NXDOMAIN message for nxdomain.example.org./A with SOA RR's TTL=1:

    Transaction ID: 0x0371
    Flags: 0x8503 Standard query response, No such name
	1... .... .... .... = Response: Message is a response
	.000 0... .... .... = Opcode: Standard query (0)
	.... .1.. .... .... = Authoritative: Server is an authority for domain
	.... ..0. .... .... = Truncated: Message is not truncated
	.... ...1 .... .... = Recursion desired: Do query recursively
	.... .... 0... .... = Recursion available: Server can't do recursive queries
	.... .... .0.. .... = Z: reserved (0)
	.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
	.... .... ...0 .... = Non-authenticated data: Unacceptable
	.... .... .... 0011 = Reply code: No such name (3)
    Questions: 1
    Answer RRs: 0
    Authority RRs: 1
    Additional RRs: 1
    Queries
	nxdomain.example.org: type A, class IN
	    Name: nxdomain.example.org
	    [Name Length: 20]
	    [Label Count: 3]
	    Type: A (Host Address) (1)
	    Class: IN (0x0001)
    Authoritative nameservers
	example.org: type SOA, class IN, mname sns.dns.icann.org
	    Name: example.org
	    Type: SOA (Start Of a zone of Authority) (6)
	    Class: IN (0x0001)
	    Time to live: 1
	    Data length: 42
	    Primary name server: sns.dns.icann.org
	    Responsible authority's mailbox: noc.dns.icann.org
	    Serial Number: 2015082600
	    Refresh Interval: 7200 (2 hours)
	    Retry Interval: 3600 (1 hour)
	    Expire limit: 1209600 (14 days)
	    Minimum TTL: 1 (1 second)
    Additional records
	<Root>: type OPT
	    Name: <Root>
	    Type: OPT (41)
	    UDP payload size: 4096
	    Higher bits in extended RCODE: 0x00
	    EDNS0 version: 0
	    Z: 0x0000
		0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
		.000 0000 0000 0000 = Reserved: 0x0000
	    Data length: 0
*/
static unsigned char nxdomain_message_ttl_1[] = {
	0x03, 0x71, 0x85, 0x03, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x08, 0x6e, 0x78, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x07, 0x65, 0x78,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72,
	0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x15,
	0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x2a, 0x03, 0x73, 0x6e, 0x73, 0x03, 0x64,
	0x6e, 0x73, 0x05, 0x69, 0x63, 0x61, 0x6e, 0x6e,
	0xc0, 0x1d, 0x03, 0x6e, 0x6f, 0x63, 0xc0, 0x36,
	0x78, 0x1b, 0xb8, 0x68, 0x00, 0x00, 0x1c, 0x20,
	0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* NXRRSET message for example.org./APL:

    Transaction ID: 0xa29a
    Flags: 0x8500 Standard query response, No error
	1... .... .... .... = Response: Message is a response
	.000 0... .... .... = Opcode: Standard query (0)
	.... .1.. .... .... = Authoritative: Server is an authority for domain
	.... ..0. .... .... = Truncated: Message is not truncated
	.... ...1 .... .... = Recursion desired: Do query recursively
	.... .... 0... .... = Recursion available: Server can't do recursive queries
	.... .... .0.. .... = Z: reserved (0)
	.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
	.... .... ...0 .... = Non-authenticated data: Unacceptable
	.... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 0
    Authority RRs: 1
    Additional RRs: 1
    Queries
	example.org: type APL, class IN
	    Name: example.org
	    [Name Length: 11]
	    [Label Count: 2]
	    Type: APL (42)
	    Class: IN (0x0001)
    Authoritative nameservers
	example.org: type SOA, class IN, mname sns.dns.icann.org
	    Name: example.org
	    Type: SOA (Start Of a zone of Authority) (6)
	    Class: IN (0x0001)
	    Time to live: 3600
	    Data length: 42
	    Primary name server: sns.dns.icann.org
	    Responsible authority's mailbox: noc.dns.icann.org
	    Serial Number: 2015082600
	    Refresh Interval: 7200 (2 hours)
	    Retry Interval: 3600 (1 hour)
	    Expire limit: 1209600 (14 days)
	    Minimum TTL: 3600 (1 hour)
    Additional records
	<Root>: type OPT
	    Name: <Root>
	    Type: OPT (41)
	    UDP payload size: 4096
	    Higher bits in extended RCODE: 0x00
	    EDNS0 version: 0
	    Z: 0x0000
		0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
		.000 0000 0000 0000 = Reserved: 0x0000
	    Data length: 0
*/
static unsigned char nxrrset_message[] = {
	0xa2, 0x9a, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
	0x00, 0x00, 0x2a, 0x00, 0x01, 0xc0, 0x0c, 0x00,
	0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00,
	0x2a, 0x03, 0x73, 0x6e, 0x73, 0x03, 0x64, 0x6e,
	0x73, 0x05, 0x69, 0x63, 0x61, 0x6e, 0x6e, 0xc0,
	0x14, 0x03, 0x6e, 0x6f, 0x63, 0xc0, 0x2d, 0x78,
	0x1b, 0xb8, 0x68, 0x00, 0x00, 0x1c, 0x20, 0x00,
	0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00,
	0x00, 0x0e, 0x10, 0x00, 0x00, 0x29, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* NXRRSET message for example.org./APL with SOA RR's TTL=1:

    Transaction ID: 0xa29a
    Flags: 0x8500 Standard query response, No error
	1... .... .... .... = Response: Message is a response
	.000 0... .... .... = Opcode: Standard query (0)
	.... .1.. .... .... = Authoritative: Server is an authority for domain
	.... ..0. .... .... = Truncated: Message is not truncated
	.... ...1 .... .... = Recursion desired: Do query recursively
	.... .... 0... .... = Recursion available: Server can't do recursive queries
	.... .... .0.. .... = Z: reserved (0)
	.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
	.... .... ...0 .... = Non-authenticated data: Unacceptable
	.... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 0
    Authority RRs: 1
    Additional RRs: 1
    Queries
	example.org: type APL, class IN
	    Name: example.org
	    [Name Length: 11]
	    [Label Count: 2]
	    Type: APL (42)
	    Class: IN (0x0001)
    Authoritative nameservers
	example.org: type SOA, class IN, mname sns.dns.icann.org
	    Name: example.org
	    Type: SOA (Start Of a zone of Authority) (6)
	    Class: IN (0x0001)
	    Time to live: 1
	    Data length: 42
	    Primary name server: sns.dns.icann.org
	    Responsible authority's mailbox: noc.dns.icann.org
	    Serial Number: 2015082600
	    Refresh Interval: 7200 (2 hours)
	    Retry Interval: 3600 (1 hour)
	    Expire limit: 1209600 (14 days)
	    Minimum TTL: 1 (1 second)
    Additional records
	<Root>: type OPT
	    Name: <Root>
	    Type: OPT (41)
	    UDP payload size: 4096
	    Higher bits in extended RCODE: 0x00
	    EDNS0 version: 0
	    Z: 0x0000
		0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
		.000 0000 0000 0000 = Reserved: 0x0000
	    Data length: 0
*/
static unsigned char nxrrset_message_ttl_1[] = {
	0xa2, 0x9a, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
	0x00, 0x00, 0x2a, 0x00, 0x01, 0xc0, 0x0c, 0x00,
	0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x2a, 0x03, 0x73, 0x6e, 0x73, 0x03, 0x64, 0x6e,
	0x73, 0x05, 0x69, 0x63, 0x61, 0x6e, 0x6e, 0xc0,
	0x14, 0x03, 0x6e, 0x6f, 0x63, 0xc0, 0x2d, 0x78,
	0x1b, 0xb8, 0x68, 0x00, 0x00, 0x1c, 0x20, 0x00,
	0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void
build_name_from_str(isc_mem_t *mctx, const char *namestr,
		    dns_fixedname_t *fname)
{
	size_t length;
	isc_buffer_t *b = NULL;
	isc_result_t result;
	dns_name_t *name;

	length = strlen(namestr);

	result = isc_buffer_allocate(mctx, &b, length);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_putmem(b, (const unsigned char *) namestr, length);

	dns_fixedname_init(fname);
	name = dns_fixedname_name(fname);
	ATF_REQUIRE(name != NULL);
	result = dns_name_fromtext(name, b, dns_rootname, 0, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_buffer_free(&b);
}

ATF_TC(iscache);
ATF_TC_HEAD(iscache, tc) {
	atf_tc_set_md_var(tc, "descr", "test dns_db_iscache");
}
ATF_TC_BODY(iscache, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	bool iscache;

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	iscache = dns_db_iscache(db);
	ATF_REQUIRE_EQ(iscache, true);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(findnode);
ATF_TC_HEAD(findnode, tc) {
	atf_tc_set_md_var(tc, "descr", "test dns_db_findnode");
}
ATF_TC_BODY(findnode, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, false, &node);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE(node == NULL);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	node = NULL;
	result = dns_db_findnode(db, name, false, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdataset);
ATF_TC_HEAD(addrdataset, tc) {
	atf_tc_set_md_var(tc, "descr", "test dns_db_addrdataset");
}
ATF_TC_BODY(addrdataset, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(findrdatasetext);
ATF_TC_HEAD(findrdatasetext, tc) {
	atf_tc_set_md_var(tc, "descr", "test dns_db_findrdatasetext");
}
ATF_TC_BODY(findrdatasetext, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);

	node = NULL;
	result = dns_db_findnode(db, name, false, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	result = dns_db_findrdataset(db, node, NULL, dns_rdatatype_a, 0,
				     now, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);

	node = NULL;
	result = dns_db_findnode(db, name, false, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findrdatasetext(db, node, NULL, dns_rdatatype_a, 0,
					now, NULL, &ci, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);

	node = NULL;
	result = dns_db_findnode(db, name, false, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findrdatasetext(db, node, NULL, dns_rdatatype_a, 0,
					now, NULL, &ci, &rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a NXDOMAIN negative answer into the cache
 * and querying against the cache for some rdataset for this
 * non-existent name.
 *
 * Negative answers are always added into the cache via dns_ncache_add()
 * which passes clientinfo=NULL.
 *
 * clientinfo with SOURCE=0, though supported, is never used. clientinfo
 * with SOURCE > 0 will fail assertion.
 */
ATF_TC(addrdatasetext_negative_nxdomain);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding negative answer (nxdomain, type=ANY) "
			  "overriding NOTHING w/ clientinfo=NULL passed by dns_ncache_add()");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_rdataset_t rdataset;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	isc_buffer_init(&source, nxdomain_message, sizeof(nxdomain_message));
	isc_buffer_add(&source, sizeof(nxdomain_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a NXRRSET negative answer into the cache
 * and querying against the cache for an rdataset of this non-existent
 * type for this name.
 *
 * Negative answers are always added into the cache via dns_ncache_add()
 * which passes clientinfo=NULL.
 *
 * clientinfo with SOURCE=0, though supported, is never used. clientinfo
 * with SOURCE > 0 will fail assertion.
 */
ATF_TC(addrdatasetext_negative_nxrrset);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding negative answer (type=APL) "
			  "overriding NOTHING w/ clientinfo=NULL passed by dns_ncache_add()");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_rdataset_t rdataset;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr", "test adding positive answer with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr", "test adding positive answer with ecs.source=0");
}
ATF_TC_BODY(addrdatasetext_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Mark the rdataset being added as for 0/0 */
	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr", "test adding positive answers at different address prefixes");
}
ATF_TC_BODY(addrdatasetext_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.5 for 1:2:3:4::1/56 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x05";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;
	ci.ecs.scope = 56;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/* Find the global answer (clientinfo=NULL) and check it */

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.4/32). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x04";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 22);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). This should
	 * be found (exact-match).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/56). This
	 * should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 56);
	ATF_REQUIRE_EQ(ci.ecs.scope, 56);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x05";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/32). This
	 * should not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_ecsscopezero);
ATF_TC_HEAD(addrdatasetext_positive_ecsscopezero, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answers at scope=/0 "
			  "for IPv4 and IPv6 address prefixes");
}
ATF_TC_BODY(addrdatasetext_positive_ecsscopezero, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 1.2.3.0/24/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1:2:3:4::1/56/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL) and check it. It
	 * should not be found.
	 */

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should also not
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * find the IPv4 /0 answer (scope=0 in the ECS tree).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/56). This
	 * should find the IPv6 /0 answer (scope=0 in the ECS tree).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 56);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a NXDOMAIN negative answer into the cache
 * overriding various existing positive answers (global and ECS for
 * different address prefixes).
 */
ATF_TC(addrdatasetext_positive_and_negative_nxdomain);
ATF_TC_HEAD(addrdatasetext_positive_and_negative_nxdomain, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding negative answer (nxdomain, type=ANY) "
			  "overriding positive answers");
}
ATF_TC_BODY(addrdatasetext_positive_and_negative_nxdomain, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add nxdomain.example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add nxdomain.example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add nxdomain.example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add nxdomain.example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message, sizeof(nxdomain_message));
	isc_buffer_add(&source, sizeof(nxdomain_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL) and check it. It
	 * should result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a NXRRSET negative answer into the cache
 * overriding various existing positive answers (global and ECS for
 * different address prefixes).
 */
ATF_TC(addrdatasetext_positive_and_negative_nxrrset_same_type);
ATF_TC_HEAD(addrdatasetext_positive_and_negative_nxrrset_same_type, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding negative answer (NXRRSET for APL type) "
			  "overriding positive answers for APL type");
}
ATF_TC_BODY(addrdatasetext_positive_and_negative_nxrrset_same_type, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./APL = 1:10.0.0.1/32 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.2/32 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.3/32 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.4/32 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL) and check it. It
	 * should result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). It should
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a NXRRSET negative answer into the cache
 * overriding various existing positive answers (global and ECS for
 * different address prefixes).
 */
ATF_TC(addrdatasetext_positive_and_negative_nxrrset_different_type);
ATF_TC_HEAD(addrdatasetext_positive_and_negative_nxrrset_different_type, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding negative answer (NXRRSET for APL type) "
			  "overriding positive answers for A type");
}
ATF_TC_BODY(addrdatasetext_positive_and_negative_nxrrset_different_type, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/* Find the global answer (clientinfo=NULL) and check it */

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x04";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 22);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). This should
	 * be found (exact-match).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXDOMAIN answer. It should result in
 * the new answer addition getting rejected by DNS_R_UNCHANGED (because
 * the unexpired NXDOMAIN answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxdomain_unexpired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_unexpired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer "
			  "overriding unexpired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_unexpired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message, sizeof(nxdomain_message));
	isc_buffer_add(&source, sizeof(nxdomain_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add nxdomain.example.org./A = 10.0.0.1 with no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL) and check it. It
	 * should still result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXDOMAIN answer. It should result in
 * the new answer addition getting rejected by DNS_R_UNCHANGED (because
 * the unexpired NXDOMAIN answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxdomain_unexpired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_unexpired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer "
			  "overriding unexpired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_unexpired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message, sizeof(nxdomain_message));
	isc_buffer_add(&source, sizeof(nxdomain_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Now, add nxdomain.example.org./A = 10.0.0.1 for 0/0. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should still result
	 * in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive address prefixed answer into
 * the cache overriding an unexpired negative NXDOMAIN answer. It should
 * result in the new answer addition getting rejected by DNS_R_UNCHANGED
 * (because the unexpired NXDOMAIN answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxdomain_unexpired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_unexpired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive address prefixed answer "
			  "overriding unexpired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_unexpired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message, sizeof(nxdomain_message));
	isc_buffer_add(&source, sizeof(nxdomain_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add nxdomain.example.org./A = 10.0.0.1 for 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 1.2.3.0/24 and check it. It should still
	 * result in an NXDOMAIN answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXDOMAIN);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for the same type. It
 * should result in the new answer addition getting rejected by
 * DNS_R_UNCHANGED (because the unexpired NXRRSET answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer "
			  "overriding unexpired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./APL = 1:10.0.0.1/32 with no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL) and check it. It
	 * should still result in an NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for the same type. It
 * should result in the new answer addition getting rejected by
 * DNS_R_UNCHANGED (because the unexpired NXRRSET answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer for 0/0 "
			  "overriding unexpired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Now, add example.org./APL = 1:10.0.0.1/32 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should still result
	 * in an NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for the same type. It
 * should result in the new answer addition getting rejected by
 * DNS_R_UNCHANGED (because the unexpired NXRRSET answer overrides it).
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive address prefixed answer "
			  "overriding unexpired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/* Now, add example.org./APL = 1:10.0.0.1/32 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 1.2.3.0/24 and check it. It should still
	 * result in an NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for a different
 * type. It should result in the new answer addition being accepted
 * because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer with no clientinfo "
			  "overriding unexpired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 with no clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer with no clientinfo and check it. It
	 * should result in a successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for a different
 * type. It should result in the new answer addition being accepted
 * because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer for 0/0 "
			  "overriding unexpired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 for 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should result in a
	 * successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an unexpired negative NXRRSET answer for a different
 * type. It should result in the new answer addition being accepted
 * because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding address prefixed answer "
			  "overriding unexpired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message, sizeof(nxrrset_message));
	isc_buffer_add(&source, sizeof(nxrrset_message));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 for 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 1.2.3.0/24 and check it. It should result
	 * in a successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXDOMAIN answer. It should result in
 * the new answer addition getting accepted because the NXDOMAIN entry
 * has expired in cache.
 */
ATF_TC(addrdatasetext_negative_nxdomain_expired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_expired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer with no clientinfo "
			  "overriding expired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_expired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message_ttl_1,
			sizeof(nxdomain_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxdomain_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add nxdomain.example.org./A = 10.0.0.1 for
	 * 0/0. It will fail as the NXDOMAIN entry has not yet expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXDOMAIN entry goes stale.
	 */
	now += 2;

	/* Now, add nxdomain.example.org./A = 10.0.0.1 for 0/0. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should result in a
	 * successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXDOMAIN answer. It should result in
 * the new answer addition getting accepted because the NXDOMAIN entry
 * has expired in cache.
 */
ATF_TC(addrdatasetext_negative_nxdomain_expired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_expired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer at 0/0 "
			  "overriding expired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_expired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message_ttl_1,
			sizeof(nxdomain_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxdomain_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add nxdomain.example.org./A = 10.0.0.1 for
	 * 0/0. It will fail as the NXDOMAIN entry has not yet expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXDOMAIN entry goes stale.
	 */
	now += 2;

	/* Now, add nxdomain.example.org./A = 10.0.0.1 for 0/0. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should result in a
	 * successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive address prefixed answer into
 * the cache overriding an expired negative NXDOMAIN answer. It should
 * result in the new answer addition getting accepted because the
 * NXDOMAIN entry has expired in cache.
 */
ATF_TC(addrdatasetext_negative_nxdomain_expired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxdomain_expired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive address prefixed answer "
			  "overriding expired negative NXDOMAIN");
}
ATF_TC_BODY(addrdatasetext_negative_nxdomain_expired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "nxdomain.example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add an NXDOMAIN entry for "nxdomain.example.org" into the
	 * cache DB.
	 */

	isc_buffer_init(&source, nxdomain_message_ttl_1,
			sizeof(nxdomain_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxdomain_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_any,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add nxdomain.example.org./A = 10.0.0.1 for
	 * 1.2.3.0/24. It will fail as the NXDOMAIN entry has not yet
	 * expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXDOMAIN entry goes stale.
	 */
	now += 2;

	/*
	 * Now, add nxdomain.example.org./A = 10.0.0.1 for 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 1.2.3.0/24 and check it. It should result
	 * in a successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXRRSET answer for the same type. It
 * should result in the new answer addition being accepted because the
 * NXRRSET entry has expired in the cache.
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer with no clientinfo "
			  "overriding expired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add example.org./APL = 1:10.0.0.1/32 with no
	 * clientinfo. It will fail as the NXRRSET entry has not yet
	 * expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/*
	 * Now, add example.org./APL = 1:10.0.0.1/32 with no clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer with no clientinfo and check it. It
	 * should result in a successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXRRSET answer for the same type. It
 * should result in the new answer addition being accepted because the
 * NXRRSET entry has expired in the cache.
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer for 0/0 "
			  "overriding expired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add example.org./APL = 1:10.0.0.1/32 for
	 * 0/0. It will fail as the NXRRSET entry has not yet expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/* Now, add example.org./APL = 1:10.0.0.1/32 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 0/0 and check it. It should result in a
	 * successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive address prefixed answer into
 * the cache overriding an expired negative NXRRSET answer for the same
 * type. It should result in the new answer addition being accepted
 * because the NXRRSET entry has expired in the cache.
 */
ATF_TC(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive address prefixed answer "
			  "overriding expired negative NXRRSET of the same type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_same_type_expired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, attempt to add example.org./APL = 1:10.0.0.1/32 for
	 * 1.2.3.0/24. It will fail as the NXRRSET entry has not yet
	 * expired.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/* Now, add example.org./APL = 1:10.0.0.1/32 for 1.2.3.0/24. */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the answer for 1.2.3.0/24 and check it. It should result
	 * in a successful find.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXRRSET answer for a different
 * type. It should result in the new answer addition being accepted
 * because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_noclientinfo);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer with no clientinfo "
			  "overriding expired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 for 0/0. It should be
	 * successful because it is of a different type than the
	 * NXRRSET.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 0/0 and check it. It should result in
	 * a NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/*
	 * Find the A answer for 0/0 and check it. It should result in a
	 * successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 0/0 and check it. It should result in
	 * a NOTFOUND (not NXRRSET as that answer has expired now).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive global answer into the cache
 * overriding an expired negative NXRRSET answer for a different
 * type. It should result in the new answer addition being accepted
 * because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_globaldata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive global answer for 0/0 "
			  "overriding expired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 for 0/0. It should be
	 * successful because it is of a different type than the
	 * NXRRSET.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 0/0 and check it. It should result in
	 * a NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/*
	 * Find the A answer for 0/0 and check it. It should result in a
	 * successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 0/0 and check it. It should result in
	 * a NOTFOUND (not NXRRSET as that answer has expired now).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This testcase tests adding a positive address prefixed answer into
 * the cache overriding an expired negative NXRRSET answer for a
 * different type. It should result in the new answer addition being
 * accepted because it is for a different type.
 */
ATF_TC(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_ecsdata);
ATF_TC_HEAD(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive address prefixed answer "
			  "overriding expired negative NXRRSET of a different type");
}
ATF_TC_BODY(addrdatasetext_negative_nxrrset_different_type_expired_and_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	dns_message_t *message;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Now add an NXRRSET entry for "example.org/APL" into the cache
	 * DB.
	 */

	isc_buffer_init(&source, nxrrset_message_ttl_1,
			sizeof(nxrrset_message_ttl_1));
	isc_buffer_add(&source, sizeof(nxrrset_message_ttl_1));

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_message_parse(message, &source, 0);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Patch the message to add NCACHE attributes */
	result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *mname = NULL;
		dns_rdataset_t *mrdataset;

		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &mname);
		if (dns_name_issubdomain(name, mname)) {
			/*
			 * Look for SOA RRset and mark the name and
			 * rdataset for NCACHE processing.
			 */
			for (mrdataset = ISC_LIST_HEAD(mname->list);
			     mrdataset != NULL;
			     mrdataset = ISC_LIST_NEXT(mrdataset, link)) {
				if (mrdataset->type == dns_rdatatype_soa) {
					mname->attributes |=
						DNS_NAMEATTR_NCACHE;
					mrdataset->attributes |=
						DNS_RDATASETATTR_NCACHE;
					mrdataset->trust =
						dns_trust_authauthority;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
		if (result == ISC_R_NOMORE)
			break;
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	}

	result = dns_ncache_add(message, db, node, dns_rdatatype_apl,
				now, 256000, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_message_destroy(&message);

	/*
	 * Now, add example.org./A = 10.0.0.1 for 1.2.3.0/24. It should
	 * be successful because it is of a different type than the
	 * NXRRSET.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 1.2.3.0/24 and check it. It should
	 * result in a NXRRSET answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_NCACHENXRRSET);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * NXRRSET entry goes stale.
	 */
	now += 2;

	/*
	 * Find the A answer for 1.2.3.0/24 and check it. It should
	 * result in a successful answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Find the APL answer for 1.2.3.0/24 and check it. It should
	 * result in a NOTFOUND (not NXRRSET as that answer has expired
	 * now).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This tests searching where a newer positive answer with non-expired
 * TTL and shorter prefix length exists in ecs_tree shadowing an older
 * positive answer with expired TTL (both positive answers have the same
 * RR type)
 */
ATF_TC(addrdatasetext_positive_matching_longest_unexpired_answer);
ATF_TC_HEAD(addrdatasetext_positive_matching_longest_unexpired_answer, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test unexpired positive answer with short prefix length + "
			  "expired answer with longer prefix length");
}
ATF_TC_BODY(addrdatasetext_positive_matching_longest_unexpired_answer, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 1.2.3.0/24 with TTL=1 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16 with TTL=3600 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 16;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * find the 1.2.3.0/24 answer which has not expired yet.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down and the
	 * longer answer expires.
	 */
	now += 2;

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * find the 1.2.0.0/16 answer as the 1.2.3.0/24 answer has
	 * expired now.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 16);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This tests searching where a positive answer with non-expired TTL and
 * matching RRTYPE with shorter prefix length exists alongside a
 * positive answer exactly matching the prefix length but different
 * RRTYPE from that being searched. In this case, the former answer with
 * shorter prefix length and matching RRTYPE is the correct answer.
 */
ATF_TC(addrdatasetext_positive_matching_longest_same_type_answer);
ATF_TC_HEAD(addrdatasetext_positive_matching_longest_same_type_answer, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test positive A answer with short prefix length + "
			  "positive APL answer with longer prefix length");
}
ATF_TC_BODY(addrdatasetext_positive_matching_longest_same_type_answer, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 1.2.3.0/24. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.2/32 for 1.2.0.0/16. */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 16;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE A at an IPv4 prefix (1.2.3.0/24). This
	 * should find the 1.2.3.0/24 RRTYPE A answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE APL at an IPv4 prefix
	 * (1.2.3.0/24). This should find the 1.2.0.0/16 RRTYPE APL
	 * answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 16);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE A at an IPv4 prefix (1.2.0.0/16). This
	 * should not be found (even though an IP tree node exists).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_multiple_types_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_multiple_types_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answers for "
			  "multiple types with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_multiple_types_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 with no clientinfo. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.2/32 with no clientinfo. */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE APL. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_multiple_types_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_multiple_types_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answers for "
			  "multiple types at 0/0");
}
ATF_TC_BODY(addrdatasetext_positive_multiple_types_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 at 0/0. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.2/32 at 0/0. */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A at 0/0. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE APL at 0/0. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_multiple_types_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_multiple_types_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answers for "
			  "multiple types for the same address prefix");
}
ATF_TC_BODY(addrdatasetext_positive_multiple_types_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 at 1.2.3.0/24. */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./APL = 1:10.0.0.2/32 at 1.2.3.0/24. */

	dns_rdata_init(&rdata);
	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 8;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_apl;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_apl;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A at 1.2.3.0/24. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find RRTYPE APL at 1.2.3.0/24. This should be
	 * found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_apl,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x00\x01\x20\x04\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 8);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 8) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_highertrust_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_highertrust_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ expired TTL "
			  "with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_highertrust_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 and no clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 and no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_lowertrust_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_lowertrust_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ expired TTL "
			  "with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_lowertrust_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 and no clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 and no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_highertrust_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_highertrust_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ unexpired TTL "
			  "with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_highertrust_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 and no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 and no
	 * clientinfo. This should result in DNS_R_UNCHANGED being
	 * returned because there is a higher trusted unexpired answer
	 * already in cache.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_lowertrust_noclientinfo);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_lowertrust_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ unexpired TTL "
			  "with clientinfo=NULL");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_lowertrust_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 and no
	 * clientinfo.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 and no
	 * clientinfo. This should result in successful addition because
	 * this answer is more trusted.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_highertrust_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_highertrust_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ expired TTL "
			  "at 0/0");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_highertrust_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_lowertrust_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_lowertrust_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ expired TTL "
			  "at 0/0");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_lowertrust_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_highertrust_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_highertrust_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ unexpired TTL "
			  "at 0/0");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_highertrust_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 0/0. This
	 * should result in DNS_R_UNCHANGED being returned because there
	 * is a higher trusted unexpired answer already in cache.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_lowertrust_globaldata);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_lowertrust_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ unexpired TTL "
			  "at 0/0");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_lowertrust_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 at 0/0.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 0/0. This
	 * should result in successful addition because this answer is
	 * more trusted.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_highertrust_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_highertrust_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ expired TTL "
			  "at address prefix");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_highertrust_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_expired_lowertrust_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_override_expired_lowertrust_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ expired TTL "
			  "at address prefix");
}
ATF_TC_BODY(addrdatasetext_positive_override_expired_lowertrust_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=1 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_highertrust_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_highertrust_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with higher trust w/ unexpired TTL "
			  "at address prefix");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_highertrust_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at
	 * 1.2.3.0/24. This should result in DNS_R_UNCHANGED being
	 * returned because there is a higher trusted unexpired answer
	 * already in cache.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(addrdatasetext_positive_override_unexpired_lowertrust_ecsdata);
ATF_TC_HEAD(addrdatasetext_positive_override_unexpired_lowertrust_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test adding positive answer overriding existing "
			  "positive answer with lower trust w/ unexpired TTL "
			  "at address prefix");
}
ATF_TC_BODY(addrdatasetext_positive_override_unexpired_lowertrust_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/*
	 * Add example.org./A = 10.0.0.1 with TTL=3600 at 1.2.3.0/24.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_answer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * NOTE: Do not call any functions now that can cause the STALE
	 * attribute to be set, until dns_db_addrdatasetext() is called
	 * first.
	 */

	/*
	 * Add example.org./A = 10.0.0.2 with TTL=3600 at
	 * 1.2.3.0/24. This should result in successful addition because
	 * this answer is more trusted.
	 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Now try to find RRTYPE A. This should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(deleterdatasetext_positive_noclientinfo);
ATF_TC_HEAD(deleterdatasetext_positive_noclientinfo, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test deleting cache entry with no clientinfo, "
			  "with positive answers existing at different "
			  "address prefixes");
}
ATF_TC_BODY(deleterdatasetext_positive_noclientinfo, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.5 for 1:2:3:4::1/56 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x05";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;
	ci.ecs.scope = 56;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Now delete the global answer with no clientinfo */

	result = dns_db_deleterdatasetext(db, node, NULL,
					  dns_rdatatype_a, 0,
					  NULL, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL). It should not be
	 * found as it was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should not be
	 * found as it is the global answer which was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.4/32). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x04";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 22);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). This should
	 * be found (exact-match).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/56). This
	 * should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 56);
	ATF_REQUIRE_EQ(ci.ecs.scope, 56);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x05";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/32). This
	 * should not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(deleterdatasetext_positive_globaldata);
ATF_TC_HEAD(deleterdatasetext_positive_globaldata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test deleting cache entry at 0/0, "
			  "with positive answers existing at different "
			  "address prefixes");
}
ATF_TC_BODY(deleterdatasetext_positive_globaldata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.5 for 1:2:3:4::1/56 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x05";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;
	ci.ecs.scope = 56;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Now delete the global answer at 0/0. */

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_deleterdatasetext(db, node, NULL,
					  dns_rdatatype_a, 0,
					  NULL, &ci);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/*
	 * Find the global answer (clientinfo=NULL). It should not be
	 * found as it was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should not be
	 * found as it is the global answer which was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.4/32). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x03";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x04";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 22);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). This should
	 * be found (exact-match).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/56). This
	 * should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 56);
	ATF_REQUIRE_EQ(ci.ecs.scope, 56);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x05";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/32). This
	 * should not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

ATF_TC(deleterdatasetext_positive_ecsdata);
ATF_TC_HEAD(deleterdatasetext_positive_ecsdata, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test deleting address prefixed cache entry, "
			  "with positive answers existing at different "
			  "address prefixes");
}
ATF_TC_BODY(deleterdatasetext_positive_ecsdata, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 0/0 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;
	ci.ecs.scope = 0;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.2 for 1.2.0.0/16/24 (exact-match) */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x02";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.3 for 1.2.3.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x03";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.4 for 1.2.4.0/24 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x04";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./A = 10.0.0.5 for 1:2:3:4::1/56 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x05";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;
	ci.ecs.scope = 56;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Now delete the answer at 1.2.3.0/24. */

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_deleterdatasetext(db, node, NULL,
					  dns_rdatatype_a, 0,
					  NULL, &ci);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Sleep for 2 seconds so that the TTL counts down */
	now += 2;

	/* Find the global answer (clientinfo=NULL) and check it */

	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);
	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, NULL,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (0/0). This should be
	 * found as it is the global answer.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("0.0.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 0;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 0);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/24). This should
	 * not be found as it was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.4/32). This should
	 * not be found as 1.2.3.0/24 was deleted.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.4.0/24). This should
	 * be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.4.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x04";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.3.0/22). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 22;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 22);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.0.0/16). This should
	 * be found (exact-match).
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 16);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x02";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv4 prefix (1.2.5.0/24). This should
	 * not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.5.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/56). This
	 * should be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 56;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 56);
	ATF_REQUIRE_EQ(ci.ecs.scope, 56);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x05";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find at an IPv6 prefix (1:2:3:4::1/32). This
	 * should not be found.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	inet_pton(AF_INET6, "1:2:3:4::1", &in6_addr);
	isc_netaddr_fromin6(&ci.ecs.addr, &in6_addr);
	ci.ecs.source = 32;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(ci.ecs.source, 32);
	ATF_REQUIRE_EQ(ci.ecs.scope, 0xff);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * This tests searching where a CNAME answer with unexpired TTL and
 * shorter prefix length exists in ecs_tree alongside an unexpired
 * positive answer of non-CNAME type for a longer prefix-length.
 */
ATF_TC(addrdatasetext_positive_matching_longest_cname_answer);
ATF_TC_HEAD(addrdatasetext_positive_matching_longest_cname_answer, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "test CNAME answer with short prefix length + "
			  "positive non-CNAME answer with longer prefix length");
}
ATF_TC_BODY(addrdatasetext_positive_matching_longest_cname_answer, tc) {
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t foundname_fixed;
	dns_name_t *foundname;
	dns_rdata_t rdata;
	const char *rdata_data;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_clientinfo_t ci;
	struct in_addr in_addr;
	isc_stdtime_t now;

	isc_stdtime_get(&now);

	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_cache,
			       dns_rdataclass_in, 0, NULL, &db);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	build_name_from_str(mctx, "example.org", &fname);
	name = dns_fixedname_name(&fname);

	node = NULL;
	result = dns_db_findnode(db, name, true, &node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(node != NULL);

	/* Add example.org./A = 10.0.0.1 for 1.2.3.0/24 with TTL=3600 */

	dns_rdata_init(&rdata);
	rdata_data = "\x0a\x00\x00\x01";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 4;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_a;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;
	ci.ecs.scope = 24;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/* Add example.org./CNAME = example.com. for 1.2.0.0/16 with TTL=3600 */

	dns_rdata_init(&rdata);
	rdata_data = "\x07example\x03com\x00";
	DE_CONST(rdata_data, rdata.data);
	rdata.length = 13;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_cname;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_cname;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.0.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 16;
	ci.ecs.scope = 16;

	result = dns_db_addrdatasetext(db, node, NULL, now, &rdataset, 0,
				       NULL, &ci, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Sleep for 2 seconds so that the TTL counts down.
	 */
	now += 2;

	/*
	 * Now try to find example.org./A at an IPv4 prefix
	 * (1.2.3.0/24). This should find the 1.2.3.0/24.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 24;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(ci.ecs.source, 24);
	ATF_REQUIRE_EQ(ci.ecs.scope, 24);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x0a\x00\x00\x01";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 4);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 4) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	/*
	 * Now try to find example.org./A at an IPv4 prefix
	 * (1.2.3.0/23). This should find the 1.2.0.0/16
	 * example.org./CNAME answer as it is the longest match.
	 */
	dns_rdataset_init(&rdataset);
	dns_fixedname_init(&foundname_fixed);
	foundname = dns_fixedname_name(&foundname_fixed);

	dns_clientinfo_init(&ci, NULL, NULL, NULL);
	in_addr.s_addr = inet_addr("1.2.3.0");
	isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
	ci.ecs.source = 23;

	result = dns_db_findext(db, name, NULL, dns_rdatatype_a,
				0, now, NULL, foundname, NULL, &ci,
				&rdataset, NULL);
	ATF_REQUIRE_EQ(result, DNS_R_CNAME);
	ATF_REQUIRE_EQ(ci.ecs.source, 23);
	ATF_REQUIRE_EQ(ci.ecs.scope, 16);
	ATF_REQUIRE(rdataset.ttl > 3590 && rdataset.ttl < 3600);

	result = dns_rdataset_first(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	rdata_data = "\x07example\x03com\x00";

	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	ATF_REQUIRE_EQ(rdata.length, 13);
	ATF_REQUIRE(memcmp(rdata.data, rdata_data, 13) == 0);

	result = dns_rdataset_next(&rdataset);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	dns_rdataset_invalidate(&rdataset);

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, iscache);
	ATF_TP_ADD_TC(tp, findnode);
	ATF_TP_ADD_TC(tp, addrdataset);
	ATF_TP_ADD_TC(tp, findrdatasetext);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_ecsdata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_ecsscopezero);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_and_negative_nxdomain);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_and_negative_nxrrset_same_type);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_and_negative_nxrrset_different_type);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_unexpired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_unexpired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_unexpired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_unexpired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_unexpired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_expired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_expired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxdomain_expired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_expired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_expired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_same_type_expired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_expired_and_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_expired_and_positive_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_negative_nxrrset_different_type_expired_and_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_matching_longest_unexpired_answer);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_matching_longest_same_type_answer);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_multiple_types_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_multiple_types_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_multiple_types_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_highertrust_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_lowertrust_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_highertrust_noclientinfo);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_lowertrust_noclientinfo);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_highertrust_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_lowertrust_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_highertrust_globaldata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_lowertrust_globaldata);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_highertrust_ecsdata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_expired_lowertrust_ecsdata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_highertrust_ecsdata);
	ATF_TP_ADD_TC(tp, addrdatasetext_positive_override_unexpired_lowertrust_ecsdata);

	ATF_TP_ADD_TC(tp, deleterdatasetext_positive_noclientinfo);
	ATF_TP_ADD_TC(tp, deleterdatasetext_positive_globaldata);
	ATF_TP_ADD_TC(tp, deleterdatasetext_positive_ecsdata);

	ATF_TP_ADD_TC(tp, addrdatasetext_positive_matching_longest_cname_answer);

	/*
	 * Unit tests left to add:
	 *
	 * adding negative answer (nxdomain, type=ANY) with existing negative answer (nxdomain, type=ANY) already in cache
	 * adding negative answer (nxdomain, type=ANY) with existing negative answer (NXRRSET) already in cache
	 */

	return (atf_no_error());
}

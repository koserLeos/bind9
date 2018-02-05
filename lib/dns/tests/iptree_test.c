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

#include <config.h>

#include <atf-c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dns/iptree.h>
#include <dns/ecs.h>

#include <isc/buffer.h>
#include <isc/netaddr.h>
#include <isc/mem.h>
#include <isc/util.h>

static isc_boolean_t
destroy_cb(void **data, void *destroy_arg) {
	size_t *count;

	ATF_REQUIRE(data != NULL && *data != NULL);

	count = (size_t *) destroy_arg;
	if (count != NULL)
		(*count)++;

	*data = NULL;

	/* Return value does not matter here. */
	return (ISC_FALSE);
}

static isc_boolean_t
callback_fn(void **data, void *callback_arg) {
	size_t *count;

	ATF_REQUIRE(data != NULL && *data != NULL);

	count = (size_t *) callback_arg;
	(*count)++;

	/* Return value does not matter here. */
	return (ISC_FALSE);
}

ATF_TC(iptree_destroy_foreach__null);
ATF_TC_HEAD(iptree_destroy_foreach__null, tc) {
	atf_tc_set_md_var(tc, "descr", "destroy iptree with root=NULL");
}
ATF_TC_BODY(iptree_destroy_foreach__null, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	root = NULL;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_common_prefix);
ATF_TC_HEAD(iptree_common_prefix, tc) {
	atf_tc_set_md_var(tc, "descr", "iptree_common_prefix");
}
ATF_TC_BODY(iptree_common_prefix, tc) {
	int diff;

	UNUSED(tc);

	{
		const uint32_t addr_a[4] = { 0, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 128);
	}

	{
		const uint32_t addr_a[4] = { 0, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 32, addr_b, 32);
		ATF_REQUIRE_EQ(diff, 32);
	}

	{
		const uint32_t addr_a[4] = { 0x42000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x42000000, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 128);
	}

	{
		const uint32_t addr_a[4] = {
			0x9a8f023e, 0xf898f882, 0x47809813, 0x9908abcd
		};
		const uint32_t addr_b[4] = {
			0x9a8f023e, 0xf898f882, 0x47809813, 0x9908abcd
		};

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 128);
	}

	{
		const uint32_t addr_a[4] = {
			0x9a8f023e, 0xf898f882, 0x47809813, 0x9908abcd
		};
		const uint32_t addr_b[4] = {
			0x9a8f023e, 0xf898f882, 0x47809813, 0x9908abcd
		};

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 32, addr_b, 32);
		ATF_REQUIRE_EQ(diff, 32);
	}

	{
		const uint32_t addr_a[4] = { 0x80000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x40000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 0);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x40000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 0);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x80000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 1);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0x000000ff };
		const uint32_t addr_b[4] = { 0x80000000, 0, 0, 0x000000ff };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 1);
	}

	{
		const uint32_t addr_a[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020304
		};
		const uint32_t addr_b[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020300
		};

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		ATF_REQUIRE_EQ(diff, 125);
	}

	{
		const uint32_t addr_a[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020304
		};
		const uint32_t addr_b[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020300
		};

		/* addresses are equal up to first 32 bits */
		diff = dns_iptree_common_prefix(addr_a, 32, addr_b, 32);
		ATF_REQUIRE_EQ(diff, 32);
	}
}

ATF_TC(iptree_search__null_root_no_create);
ATF_TC_HEAD(iptree_search__null_root_no_create, tc) {
	atf_tc_set_md_var(tc, "descr", "search iptree with root=NULL, create=ISC_FALSE");
}
ATF_TC_BODY(iptree_search__null_root_no_create, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;
	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE_EQ(root, NULL);
	ATF_REQUIRE_EQ(found_node, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_v4);
ATF_TC_HEAD(iptree_search_v4, tc) {
	atf_tc_set_md_var(tc, "descr", "search IPv4 iptree with root=NULL, create=ISC_TRUE");
}
ATF_TC_BODY(iptree_search_v4, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root, *root_copy;
	struct in_addr in_addr, in_addr2;
	isc_netaddr_t netaddr, netaddr2;
	dns_iptree_node_t *found_node;
	void **found_data;
	uint8_t found_address_prefix_length;
	uint8_t found_scope_prefix_length;
	size_t count, dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0x809ffbc1;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_EXISTS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Repeat with create=ISC_FALSE */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	/* Look for the inserted 0/0 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 1, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for the inserted old 1.2.3.4/32. It should still be
	 * present.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for 1.2.3.4/24 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	inet_pton(AF_INET, "1.2.3.1", &in_addr2);
	isc_netaddr_fromin(&netaddr2, &in_addr2);

	/*
	 * Look for 1.2.3.1/24 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Create 1.2.3.1/32. */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 32, 32,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/* Set some dummy data */
	*found_data = (void *) 0xabcdabcd;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xabcdabcd);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/*
	 * Create 1.2.3.1/24/26.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 24, 26,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 26);

	/* Set some dummy data */
	*found_data = (void *) 0xf000f000;

	/*
	 * Search for 1.2.3.1/24. It should be found (exact match).
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf000f000);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 26);

	/*
	 * Search for 1.2.3.1/25. The longer 1.2.3.1/24 should not be
	 * found as it is an exact-match address prefix; instead
	 * 0/0 should be found.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 25, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	/*
	 * Search for 1.2.3.1/24 again. It should be found (exact
	 * match).
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf000f000);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 26);

	/*
	 * Clear the node data, effectively deleting that address
	 * prefix.
	 */
	*found_data = NULL;

	/*
	 * Create 1.2.3.1/24 with exact_match=ISC_FALSE.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 24);

	/* Set some dummy data */
	*found_data = (void *) 0xb000b000;

	/*
	 * Search for 1.2.3.1/24. It should be found.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xb000b000);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 24);

	/*
	 * Search for 1.2.3.1/25. The longer 1.2.3.1/24 should be found
	 * as it is not an exact-match address prefix.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 25, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xb000b000);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 24);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);
	/* dcount should be 4 (count - 1, where 1 is the fork node). */
	ATF_REQUIRE_EQ(dcount, 4);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_v6);
ATF_TC_HEAD(iptree_search_v6, tc) {
	atf_tc_set_md_var(tc, "descr", "search IPv6 iptree with root=NULL, create=ISC_TRUE");
}
ATF_TC_BODY(iptree_search_v6, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root, *root_copy;
	struct in6_addr in_addr, in_addr2;
	struct in_addr in_addr3;
	isc_netaddr_t netaddr, netaddr2, netaddr3;
	dns_iptree_node_t *found_node;
	void **found_data;
	uint8_t found_address_prefix_length;
	uint8_t found_scope_prefix_length;
	size_t count, dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET6, "1:2:3:4::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0x809ffbc1;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_EXISTS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Repeat with create=ISC_FALSE */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 128, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 1, 0,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	/* Look for the inserted 0/0 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 1, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for the inserted old 1:2:3:4::1/128. It should still be
	 * present.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 128, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0x809ffbc1);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for 1:2:3:4::1/120 - should get a PARTIALMATCH against
	 * 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 120, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	inet_pton(AF_INET6, "1:2:3:1::1", &in_addr2);
	isc_netaddr_fromin6(&netaddr2, &in_addr2);

	/*
	 * Look for 1:2:3:1::1/120 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 120, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xf0173712);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Create 1:2:3:1::1/128. */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 128, 128,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/* Set some dummy data */
	*found_data = (void *) 0xabcdabcd;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;
	root_copy = root;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 128, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE_EQ(root, root_copy);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xabcdabcd);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/*
	 * IPv4 lookup for 0.0.0.0/1 should not PARTIALMATCH anything,
	 * even though there is a /0 node in the tree, because there is
	 * no ::ffff:0.0.0.0/96 node in the tree.
	 */
	inet_pton(AF_INET, "1.2.3.1", &in_addr3);
	isc_netaddr_fromin(&netaddr3, &in_addr3);

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr3, 1, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE(found_node == NULL);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);
	/* dcount should be 3 (count - 1, where 1 is the fork node). */
	ATF_REQUIRE_EQ(dcount, 3);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_foreach);
ATF_TC_HEAD(iptree_foreach, tc) {
	atf_tc_set_md_var(tc, "descr", "test dns_iptree_foreach()");
}
ATF_TC_BODY(iptree_foreach, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in6_addr in_addr, in_addr2;
	isc_netaddr_t netaddr, netaddr2;
	dns_iptree_node_t *found_node;
	void **found_data;
	uint8_t found_address_prefix_length;
	uint8_t found_scope_prefix_length;
	size_t count, cbcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	/* Create 1:2:3:4::1/128 */
	inet_pton(AF_INET6, "1:2:3:4::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 1, 0,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Create 1:2:3:1::1/128. */
	inet_pton(AF_INET6, "1:2:3:1::1", &in_addr2);
	isc_netaddr_fromin6(&netaddr2, &in_addr2);

	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 128, 128,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 128);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 128);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/* Test the callback */
	cbcount = 0;
	dns_iptree_foreach(root, callback_fn, &cbcount);
	/* cbcount should be 3 (count - 1, where 1 is the fork node). */
	ATF_REQUIRE_EQ(cbcount, 3);

	/* The tree should still exist. */
	ATF_REQUIRE(root != NULL);
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 4);

	/* Destroy the tree */
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, NULL);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

static isc_boolean_t
match_cb(void **data, void *match_arg) {
	UNUSED(match_arg);

	ATF_REQUIRE(data != NULL && *data != NULL);

	if (*data == (void *) 0xdd)
		return (ISC_FALSE);

	return (ISC_TRUE);
}

ATF_TC(iptree_search_v4_exact_is_non_matching);
ATF_TC_HEAD(iptree_search_v4_exact_is_non_matching, tc) {
	atf_tc_set_md_var(tc, "descr", "search IPv4 iptree where an exact match node is ignored by match callback");
}
ATF_TC_BODY(iptree_search_v4_exact_is_non_matching, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	void **found_data;
	uint8_t found_address_prefix_length;
	uint8_t found_scope_prefix_length;
	size_t count, dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 0);

	/* Insert 1.2.3.4/32. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0xdd;

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xcc;

	/*
	 * Look for 1.2.3.4/32 without match callback. The inserted
	 * 1.2.3.4/32 should be found as an exact match result.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xdd);
	ATF_REQUIRE_EQ(found_address_prefix_length, 32);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for 1.2.3.4/32 with match callback which ignores 0xdd
	 * data. The 0/0 should be found in this case.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, match_cb, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xcc);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	ATF_REQUIRE_EQ(dcount, 2);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_v4_partial_is_non_matching);
ATF_TC_HEAD(iptree_search_v4_partial_is_non_matching, tc) {
	atf_tc_set_md_var(tc, "descr", "search IPv4 iptree where a partialmatch node is ignored by match callback");
}
ATF_TC_BODY(iptree_search_v4_partial_is_non_matching, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	void **found_data;
	uint8_t found_address_prefix_length;
	uint8_t found_scope_prefix_length;
	size_t count, dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 0);

	/* Insert 1.2.3.0/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 24);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0xdd;

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE(found_data != NULL);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xcc;

	/*
	 * Look for 1.2.3.4/32 without match callback. The inserted
	 * 1.2.3.0/24 should be found as a partialmatch result.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xdd);
	ATF_REQUIRE_EQ(found_address_prefix_length, 24);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 24);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/*
	 * Look for 1.2.3.4/32 with match callback which ignores 0xdd
	 * data. The 0/0 should be found in this case.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   ISC_FALSE, match_cb, NULL, &found_node);
	ATF_REQUIRE_EQ(result, DNS_R_PARTIALMATCH);
	ATF_REQUIRE(found_node != NULL);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	ATF_REQUIRE_EQ(*found_data, (void *) 0xcc);
	ATF_REQUIRE_EQ(found_address_prefix_length, 0);
	ATF_REQUIRE_EQ(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	ATF_REQUIRE_EQ(count, 2);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	ATF_REQUIRE_EQ(dcount, 2);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_v6_byteorder);
ATF_TC_HEAD(iptree_search_v6_byteorder, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "check that v6 byte ordering of address prefixes "
			  "is correctly implemented");
}
ATF_TC_BODY(iptree_search_v6_byteorder, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in6_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET6, "7fff::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	root = NULL;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 8, 8,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, ffff::1/8 should not be found. */
	inet_pton(AF_INET6, "ffff::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 8, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_NOTFOUND);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node == NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

typedef struct {
	unsigned int nodes_to_delete[7];
	unsigned int expected_nodecount;
} destroy_testcase_t;

static isc_boolean_t
destroy_testcase_cb(void **data, void *destroy_arg) {
	destroy_testcase_t *test;
	size_t value;
	int i;

	ATF_REQUIRE(data != NULL && *data != NULL);

	test = (destroy_testcase_t *) destroy_arg;
	value = (size_t) *data;

	for (i = 0; i < 7; i++) {
		if (test->nodes_to_delete[i] == 0)
			break;
		if (test->nodes_to_delete[i] == value) {
			*data = NULL;
			break;
		}
	}

	/* Return value does not matter here. */
	return (ISC_FALSE);
}

ATF_TC(iptree_destroy_foreach);
ATF_TC_HEAD(iptree_destroy_foreach, tc) {
	atf_tc_set_md_var(tc, "descr", "iptree destroy tests");
}
ATF_TC_BODY(iptree_destroy_foreach, tc) {
	isc_result_t result;
	isc_mem_t *mctx;
	unsigned int i;
	destroy_testcase_t tests[] = {
		{ { 1, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 2, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 3, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 4, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 5, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 6, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 7, 0, 0, 0, 0, 0, 0 }, 6 },

		{ { 1, 2, 0, 0, 0, 0, 0 }, 7 },
		{ { 1, 3, 0, 0, 0, 0, 0 }, 7 },
		{ { 2, 4, 0, 0, 0, 0, 0 }, 5 },
		{ { 2, 5, 0, 0, 0, 0, 0 }, 5 },
		{ { 3, 6, 0, 0, 0, 0, 0 }, 5 },
		{ { 3, 7, 0, 0, 0, 0, 0 }, 5 },
		{ { 2, 6, 0, 0, 0, 0, 0 }, 6 },
		{ { 3, 5, 0, 0, 0, 0, 0 }, 6 },

		{ { 1, 2, 3, 0, 0, 0, 0 }, 7 },
		{ { 2, 4, 5, 0, 0, 0, 0 }, 4 },
		{ { 3, 6, 7, 0, 0, 0, 0 }, 4 },
		{ { 1, 2, 4, 0, 0, 0, 0 }, 5 },
		{ { 1, 2, 5, 0, 0, 0, 0 }, 5 },
		{ { 1, 3, 6, 0, 0, 0, 0 }, 5 },
		{ { 1, 3, 7, 0, 0, 0, 0 }, 5 },

		{ { 1, 2, 3, 4, 5, 6, 7 }, 0 },

		{ { 1, 2, 3, 4, 5, 6, 0 }, 1 },
		{ { 2, 3, 4, 5, 6, 7, 0 }, 1 },
		{ { 3, 4, 5, 6, 7, 1, 0 }, 1 },
		{ { 4, 5, 6, 7, 1, 2, 0 }, 1 },
		{ { 5, 6, 7, 1, 2, 3, 0 }, 1 },
		{ { 6, 7, 1, 2, 3, 4, 0 }, 1 },
		{ { 7, 1, 2, 3, 4, 5, 0 }, 1 },

		{ { 1, 2, 3, 4, 5, 0, 0 }, 3 },
		{ { 2, 3, 4, 5, 6, 0, 0 }, 2 },
		{ { 3, 4, 5, 6, 7, 0, 0 }, 2 },
		{ { 4, 5, 6, 7, 1, 0, 0 }, 3 },
		{ { 5, 6, 7, 1, 2, 0, 0 }, 3 },
		{ { 6, 7, 1, 2, 3, 0, 0 }, 3 },
		{ { 7, 1, 2, 3, 4, 0, 0 }, 3 }
	};

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	for (i = 0; i < sizeof(tests) / sizeof (destroy_testcase_t); i++) {
		dns_iptree_node_t *root;
		struct in6_addr in_addr;
		isc_netaddr_t netaddr;
		dns_iptree_node_t *found_node;

		root = NULL;

		/*
		 * Build this tree (values shown are node data values):
		 *
		 *           1
		 *         /   \
		 *       2       3
		 *     /  \     /  \
		 *   4     5   6    7
		 */

		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 4);

		inet_pton(AF_INET6, "::1", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 5);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 6);

		inet_pton(AF_INET6, "::3", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 7);

		/*
		 * Now set values 0, 1, 2, 3 in implicitly created
		 * parent nodes.
		 */
		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 2);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 3);

		dns_iptree_set_data(root, (void *) 1);

		/*
		 * Destroy the tree selectively and check if appropriate
		 * numbers of unused nodes had been freed.
		 */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_testcase_cb,
					   &tests[i]);

		ATF_REQUIRE_EQ(dns_iptree_get_nodecount(root),
			       tests[i].expected_nodecount);

		/* Destroy the tree completely */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_cb, NULL);
		ATF_REQUIRE_EQ(root, NULL);
	}

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_iter__null);
ATF_TC_HEAD(iptree_iter__null, tc) {
	atf_tc_set_md_var(tc, "descr", "iptree iterator with root=NULL");
}
ATF_TC_BODY(iptree_iter__null, tc) {
	isc_result_t result;
	isc_mem_t *mctx;
	dns_iptree_iter_t *iter;
	void *data;
	dns_ecs_t ecs;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	iter = NULL;
	result = dns_iptree_iter_create(mctx, NULL, &iter);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	data = NULL;
	dns_ecs_init(&ecs);
	result = dns_iptree_iter_next(iter, &data, &ecs);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);
	ATF_REQUIRE_EQ(data, NULL);
	ATF_REQUIRE_EQ(ecs.addr.family, AF_UNSPEC);

	result = dns_iptree_iter_next(iter, &data, &ecs);
	ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

	dns_iptree_iter_destroy(&iter);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_iter);
ATF_TC_HEAD(iptree_iter, tc) {
	atf_tc_set_md_var(tc, "descr", "iptree iterator test");
}
ATF_TC_BODY(iptree_iter, tc) {
	isc_result_t result;
	isc_mem_t *mctx;
	unsigned int i;
	destroy_testcase_t tests[] = {
		{ { 1, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 2, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 3, 0, 0, 0, 0, 0, 0 }, 7 },
		{ { 4, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 5, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 6, 0, 0, 0, 0, 0, 0 }, 6 },
		{ { 7, 0, 0, 0, 0, 0, 0 }, 6 },

		{ { 1, 2, 0, 0, 0, 0, 0 }, 7 },
		{ { 1, 3, 0, 0, 0, 0, 0 }, 7 },
		{ { 2, 4, 0, 0, 0, 0, 0 }, 5 },
		{ { 2, 5, 0, 0, 0, 0, 0 }, 5 },
		{ { 3, 6, 0, 0, 0, 0, 0 }, 5 },
		{ { 3, 7, 0, 0, 0, 0, 0 }, 5 },
		{ { 2, 6, 0, 0, 0, 0, 0 }, 6 },
		{ { 3, 5, 0, 0, 0, 0, 0 }, 6 },

		{ { 1, 2, 3, 0, 0, 0, 0 }, 7 },
		{ { 2, 4, 5, 0, 0, 0, 0 }, 4 },
		{ { 3, 6, 7, 0, 0, 0, 0 }, 4 },
		{ { 1, 2, 4, 0, 0, 0, 0 }, 5 },
		{ { 1, 2, 5, 0, 0, 0, 0 }, 5 },
		{ { 1, 3, 6, 0, 0, 0, 0 }, 5 },
		{ { 1, 3, 7, 0, 0, 0, 0 }, 5 },

		{ { 1, 2, 3, 4, 5, 6, 7 }, 0 },

		{ { 1, 2, 3, 4, 5, 6, 0 }, 1 },
		{ { 2, 3, 4, 5, 6, 7, 0 }, 1 },
		{ { 3, 4, 5, 6, 7, 1, 0 }, 1 },
		{ { 4, 5, 6, 7, 1, 2, 0 }, 1 },
		{ { 5, 6, 7, 1, 2, 3, 0 }, 1 },
		{ { 6, 7, 1, 2, 3, 4, 0 }, 1 },
		{ { 7, 1, 2, 3, 4, 5, 0 }, 1 },

		{ { 1, 2, 3, 4, 5, 0, 0 }, 3 },
		{ { 2, 3, 4, 5, 6, 0, 0 }, 2 },
		{ { 3, 4, 5, 6, 7, 0, 0 }, 2 },
		{ { 4, 5, 6, 7, 1, 0, 0 }, 3 },
		{ { 5, 6, 7, 1, 2, 0, 0 }, 3 },
		{ { 6, 7, 1, 2, 3, 0, 0 }, 3 },
		{ { 7, 1, 2, 3, 4, 0, 0 }, 3 }
	};
	size_t node_order[7] = {
		1, 2, 4, 5, 3, 6, 7
	};

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	for (i = 0; i < sizeof(tests) / sizeof (destroy_testcase_t); i++) {
		dns_iptree_node_t *root;
		struct in6_addr in_addr;
		isc_netaddr_t netaddr;
		dns_iptree_node_t *found_node;

		root = NULL;

		/*
		 * Build this tree (values shown are node data values):
		 *
		 *           1
		 *         /   \
		 *       2       3
		 *     /  \     /  \
		 *   4     5   6    7
		 */

		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 4);

		inet_pton(AF_INET6, "::1", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 5);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 6);

		inet_pton(AF_INET6, "::3", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 7);

		/*
		 * Now set values 0, 1, 2, 3 in implicitly created
		 * parent nodes.
		 */
		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 2);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   ISC_TRUE, NULL, NULL, &found_node);
		ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		ATF_REQUIRE(root != NULL);
		ATF_REQUIRE(found_node != NULL);

		dns_iptree_set_data(found_node, (void *) 3);

		dns_iptree_set_data(root, (void *) 1);

		/*
		 * Destroy the tree selectively and check if appropriate
		 * numbers of unused nodes had been freed.
		 */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_testcase_cb,
					   &tests[i]);

		ATF_REQUIRE_EQ(dns_iptree_get_nodecount(root),
			       tests[i].expected_nodecount);

		/*
		 * Iterate over the remaining nodes and check that they
		 * are in order and that none of the deleted nodes are
		 * found.
		 */
		{
			dns_iptree_iter_t *iter;
			size_t value;
			int last_found;
			int j;
			unsigned int count, expected_count;

			iter = NULL;
			result = dns_iptree_iter_create(mctx, root, &iter);
			ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

			last_found = -1;
			count = 0;
			while (result == ISC_R_SUCCESS) {
				void *data;
				dns_ecs_t ecs;

				data = NULL;
				dns_ecs_init(&ecs);

				result = dns_iptree_iter_next(iter, &data, &ecs);
				if (result == ISC_R_SUCCESS) {
					count++;

					/*
					 * Check the data returned.
					 */

					ATF_REQUIRE(data != NULL);

					value = (size_t) data;
					for (j = 0; j < 7; j++) {
						ATF_REQUIRE(tests[i].nodes_to_delete[j] != value);
						if (node_order[j] == value)
							break;
					}
					ATF_REQUIRE(j < 7);
					ATF_REQUIRE(last_found < j);
					last_found = j;

					/*
					 * Check the ECS struct
					 * returned.
					 */

					ATF_REQUIRE_EQ(ecs.addr.family, AF_INET6);
				} else {
					ATF_REQUIRE_EQ(data, NULL);
					ATF_REQUIRE_EQ(ecs.addr.family, AF_UNSPEC);
				}
			}

			ATF_REQUIRE_EQ(result, ISC_R_NOMORE);

			expected_count = 7;
			for (j = 0; j < 7; j++)
				if (tests[i].nodes_to_delete[j] != 0)
					expected_count--;

			ATF_REQUIRE_EQ(count, expected_count);

			dns_iptree_iter_destroy(&iter);
		}

		/* Destroy the tree completely */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_cb, NULL);
		ATF_REQUIRE_EQ(root, NULL);
	}

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_left_parent);
ATF_TC_HEAD(iptree_search_insert_left_parent, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a left parent "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_left_parent, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.2.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Insert 10.2.2.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Now, 10.2.2.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_right_parent);
ATF_TC_HEAD(iptree_search_insert_right_parent, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a right parent "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_right_parent, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.3.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Insert 10.2.3.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Now, 10.2.3.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_left_child);
ATF_TC_HEAD(iptree_search_insert_left_child, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a left child "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_left_child, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.2.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.2.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.2.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_right_child);
ATF_TC_HEAD(iptree_search_insert_right_child, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a right child "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_right_child, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.3.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.3.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.3.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_left_sibling);
ATF_TC_HEAD(iptree_search_insert_left_sibling, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a left sibling "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_left_sibling, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	root = NULL;

	/* Insert 10.2.3.4/24. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.2.4/24. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.2.4/24 should be found. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.3.4/24 should also be found. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

ATF_TC(iptree_search_insert_right_sibling);
ATF_TC_HEAD(iptree_search_insert_right_sibling, tc) {
	atf_tc_set_md_var(tc, "descr",
			  "Check that inserting to a right sibling "
			  "of an existing node works");
}
ATF_TC_BODY(iptree_search_insert_right_sibling, tc) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(tc);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	root = NULL;

	/* Insert 10.2.2.4/24. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.3.4/24. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   ISC_TRUE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.3.4/24 should be found. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* 10.2.2.4/24 should also be found. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   ISC_FALSE, NULL, NULL, &found_node);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	ATF_REQUIRE(root != NULL);
	ATF_REQUIRE(found_node != NULL);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	ATF_REQUIRE_EQ(root, NULL);

	isc_mem_destroy(&mctx);
	ATF_REQUIRE_EQ(mctx, NULL);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, iptree_destroy_foreach__null);

	ATF_TP_ADD_TC(tp, iptree_common_prefix);

	ATF_TP_ADD_TC(tp, iptree_search__null_root_no_create);
	ATF_TP_ADD_TC(tp, iptree_search_v4);
	ATF_TP_ADD_TC(tp, iptree_search_v6);

	ATF_TP_ADD_TC(tp, iptree_search_v4_exact_is_non_matching);
	ATF_TP_ADD_TC(tp, iptree_search_v4_partial_is_non_matching);

	ATF_TP_ADD_TC(tp, iptree_foreach);

	ATF_TP_ADD_TC(tp, iptree_search_v6_byteorder);

	ATF_TP_ADD_TC(tp, iptree_destroy_foreach);

	ATF_TP_ADD_TC(tp, iptree_iter__null);
	ATF_TP_ADD_TC(tp, iptree_iter);

	ATF_TP_ADD_TC(tp, iptree_search_insert_left_parent);
	ATF_TP_ADD_TC(tp, iptree_search_insert_right_parent);
	ATF_TP_ADD_TC(tp, iptree_search_insert_left_child);
	ATF_TP_ADD_TC(tp, iptree_search_insert_right_child);
	ATF_TP_ADD_TC(tp, iptree_search_insert_left_sibling);
	ATF_TP_ADD_TC(tp, iptree_search_insert_right_sibling);

	return (atf_no_error());
}

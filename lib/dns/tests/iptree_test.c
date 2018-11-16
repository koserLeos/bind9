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

#if HAVE_CMOCKA

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/netaddr.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/iptree.h>
#include <dns/ecs.h>

static bool
destroy_cb(void **data, void *destroy_arg) {
	size_t *count;

	REQUIRE(data != NULL && *data != NULL);

	count = (size_t *) destroy_arg;
	if (count != NULL) {
		(*count)++;
	}

	*data = NULL;

	/* Return value does not matter here. */
	return (false);
}

static bool
callback_fn(void **data, void *callback_arg) {
	size_t *count;

	REQUIRE(data != NULL && *data != NULL);

	count = (size_t *) callback_arg;
	(*count)++;

	/* Return value does not matter here. */
	return (false);
}

/* destroy iptree with root=NULL */
static void
iptree_destroy_foreach__null(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	root = NULL;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, NULL);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* iptree_common_prefix */
static void
iptree_common_prefix(void **state) {
	int diff;

	UNUSED(state);

	{
		const uint32_t addr_a[4] = { 0, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 128);
	}

	{
		const uint32_t addr_a[4] = { 0, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 32, addr_b, 32);
		assert_int_equal(diff, 32);
	}

	{
		const uint32_t addr_a[4] = { 0x42000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x42000000, 0, 0, 0 };

		/* addresses are equal */
		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 128);
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
		assert_int_equal(diff, 128);
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
		assert_int_equal(diff, 32);
	}

	{
		const uint32_t addr_a[4] = { 0x80000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x40000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 0);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x40000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 0);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0 };
		const uint32_t addr_b[4] = { 0x80000000, 0, 0, 0 };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 1);
	}

	{
		const uint32_t addr_a[4] = { 0xc0000000, 0, 0, 0x000000ff };
		const uint32_t addr_b[4] = { 0x80000000, 0, 0, 0x000000ff };

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 1);
	}

	{
		const uint32_t addr_a[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020304
		};
		const uint32_t addr_b[4] = {
			0x00000000, 0, 0x0000ffff, 0x01020300
		};

		diff = dns_iptree_common_prefix(addr_a, 128, addr_b, 128);
		assert_int_equal(diff, 125);
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
		assert_int_equal(diff, 32);
	}
}

/* search iptree with root=NULL, create=false */
static void
iptree_search__null_root_no_create(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	in_addr.s_addr = inet_addr("1.2.3.4");
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;
	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_null(root);
	assert_null(found_node);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* search IPv4 iptree with root=NULL, create=true */
static void
iptree_search_v4(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0x809ffbc1;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_EXISTS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Repeat with create=false */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	/* Look for the inserted 0/0 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 1, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for the inserted old 1.2.3.4/32. It should still be
	 * present.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for 1.2.3.4/24 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	inet_pton(AF_INET, "1.2.3.1", &in_addr2);
	isc_netaddr_fromin(&netaddr2, &in_addr2);

	/*
	 * Look for 1.2.3.1/24 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Create 1.2.3.1/32. */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 32, 32,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/* Set some dummy data */
	*found_data = (void *) 0xabcdabcd;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 32, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xabcdabcd);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/*
	 * Create 1.2.3.1/24/26.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 24, 26,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 26);

	/* Set some dummy data */
	*found_data = (void *) 0xf000f000;

	/*
	 * Search for 1.2.3.1/24. It should be found (exact match).
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf000f000);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 26);

	/*
	 * Search for 1.2.3.1/25. The longer 1.2.3.1/24 should not be
	 * found as it is an exact-match address prefix; instead
	 * 0/0 should be found.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 25, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	/*
	 * Search for 1.2.3.1/24 again. It should be found (exact
	 * match).
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf000f000);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 26);

	/*
	 * Clear the node data, effectively deleting that address
	 * prefix.
	 */
	*found_data = NULL;

	/*
	 * Create 1.2.3.1/24 with exact_match=false.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 24);

	/* Set some dummy data */
	*found_data = (void *) 0xb000b000;

	/*
	 * Search for 1.2.3.1/24. It should be found.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xb000b000);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 24);

	/*
	 * Search for 1.2.3.1/25. The longer 1.2.3.1/24 should be found
	 * as it is not an exact-match address prefix.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 25, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xb000b000);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 24);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);
	/* dcount should be 4 (count - 1, where 1 is the fork node). */
	assert_int_equal(dcount, 4);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* search IPv6 iptree with root=NULL, create=true */
static void
iptree_search_v6(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET6, "1:2:3:4::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0x809ffbc1;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;

	root_copy = root;
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_EXISTS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Repeat with create=false */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 128, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 1, 0,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	/* Look for the inserted 0/0 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 1, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for the inserted old 1:2:3:4::1/128. It should still be
	 * present.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 128, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0x809ffbc1);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for 1:2:3:4::1/120 - should get a PARTIALMATCH against
	 * 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 120, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	inet_pton(AF_INET6, "1:2:3:1::1", &in_addr2);
	isc_netaddr_fromin6(&netaddr2, &in_addr2);

	/*
	 * Look for 1:2:3:1::1/120 - should get a PARTIALMATCH against 0/0.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 120, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xf0173712);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Create 1:2:3:1::1/128. */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 128, 128,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/* Set some dummy data */
	*found_data = (void *) 0xabcdabcd;

	/* Now look for the inserted data */
	found_data = NULL;
	found_address_prefix_length = 255;
	root_copy = root;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr2, 128, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(root, root_copy);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xabcdabcd);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/*
	 * IPv4 lookup for 0.0.0.0/1 should not PARTIALMATCH anything,
	 * even though there is a /0 node in the tree, because there is
	 * no ::ffff:0.0.0.0/96 node in the tree.
	 */
	inet_pton(AF_INET, "1.2.3.1", &in_addr3);
	isc_netaddr_fromin(&netaddr3, &in_addr3);

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr3, 1, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_null(found_node);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);
	/* dcount should be 3 (count - 1, where 1 is the fork node). */
	assert_int_equal(dcount, 3);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* test dns_iptree_foreach() */
static void
iptree_foreach(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Create 1:2:3:4::1/128 */
	inet_pton(AF_INET6, "1:2:3:4::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 0);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 1, 0,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Create 1:2:3:1::1/128. */
	inet_pton(AF_INET6, "1:2:3:1::1", &in_addr2);
	isc_netaddr_fromin6(&netaddr2, &in_addr2);

	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr2, 128, 128,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 128);
	assert_int_equal(found_scope_prefix_length, 128);

	/* Set some dummy data */
	*found_data = (void *) 0xf0173712;

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/* Test the callback */
	cbcount = 0;
	dns_iptree_foreach(root, callback_fn, &cbcount);
	/* cbcount should be 3 (count - 1, where 1 is the fork node). */
	assert_int_equal(cbcount, 3);

	/* The tree should still exist. */
	assert_non_null(root);
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 4);

	/* Destroy the tree */
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, NULL);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

static bool
match_cb(void **data, void *match_arg) {
	UNUSED(match_arg);

	REQUIRE(data != NULL && *data != NULL);

	if (*data == (void *) 0xdd) {
		return (false);
	}

	return (true);
}

/* search IPv4 iptree where an exact match node is ignored by match callback */
static void
iptree_search_v4_exact_is_non_matching(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 0);

	/* Insert 1.2.3.4/32. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 32,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0xdd;

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

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
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xdd);
	assert_int_equal(found_address_prefix_length, 32);
	assert_int_equal(found_scope_prefix_length, 32);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for 1.2.3.4/32 with match callback which ignores 0xdd
	 * data. The 0/0 should be found in this case.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   false, match_cb, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xcc);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	assert_int_equal(dcount, 2);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* search IPv4 iptree where a partialmatch node is ignored by match callback */
static void
iptree_search_v4_partial_is_non_matching(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "1.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);
	found_data = NULL;
	found_address_prefix_length = 255;

	root = NULL;
	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 0);

	/* Insert 1.2.3.0/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 32, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 24);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 1);

	/* Set some dummy data */
	*found_data = (void *) 0xdd;

	/* Create 0/0 - a node corresponding to the global answer */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 16, 0,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_non_null(found_data);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

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
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xdd);
	assert_int_equal(found_address_prefix_length, 24);
	assert_int_equal(found_scope_prefix_length, 24);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/*
	 * Look for 1.2.3.4/32 with match callback which ignores 0xdd
	 * data. The 0/0 should be found in this case.
	 */
	found_data = NULL;
	found_address_prefix_length = 255;

	found_node = NULL;
	result = dns_iptree_search(&root, NULL, &netaddr, 32, 0,
				   false, match_cb, NULL, &found_node);
	assert_int_equal(result, DNS_R_PARTIALMATCH);
	assert_non_null(found_node);

	dns_iptree_get_data(found_node,
			    (void **) &found_data,
			    &found_address_prefix_length,
			    &found_scope_prefix_length);
	assert_ptr_equal(*found_data, (void *) 0xcc);
	assert_int_equal(found_address_prefix_length, 0);
	assert_int_equal(found_scope_prefix_length, 0);

	count = dns_iptree_get_nodecount(root);
	assert_int_equal(count, 2);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	assert_int_equal(dcount, 2);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* check that v6 byte ordering of address prefixes is correctly implemented */
static void
iptree_search_v6_byteorder(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in6_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET6, "7fff::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	root = NULL;

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 8, 8,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, ffff::1/8 should not be found. */
	inet_pton(AF_INET6, "ffff::1", &in_addr);
	isc_netaddr_fromin6(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 8, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_non_null(root);
	assert_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

typedef struct {
	unsigned int nodes_to_delete[7];
	unsigned int expected_nodecount;
} destroy_testcase_t;

static bool
destroy_testcase_cb(void **data, void *destroy_arg) {
	destroy_testcase_t *test;
	size_t value;
	int i;

	REQUIRE(data != NULL && *data != NULL);

	test = (destroy_testcase_t *) destroy_arg;
	value = (size_t) *data;

	for (i = 0; i < 7; i++) {
		if (test->nodes_to_delete[i] == 0) {
			break;
		}
		if (test->nodes_to_delete[i] == value) {
			*data = NULL;
			break;
		}
	}

	/* Return value does not matter here. */
	return (false);
}

/* iptree destroy tests */
static void
iptree_destroy_foreach(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

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
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 4);

		inet_pton(AF_INET6, "::1", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 5);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 6);

		inet_pton(AF_INET6, "::3", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 7);

		/*
		 * Now set values 0, 1, 2, 3 in implicitly created
		 * parent nodes.
		 */
		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 2);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 3);

		dns_iptree_set_data(root, (void *) 1);

		/*
		 * Destroy the tree selectively and check if appropriate
		 * numbers of unused nodes had been freed.
		 */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_testcase_cb,
					   &tests[i]);

		assert_int_equal(dns_iptree_get_nodecount(root),
				 tests[i].expected_nodecount);

		/* Destroy the tree completely */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_cb, NULL);
		assert_null(root);
	}

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* iptree iterator with root=NULL */
static void
iptree_iter__null(void **state) {
	isc_result_t result;
	isc_mem_t *mctx;
	dns_iptree_iter_t *iter;
	void *data;
	dns_ecs_t ecs;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	iter = NULL;
	result = dns_iptree_iter_create(mctx, NULL, &iter);
	assert_int_equal(result, ISC_R_SUCCESS);

	data = NULL;
	dns_ecs_init(&ecs);
	result = dns_iptree_iter_next(iter, &data, &ecs);
	assert_int_equal(result, ISC_R_NOMORE);
	assert_null(data);
	assert_int_equal(ecs.addr.family, AF_UNSPEC);

	result = dns_iptree_iter_next(iter, &data, &ecs);
	assert_int_equal(result, ISC_R_NOMORE);

	dns_iptree_iter_destroy(&iter);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* iptree iterator test */
static void
iptree_iter(void **state) {
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

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (i = 0; i < sizeof(tests) / sizeof (destroy_testcase_t); i++) {
		dns_iptree_node_t *root = NULL;
		struct in6_addr in_addr;
		isc_netaddr_t netaddr;
		dns_iptree_node_t *found_node = NULL;
		dns_iptree_iter_t *iter;
		size_t value;
		int last_found;
		int j;
		unsigned int count, expected_count;

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

		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 4);

		inet_pton(AF_INET6, "::1", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 5);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 6);

		inet_pton(AF_INET6, "::3", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 128, 128,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 7);

		/*
		 * Now set values 0, 1, 2, 3 in implicitly created
		 * parent nodes.
		 */
		inet_pton(AF_INET6, "::0", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 2);

		inet_pton(AF_INET6, "::2", &in_addr);
		isc_netaddr_fromin6(&netaddr, &in_addr);

		found_node = NULL;
		result = dns_iptree_search(&root, mctx, &netaddr, 127, 127,
					   true, NULL, NULL, &found_node);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(root);
		assert_non_null(found_node);

		dns_iptree_set_data(found_node, (void *) 3);

		dns_iptree_set_data(root, (void *) 1);

		/*
		 * Destroy the tree selectively and check if appropriate
		 * numbers of unused nodes had been freed.
		 */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_testcase_cb,
					   &tests[i]);

		assert_int_equal(dns_iptree_get_nodecount(root),
				 tests[i].expected_nodecount);

		/*
		 * Iterate over the remaining nodes and check that they
		 * are in order and that none of the deleted nodes are
		 * found.
		 */
		iter = NULL;
		result = dns_iptree_iter_create(mctx, root, &iter);
		assert_int_equal(result, ISC_R_SUCCESS);

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

				assert_non_null(data);

				value = (size_t) data;
				for (j = 0; j < 7; j++) {
					assert_ptr_not_equal(value,
						tests[i].nodes_to_delete[j]);
					if (node_order[j] == value) {
						break;
					}
				}
				assert_true(j < 7);
				assert_true(last_found < j);
				last_found = j;

				/*
				 * Check the ECS struct
				 * returned.
				 */

				assert_int_equal(ecs.addr.family, AF_INET6);
			} else {
				assert_null(data);
				assert_int_equal(ecs.addr.family, AF_UNSPEC);
			}
		}

		assert_int_equal(result, ISC_R_NOMORE);

		expected_count = 7;
		for (j = 0; j < 7; j++) {
			if (tests[i].nodes_to_delete[j] != 0) {
				expected_count--;
			}
		}

		assert_int_equal(count, expected_count);

		dns_iptree_iter_destroy(&iter);

		/* Destroy the tree completely */
		dns_iptree_destroy_foreach(&root, mctx,
					   destroy_cb, NULL);
		assert_null(root);
	}

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a left parent of an existing node works */
static void
iptree_search_insert_left_parent(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.2.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Insert 10.2.2.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Now, 10.2.2.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a right parent of an existing node works */
static void
iptree_search_insert_right_parent(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.3.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Insert 10.2.3.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Now, 10.2.3.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a left child of an existing node works */
static void
iptree_search_insert_left_child(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.2.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.2.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.2.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a right child of an existing node works */
static void
iptree_search_insert_right_child(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	root = NULL;

	/* Insert 10.2.3.4/23/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.3.4/24. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.3.4/24 should be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.3.4/23 should also be found. */
	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 23, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a left sibling of an existing node works */
static void
iptree_search_insert_left_sibling(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	root = NULL;

	/* Insert 10.2.3.4/24. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.2.4/24. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.2.4/24 should be found. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.3.4/24 should also be found. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

/* Check that inserting to a right sibling of an existing node works */
static void
iptree_search_insert_right_sibling(void **state) {
	isc_mem_t *mctx;
	isc_result_t result;
	dns_iptree_node_t *root;
	struct in_addr in_addr;
	isc_netaddr_t netaddr;
	dns_iptree_node_t *found_node;
	size_t dcount;

	UNUSED(state);

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	root = NULL;

	/* Insert 10.2.2.4/24. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x5678);

	/* Insert 10.2.3.4/24. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 24,
				   true, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Set some dummy data */
	dns_iptree_set_data(found_node, (void *) 0x1234);

	/* Now, 10.2.3.4/24 should be found. */
	inet_pton(AF_INET, "10.2.3.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* 10.2.2.4/24 should also be found. */
	inet_pton(AF_INET, "10.2.2.4", &in_addr);
	isc_netaddr_fromin(&netaddr, &in_addr);

	found_node = NULL;
	result = dns_iptree_search(&root, mctx, &netaddr, 24, 0,
				   false, NULL, NULL, &found_node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(root);
	assert_non_null(found_node);

	/* Destroy the tree */
	dcount = 0;
	dns_iptree_destroy_foreach(&root, mctx, destroy_cb, &dcount);
	assert_null(root);

	isc_mem_destroy(&mctx);
	assert_null(mctx);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(iptree_destroy_foreach__null),
		cmocka_unit_test(iptree_common_prefix),
		cmocka_unit_test(iptree_search__null_root_no_create),
		cmocka_unit_test(iptree_search_v4),
		cmocka_unit_test(iptree_search_v6),
		cmocka_unit_test(iptree_search_v4_exact_is_non_matching),
		cmocka_unit_test(iptree_search_v4_partial_is_non_matching),
		cmocka_unit_test(iptree_foreach),
		cmocka_unit_test(iptree_search_v6_byteorder),
		cmocka_unit_test(iptree_destroy_foreach),
		cmocka_unit_test(iptree_iter__null),
		cmocka_unit_test(iptree_iter),
		cmocka_unit_test(iptree_search_insert_left_parent),
		cmocka_unit_test(iptree_search_insert_right_parent),
		cmocka_unit_test(iptree_search_insert_left_child),
		cmocka_unit_test(iptree_search_insert_right_child),
		cmocka_unit_test(iptree_search_insert_left_sibling),
		cmocka_unit_test(iptree_search_insert_right_sibling),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif

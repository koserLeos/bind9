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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/app.h>
#include <isc/commandline.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/cache.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/db.h>
#include <dns/rdatalist.h>
#include "dnstest.h"

#define SETCACHESIZE_TEST_DURATION_SECONDS 5
#define SETCACHESIZE_LIMIT_BYTES (2U * 1024 * 1024)
#define SETCACHESIZE_NAMECOUNT 1024

/* Set to true for verbose output */
static bool verbose = false;

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dns_test_begin(NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	dns_test_end();

	return (0);
}

typedef struct {
	isc_mem_t *cmctx;
	isc_mem_t *hmctx;
	dns_db_t *db;
	dns_fixedname_t *fnames;
	dns_name_t **names;
} testctx_t;

static void
run(isc_task_t *task, isc_event_t *event) {
	testctx_t *testctx = (testctx_t *) (event->ev_arg);
	isc_stdtime_t start, now;
	unsigned int i;
	isc_result_t result;

	UNUSED(task);

	/*
	 * Now add random cache entries in a loop during the test
	 * duration. The cache should not go above limit.
	 */
	isc_stdtime_get(&start);
	now = start;
	i = 0;
	while ((now - start) < SETCACHESIZE_TEST_DURATION_SECONDS) {
		dns_dbnode_t *node;
		dns_rdata_t rdata;
		dns_rdatalist_t rdatalist;
		dns_rdataset_t rdataset;
		dns_clientinfo_t ci;
		struct in_addr in_addr;
		uint8_t a_data[4];
		isc_stdtime_t last;
		long r;

		node = NULL;
		result = dns_db_findnode(testctx->db, testctx->names[i],
					 true, &node);
		assert_true(result == ISC_R_SUCCESS || result == ISC_R_EXISTS);
		assert_non_null(node);

		r = random();

		a_data[0] = r & 0xff;
		a_data[1] = (r >> 8) & 0xff;
		a_data[2] = (r >> 16) & 0xff;
		a_data[3] = (r >> 24) & 0xff;

		dns_rdata_init(&rdata);
		DE_CONST(a_data, rdata.data);
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
		assert_int_equal(result, ISC_R_SUCCESS);

		dns_clientinfo_init(&ci, NULL, NULL, NULL);
		in_addr.s_addr = random();
		isc_netaddr_fromin(&ci.ecs.addr, &in_addr);
		ci.ecs.source = r % 32;
		ci.ecs.scope = ci.ecs.source;

		result = dns_db_addrdatasetext(testctx->db, node, NULL, now,
					       &rdataset, 0,
					       NULL, &ci, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		if (dns_rdataset_isassociated(&rdataset))
			dns_rdataset_disassociate(&rdataset);
		dns_rdataset_invalidate(&rdataset);

		dns_db_detachnode(testctx->db, &node);

		/*
		 * This is the main assertion of the unittest. We assert
		 * that we never go above the maximum configured cache
		 * size.
		 */
		assert_true(isc_mem_inuse(testctx->cmctx) <
			    SETCACHESIZE_LIMIT_BYTES);

		last = now;
		isc_stdtime_get(&now);
		if (verbose && now - last > 0) {
			print_message("# Current usage: %zd/%u\n",
				      isc_mem_inuse(testctx->cmctx),
				      SETCACHESIZE_LIMIT_BYTES);
			print_message("# Running for another %u seconds\n",
				      (SETCACHESIZE_TEST_DURATION_SECONDS -
				       (now - start)));
		}
		i = (i + 1) % SETCACHESIZE_NAMECOUNT;
	}

	isc_event_free(&event);
	isc_app_shutdown();
}

/* test dns_cache_setcachesize */
static void
setcachesize(void **state) {
	isc_result_t result;
	dns_cache_t *cache;
	char namestr[sizeof("name18446744073709551616.example.org.")];
	unsigned int i;
	testctx_t testctx;

	UNUSED(state);

	debug_mem_record = false;

	testctx.fnames = isc_mem_get(mctx,
				     sizeof(dns_fixedname_t) *
				     SETCACHESIZE_NAMECOUNT);
	testctx.names = isc_mem_get(mctx,
				    sizeof(dns_name_t *) *
				    SETCACHESIZE_NAMECOUNT);

	testctx.cmctx = NULL;
	result = isc_mem_create(0, 0, &testctx.cmctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	testctx.hmctx = NULL;
	result = isc_mem_create(0, 0, &testctx.hmctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	cache = NULL;
	result = dns_cache_create3(testctx.cmctx, testctx.hmctx,
				   taskmgr, timermgr, dns_rdataclass_in,
				   "testcache", "rbt", 0, NULL, &cache);

	testctx.db = NULL;
	dns_cache_attachdb(cache, &testctx.db);

	/* Set cache size */
	dns_cache_setcachesize(cache, SETCACHESIZE_LIMIT_BYTES);

	for (i = 0; i < SETCACHESIZE_NAMECOUNT; i++) {
		unsigned int r;

		r = random();
		snprintf(namestr, sizeof(namestr), "name%u.example.org.", r);
		result = dns_test_namefromstring(namestr, &testctx.fnames[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
		testctx.names[i] = dns_fixedname_name(&testctx.fnames[i]);
	}

	isc_app_onrun(mctx, maintask, run, &testctx);
	isc_app_run();

	dns_db_detach(&testctx.db);
	dns_cache_detach(&cache);
	isc_mem_detach(&testctx.hmctx);
	isc_mem_detach(&testctx.cmctx);

	isc_mem_put(mctx, testctx.fnames,
		    sizeof(dns_fixedname_t) * SETCACHESIZE_NAMECOUNT);
	isc_mem_put(mctx, testctx.names,
		    sizeof(dns_name_t *) * SETCACHESIZE_NAMECOUNT);
}

int
main(int argc, char **argv) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(setcachesize,
						_setup, _teardown),
	};
	int c;

	while ((c = isc_commandline_parse(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = true;
			break;
		default:
			break;
		}
	}


	return (cmocka_run_group_tests(tests, dns_test_init, dns_test_final));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);
}

#endif

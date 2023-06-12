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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/file.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/nsec3.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>

#include <tests/dns.h>

static char tempname[11] = "dtXXXXXXXX";
static dns_db_t *db1 = NULL, *db2 = NULL;
static dns_dbversion_t *v1 = NULL, *v2 = NULL;

/*
 * The code below enables us to trap assertion failures for testing
 * purposes. local_callback() is set as the callback function for
 * isc_assertion_failed(). It calls mock_assert() so that CMOCKA
 * will be able to see it, then returns to the calling function via
 * longjmp() so that the abort() call in isc_assertion_failed() will
 * never be reached. Use check_assertion() to check for assertions
 * instead of expect_assert_failure().
 */
jmp_buf assertion;

#define check_assertion(function_call)                        \
	do {                                                  \
		const int r = setjmp(assertion);              \
		if (r == 0) {                                 \
			expect_assert_failure(function_call); \
		}                                             \
	} while (false);

static void
local_callback(const char *file, int line, isc_assertiontype_t type,
	       const char *cond) {
	UNUSED(type);

	mock_assert(1, cond, file, line);
	longjmp(assertion, 1);
}

static int
setup_test(void **state) {
	isc_result_t res;

	UNUSED(state);

	isc_assertion_setcallback(local_callback);

	res = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &db1);
	assert_int_equal(res, ISC_R_SUCCESS);
	dns_db_newversion(db1, &v1);
	assert_non_null(v1);

	res = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &db2);
	assert_int_equal(res, ISC_R_SUCCESS);
	dns_db_newversion(db2, &v2);
	assert_non_null(v1);

	return (0);
}

static int
teardown_test(void **state) {
	UNUSED(state);

	if (strcmp(tempname, "dtXXXXXXXX") != 0) {
		unlink(tempname);
	}

	if (v1 != NULL) {
		dns_db_closeversion(db1, &v1, false);
		assert_null(v1);
	}
	if (db1 != NULL) {
		dns_db_detach(&db1);
		assert_null(db1);
	}

	if (v2 != NULL) {
		dns_db_closeversion(db2, &v2, false);
		assert_null(v2);
	}
	if (db2 != NULL) {
		dns_db_detach(&db2);
		assert_null(db2);
	}

	return (0);
}

/*
 * Check dns_db_attachversion() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(attachversion)
void run_test_attachversion(void **state __attribute__((unused)));
void run_test_attachversion(void **state __attribute__((unused))) {
	dns_dbversion_t *v = NULL;

	UNUSED(state);

	dns_db_attachversion(db1, v1, &v);
	assert_ptr_equal(v, v1);
	dns_db_closeversion(db1, &v, false);
	assert_null(v);

	check_assertion(dns_db_attachversion(db1, v2, &v));
}

/*
 * Check dns_db_closeversion() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(closeversion)
void run_test_closeversion(void **state __attribute__((unused)));
void run_test_closeversion(void **state __attribute__((unused))) {
	UNUSED(state);

	assert_non_null(v1);
	dns_db_closeversion(db1, &v1, false);
	assert_null(v1);

	check_assertion(dns_db_closeversion(db1, &v2, false));
}

/*
 * Check dns_db_find() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(find)
void run_test_find(void **state __attribute__((unused)));
void run_test_find(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_rdataset_t rdataset;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	UNUSED(state);

	name = dns_fixedname_initname(&fixed);

	dns_rdataset_init(&rdataset);
	res = dns_db_find(db1, dns_rootname, v1, dns_rdatatype_soa, 0, 0, NULL,
			  name, &rdataset, NULL);
	assert_int_equal(res, DNS_R_NXDOMAIN);

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	dns_rdataset_init(&rdataset);
	check_assertion((void)dns_db_find(db1, dns_rootname, v2,
					  dns_rdatatype_soa, 0, 0, NULL, name,
					  &rdataset, NULL));
}

/*
 * Check dns_db_allrdatasets() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(allrdatasets)
void run_test_allrdatasets(void **state __attribute__((unused)));
void run_test_allrdatasets(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_dbnode_t *node = NULL;
	dns_rdatasetiter_t *iterator = NULL;

	UNUSED(state);

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_allrdatasets(db1, node, v1, 0, 0, &iterator);
	assert_int_equal(res, ISC_R_SUCCESS);

	check_assertion(dns_db_allrdatasets(db1, node, v2, 0, 0, &iterator));

	dns_rdatasetiter_destroy(&iterator);
	assert_null(iterator);

	dns_db_detachnode(db1, &node);
	assert_null(node);
}

/*
 * Check dns_db_findrdataset() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(findrdataset)
void run_test_findrdataset(void **state __attribute__((unused)));
void run_test_findrdataset(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_rdataset_t rdataset;
	dns_dbnode_t *node = NULL;

	UNUSED(state);

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	dns_rdataset_init(&rdataset);
	res = dns_db_findrdataset(db1, node, v1, dns_rdatatype_soa, 0, 0,
				  &rdataset, NULL);
	assert_int_equal(res, ISC_R_NOTFOUND);

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	dns_rdataset_init(&rdataset);
	check_assertion(dns_db_findrdataset(db1, node, v2, dns_rdatatype_soa, 0,
					    0, &rdataset, NULL));

	dns_db_detachnode(db1, &node);
	assert_null(node);
}

/*
 * Check dns_db_deleterdataset() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(deleterdataset)
void run_test_deleterdataset(void **state __attribute__((unused)));
void run_test_deleterdataset(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_dbnode_t *node = NULL;

	UNUSED(state);

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_deleterdataset(db1, node, v1, dns_rdatatype_soa, 0);
	assert_int_equal(res, DNS_R_UNCHANGED);

	check_assertion(
		dns_db_deleterdataset(db1, node, v2, dns_rdatatype_soa, 0));
	dns_db_detachnode(db1, &node);
	assert_null(node);
}

/*
 * Check dns_db_subtractrdataset() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(subtract)
void run_test_subtract(void **state __attribute__((unused)));
void run_test_subtract(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_rdataset_t rdataset;
	dns_rdatalist_t rdatalist;
	dns_dbnode_t *node = NULL;

	UNUSED(state);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_init(&rdatalist);

	rdatalist.rdclass = dns_rdataclass_in;

	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_subtractrdataset(db1, node, v1, &rdataset, 0, NULL);
	assert_int_equal(res, DNS_R_UNCHANGED);

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	check_assertion(
		dns_db_subtractrdataset(db1, node, v2, &rdataset, 0, NULL));

	dns_db_detachnode(db1, &node);
	assert_null(node);
}

/*
 * Check dns_db_dump() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(dump)
void run_test_dump(void **state __attribute__((unused)));
void run_test_dump(void **state __attribute__((unused))) {
	isc_result_t res;
	FILE *f = NULL;

	UNUSED(state);

	res = isc_file_openunique(tempname, &f);
	fclose(f);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_dump(db1, v1, tempname);
	assert_int_equal(res, ISC_R_SUCCESS);

	check_assertion(dns_db_dump(db1, v2, tempname));
}

/*
 * Check dns_db_addrdataset() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(addrdataset)
void run_test_addrdataset(void **state __attribute__((unused)));
void run_test_addrdataset(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_rdataset_t rdataset;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;

	UNUSED(state);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_init(&rdatalist);

	rdatalist.rdclass = dns_rdataclass_in;

	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_addrdataset(db1, node, v1, 0, &rdataset, 0, NULL);
	assert_int_equal(res, ISC_R_SUCCESS);

	check_assertion(
		dns_db_addrdataset(db1, node, v2, 0, &rdataset, 0, NULL));

	dns_db_detachnode(db1, &node);
	assert_null(node);
}

/*
 * Check dns_db_getnsec3parameters() passes with matching db and version,
 * and asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(getnsec3parameters)
void run_test_getnsec3parameters(void **state __attribute__((unused)));
void run_test_getnsec3parameters(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_hash_t hash;
	uint8_t flags;
	uint16_t iterations;
	unsigned char salt[DNS_NSEC3_SALTSIZE];
	size_t salt_length = sizeof(salt);

	UNUSED(state);

	res = dns_db_getnsec3parameters(db1, v1, &hash, &flags, &iterations,
					salt, &salt_length);
	assert_int_equal(res, ISC_R_NOTFOUND);

	check_assertion(dns_db_getnsec3parameters(
		db1, v2, &hash, &flags, &iterations, salt, &salt_length));
}

/*
 * Check dns_db_resigned() passes with matching db and version, and
 * asserts with mis-matching db and version.
 */
// ISC_RUN_TEST_IMPL(resigned)
void run_test_resigned(void **state __attribute__((unused)));
void run_test_resigned(void **state __attribute__((unused))) {
	isc_result_t res;
	dns_rdataset_t rdataset, added;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdata_rrsig_t rrsig;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_buffer_t b;
	unsigned char buf[1024];

	UNUSED(state);

	/*
	 * Create a dummy RRSIG record and set a resigning time.
	 */
	dns_rdataset_init(&added);
	dns_rdataset_init(&rdataset);
	dns_rdatalist_init(&rdatalist);
	isc_buffer_init(&b, buf, sizeof(buf));

	DNS_RDATACOMMON_INIT(&rrsig, dns_rdatatype_rrsig, dns_rdataclass_in);
	rrsig.covered = dns_rdatatype_a;
	rrsig.algorithm = 100;
	rrsig.labels = 0;
	rrsig.originalttl = 0;
	rrsig.timeexpire = 3600;
	rrsig.timesigned = 0;
	rrsig.keyid = 0;
	dns_name_init(&rrsig.signer, NULL);
	dns_name_clone(dns_rootname, &rrsig.signer);
	rrsig.siglen = 0;
	rrsig.signature = NULL;

	res = dns_rdata_fromstruct(&rdata, dns_rdataclass_in,
				   dns_rdatatype_rrsig, &rrsig, &b);
	assert_int_equal(res, ISC_R_SUCCESS);

	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_rrsig;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	rdataset.attributes |= DNS_RDATASETATTR_RESIGN;
	rdataset.resign = 7200;

	res = dns_db_findnode(db1, dns_rootname, false, &node);
	assert_int_equal(res, ISC_R_SUCCESS);

	res = dns_db_addrdataset(db1, node, v1, 0, &rdataset, 0, &added);
	assert_int_equal(res, ISC_R_SUCCESS);

	dns_db_detachnode(db1, &node);
	assert_null(node);

	check_assertion(dns_db_resigned(db1, &added, v2));

	dns_db_resigned(db1, &added, v1);

	dns_rdataset_disassociate(&added);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(dump, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(find, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(allrdatasets, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(findrdataset, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(deleterdataset, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(subtract, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(addrdataset, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(getnsec3parameters, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(resigned, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(attachversion, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(closeversion, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN

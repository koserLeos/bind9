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

#include <string.h>

#include <isc/result.h>
#include <pk11/result.h>

ATF_TC(tables);
ATF_TC_HEAD(tables, tc) {
	atf_tc_set_md_var(tc, "descr", "check tables are populated");
}
ATF_TC_BODY(tables, tc) {
	const char *str;
	isc_result_t result;

#ifdef PKCS11CRYPTO
	pk11_result_register();
#endif

	for (result = 0; result < ISC_R_NRESULTS; result++) {
		str = isc_result_toid(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_toid(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
			      "(result code text not available)") != 0,
			      "isc_result_toid(%u) returned %s", result, str);

		str = isc_result_totext(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_totext(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
			      "(result code text not available)") != 0,
			      "isc_result_totext(%u) returned %s", result, str);
	}

	str = isc_result_toid(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");

	str = isc_result_totext(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");

#ifdef PKCS11CRYPTO
	for (result = ISC_RESULTCLASS_PK11;
	     result < (ISC_RESULTCLASS_PK11 + PK11_R_NRESULTS);
	     result++)
	{
		str = isc_result_toid(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_toid(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
			      "(result code text not available)") != 0,
			      "isc_result_toid(%u) returned %s", result, str);

		str = isc_result_totext(result);
		ATF_REQUIRE_MSG(str != NULL,
				"isc_result_totext(%u) returned NULL", result);
		ATF_CHECK_MSG(strcmp(str,
			      "(result code text not available)") != 0,
			      "isc_result_totext(%u) returned %s", result, str);
	}

	str = isc_result_toid(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");

	str = isc_result_totext(result);
	ATF_REQUIRE(str != NULL);
	ATF_CHECK_STREQ(str, "(result code text not available)");
#endif
}

ATF_TC(isc_result_toid);
ATF_TC_HEAD(isc_result_toid, tc) {
	atf_tc_set_md_var(tc, "descr", "convert result to identifier string");
}
ATF_TC_BODY(isc_result_toid, tc) {
	const char *id;

	id = isc_result_toid(ISC_R_SUCCESS);
	ATF_REQUIRE_STREQ("ISC_R_SUCCESS", id);

	id = isc_result_toid(ISC_R_FAILURE);
	ATF_REQUIRE_STREQ("ISC_R_FAILURE", id);
}

ATF_TC(isc_result_totext);
ATF_TC_HEAD(isc_result_totext, tc) {
	atf_tc_set_md_var(tc, "descr", "convert result to description string");
}
ATF_TC_BODY(isc_result_totext, tc) {
	const char *str;

	str = isc_result_totext(ISC_R_SUCCESS);
	ATF_REQUIRE_STREQ("success", str);

	str = isc_result_totext(ISC_R_FAILURE);
	ATF_REQUIRE_STREQ("failure", str);
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, isc_result_toid);
	ATF_TP_ADD_TC(tp, isc_result_totext);
	ATF_TP_ADD_TC(tp, tables);

	return (atf_no_error());
}

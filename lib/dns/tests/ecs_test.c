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

/* ! \file */

#include <config.h>

#include <atf-c.h>

#include <unistd.h>

#include <isc/util.h>
#include <isc/string.h>

#include <dns/ecs.h>

#include "dnstest.h"

/*
 * This type bitmap is set to the following types:
 * A, AAAA, CNAME, MX, TXT
 */
unsigned char testmap[] = { 0x00, 0x04, 0x44, 0x01, 0x80, 0x08 };
int answers[] = {
	0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

ATF_TC(dns_ecs_type_allowed);
ATF_TC_HEAD(dns_ecs_type_allowed, tc) {
	atf_tc_set_md_var(tc, "descr", "dns_ecs_type_allowed");
}
ATF_TC_BODY(dns_ecs_type_allowed, tc) {
	isc_result_t result;
	isc_buffer_t buf;
	int i;

	UNUSED(tc);

	result = dns_test_begin(NULL, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	isc_buffer_init(&buf, testmap, sizeof(testmap));
	isc_buffer_add(&buf, 2 + testmap[1]);
	for (i = 0; i < 256; i++)
		ATF_CHECK_EQ_MSG(answers[i] ? true : false,
				 dns_ecs_type_allowed(&buf, i),
				 "type %d should be %s", i,
				 answers[i] ? "set" : "clear");

	dns_test_end();
}

/*
 * Test data for the dns_ecs_domain test
 */
typedef struct {
	const char *name;
	bool active;
	uint8_t bits4;
	uint8_t bits6;
} domain_testdata_t;

domain_testdata_t domain_testdata[] = {
	{ "example.com.", true, 22, 48 },
	{ "subdomain.example.com.", false, 0, 0 }, /* negated */
	{ "deeper.subdomain.example.com.", true, 24, 56 },
	{ "example.org.", true, 20, 52 },
	{ "subdomain.example.org.", true, 24, 56 },
	{ "example.net.", true, 24, 56 },
	{ NULL, false, 0, 0 }
};

domain_testdata_t domain_testcases[] = {
	{ "example.com.", true, 22, 48 },
	{ "www.example.com.", true, 22, 48 },
	{ "subdomain.example.com.", false, 0, 0 },
	{ "www.subdomain.example.com.", false, 0, 0 },
	{ "deeper.subdomain.example.com.", true, 22, 48 },
	{ "even.deeper.subdomain.example.com.", true, 22, 48 },
	{ "example.org.", true, 20, 52 },
	{ "subdomain.example.org.", true, 20, 52 },
	{ "deeper.subdomain.example.org.", true, 20, 52 },
	{ "www.example.org.", true, 20, 52 },
	{ "example.net.", true, 24, 56 },
	{ "www.example.net.", true, 24, 56 },
	{ NULL, false, 0, 0 }
};

ATF_TC(dns_ecszones_name_allowed);
ATF_TC_HEAD(dns_ecszones_name_allowed, tc) {
	atf_tc_set_md_var(tc, "descr", "dns_ecszones_name_allowed");
}
ATF_TC_BODY(dns_ecszones_name_allowed, tc) {
	isc_result_t result;
	dns_ecszones_t *ecszones = NULL;
	dns_fixedname_t fn;
	dns_name_t *name;
	int i;

	UNUSED(tc);

	result = dns_test_begin(NULL, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	result = dns_ecszones_create(mctx, &ecszones);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	dns_fixedname_init(&fn);
	name = dns_fixedname_name(&fn);
	for (i = 0; domain_testdata[i].name != NULL; i++) {
		if (domain_testdata[i].name[0] == 0) {
			dns_fixedname_init(&fn);
		} else {
			result = dns_name_fromstring2(name,
						      domain_testdata[i].name,
						      NULL, 0, NULL);
			ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
		}

		result = dns_ecszones_setdomain(ecszones, name,
						!domain_testdata[i].active,
						domain_testdata[i].bits4,
						domain_testdata[i].bits6);
		ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	}

	for (i = 0; domain_testcases[i].name != NULL; i++) {
		uint8_t bits4, bits6;
		bool active;

		if (domain_testcases[i].name[0] == 0) {
			dns_fixedname_init(&fn);
		} else {
			result = dns_name_fromstring2(name,
						      domain_testcases[i].name,
						      NULL, 0, NULL);
			ATF_CHECK_EQ(result, ISC_R_SUCCESS);
			if (result != ISC_R_SUCCESS)
				continue;
		}

		active = dns_ecszones_name_allowed(ecszones, name,
						   &bits4, &bits6);
		if (active != domain_testcases[i].active)
			ATF_CHECK_MSG(0, "%s %s", domain_testcases[i].name,
				      active ? "active" : "not active");
		if (active) {
			ATF_CHECK_EQ_MSG(bits4, domain_testcases[i].bits4,
					 "test %d: %d: expected %d",
					 i, bits4, domain_testcases[i].bits4);
			ATF_CHECK_EQ_MSG(bits6, domain_testcases[i].bits6,
					 "test %d: %d: expected %d",
					 i, bits6, domain_testcases[i].bits6);
		}
	}

	dns_ecszones_free(&ecszones);
	ATF_CHECK_EQ(ecszones, NULL);

	dns_test_end();
}

typedef struct {
	int family;
	const char *addr1;
	uint8_t bits1;
	const char *addr2;
	uint8_t bits2;
	bool match;
} match_test_t;

match_test_t match_testcases[] = {
	{ AF_INET, "1.2.3.4", 8, "1.2.3.4", 8, true},		/* 0 */
	{ AF_INET, "1.2.3.4", 8, "1.2.3.4", 9, false},
	{ AF_INET, "1.2.3.4", 0, "1.2.3.4", 0, true},
	{ AF_INET, "170.0.0.0", 1, "85.0.0.0", 1, false},
	{ AF_INET, "170.0.0.0", 2, "85.0.0.0", 2, false},
	{ AF_INET, "170.0.0.0", 3, "85.0.0.0", 3, false},
	{ AF_INET, "170.0.0.0", 4, "85.0.0.0", 4, false},
	{ AF_INET, "170.0.0.0", 5, "85.0.0.0", 5, false},
	{ AF_INET, "170.0.0.0", 6, "85.0.0.0", 6, false},
	{ AF_INET, "170.0.0.0", 7, "85.0.0.0", 7, false},
	{ AF_INET, "170.0.0.0", 8, "85.0.0.0", 8, false},   	/* 10 */
	{ AF_INET, "10.29.44.5", 8, "10.9.8.7", 8, true},
	{ AF_INET, "10.29.31.100", 9, "10.29.31.44", 9, true},
	{ AF_INET, "10.170.31.6", 9, "10.85.0.7", 9, false},
	{ AF_INET, "10.170.31.6", 9, "10.129.0.7", 9, true},
	{ AF_INET, "10.170.31.6", 10, "10.150.0.7", 10, true},
	{ AF_INET, "10.170.31.6", 10, "10.244.0.7", 10, false},
	{ AF_INET, "10.170.31.6", 15, "10.171.31.44", 15, true},
	{ AF_INET, "10.170.31.6", 16, "10.29.31.44", 16, false},
	{ AF_INET, "10.170.31.6", 16, "10.170.31.44", 16, true},
	{ AF_INET, "10.170.31.6", 19, "10.29.31.44", 19, false},	/* 20 */
	{ AF_INET, "10.170.31.6", 23, "10.29.31.44", 23, false},
	{ AF_INET, "10.140.72.0", 9, "10.29.31.44", 9, false},
	{ 0, NULL, 0, NULL, 0, 0 }
};
ATF_TC(dns_ecs_equals);
ATF_TC_HEAD(dns_ecs_equals, tc) {
	atf_tc_set_md_var(tc, "descr", "dns_ecs_equals");
}
ATF_TC_BODY(dns_ecs_equals, tc) {
	isc_result_t result;
	struct in_addr in4a, in4b;
	struct in6_addr in6a, in6b;
	isc_netaddr_t net1, net2;
	dns_ecs_t ecs1, ecs2;
	int i;

	UNUSED(tc);

	result = dns_test_begin(NULL, false);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	for (i = 0; match_testcases[i].addr1 != NULL; i++) {
		bool match;

		if (match_testcases[i].family == AF_INET) {
			inet_pton(AF_INET, match_testcases[i].addr1, &in4a);
			inet_pton(AF_INET, match_testcases[i].addr2, &in4b);
			isc_netaddr_fromin(&net1, &in4a);
			isc_netaddr_fromin(&net2, &in4b);
		} else {
			inet_pton(AF_INET6, match_testcases[i].addr1, &in6a);
			inet_pton(AF_INET6, match_testcases[i].addr2, &in6b);
			isc_netaddr_fromin6(&net1, &in6a);
			isc_netaddr_fromin6(&net2, &in6b);
		}

		ecs1.addr = net1;
		ecs2.addr = net2;
		ecs1.source = match_testcases[i].bits1;
		ecs2.source = match_testcases[i].bits2;

		match = dns_ecs_equals(&ecs1, &ecs2);
		ATF_CHECK_EQ_MSG(match, match_testcases[i].match,
				 "test %d: unexpected %s",
				 i, match ? "match" : "no match");
	}

	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, dns_ecs_type_allowed);
	ATF_TP_ADD_TC(tp, dns_ecszones_name_allowed);
	ATF_TP_ADD_TC(tp, dns_ecs_equals);
	return (atf_no_error());
}

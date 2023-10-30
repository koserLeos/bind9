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

/* draft-thomassen-dnsop-generalized-dnsnotif-02 */

#ifndef RDATA_IN_1_NOTIFY_UNDEFINED_C
#define RDATA_IN_1_NOTIFY_UNDEFINED_C

#define RRTYPE_NOTIFY_ATTRIBUTES (0)

static isc_result_t
fromtext_in_notify(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_rdatatype_t rrtype;
	dns_name_t name;
	isc_buffer_t buffer;
	bool ok;

	REQUIRE(type == dns_rdatatype_notify);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(rrtype);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/*
	 * RRtype.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	RETTOK(dns_rdatatype_fromtext(&rrtype, &token.value.as_textregion));
	RETERR(uint16_tobuffer(rrtype, target));

	/*
	 * Scheme.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/*
	 * Port.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/*
	 * Target.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_fromtext(&name, &buffer, origin, options, target));
	ok = true;
	if ((options & DNS_RDATA_CHECKNAMES) != 0) {
		ok = dns_name_ishostname(&name, false);
	}
	if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
		RETTOK(DNS_R_BADNAME);
	}
	if (!ok && callbacks != NULL) {
		warn_badname(&name, lexer, callbacks);
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
totext_in_notify(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	char buf[sizeof("64000")];
	uint16_t num;
	unsigned int opts;

	REQUIRE(rdata->type == dns_rdatatype_notify);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	/*
	 * RRtype.
	 */
	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	dns_rdatatype_totext((dns_rdatatype_t)num, target);
	RETERR(str_totext(" ", target));

	/*
	 * Scheme.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/*
	 * Port.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/*
	 * Target.
	 */
	dns_name_fromregion(&name, &region);
	opts = name_prefix(&name, tctx->origin, &prefix) ? DNS_NAME_OMITFINALDOT
							 : 0;
	return (dns_name_totext(&prefix, opts, target));
}

static isc_result_t
fromwire_in_notify(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(type == dns_rdatatype_notify);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, false);

	dns_name_init(&name, NULL);

	/*
	 * RRtype, scheme, port.
	 */
	isc_buffer_activeregion(source, &sr);
	if (sr.length < 6) {
		return (ISC_R_UNEXPECTEDEND);
	}
	RETERR(mem_tobuffer(target, sr.base, 6));
	isc_buffer_forward(source, 6);

	/*
	 * Target.
	 */
	return (dns_name_fromwire(&name, source, dctx, target));
}

static isc_result_t
towire_in_notify(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_notify);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);
	/*
	 * RRtype, scheme, port.
	 */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 6));
	isc_region_consume(&sr, 6);

	/*
	 * Target.
	 */
	dns_name_init(&name, offsets);
	dns_name_fromregion(&name, &sr);
	return (dns_name_towire(&name, cctx, target, NULL));
}

static int
compare_in_notify(ARGS_COMPARE) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_notify);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	/*
	 * RRtype, scheme, port.
	 */
	order = memcmp(rdata1->data, rdata2->data, 6);
	if (order != 0) {
		return (order < 0 ? -1 : 1);
	}

	/*
	 * Target.
	 */
	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	isc_region_consume(&region1, 6);
	isc_region_consume(&region2, 6);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_rdatacompare(&name1, &name2));
}

static isc_result_t
fromstruct_in_notify(ARGS_FROMSTRUCT) {
	dns_rdata_in_notify_t *notify = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_notify);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(notify != NULL);
	REQUIRE(notify->common.rdtype == type);
	REQUIRE(notify->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint16_tobuffer(notify->rrtype, target));
	RETERR(uint16_tobuffer(notify->scheme, target));
	RETERR(uint16_tobuffer(notify->port, target));
	dns_name_toregion(&notify->target, &region);
	return (isc_buffer_copyregion(target, &region));
}

static isc_result_t
tostruct_in_notify(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_in_notify_t *notify = target;
	dns_name_t name;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_notify);
	REQUIRE(notify != NULL);
	REQUIRE(rdata->length != 0);

	notify->common.rdclass = rdata->rdclass;
	notify->common.rdtype = rdata->type;
	ISC_LINK_INIT(&notify->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &region);
	notify->rrtype = (dns_rdatatype_t)uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	notify->scheme = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	notify->port = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);
	dns_name_init(&notify->target, NULL);
	name_duporclone(&name, mctx, &notify->target);
	notify->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static void
freestruct_in_notify(ARGS_FREESTRUCT) {
	dns_rdata_in_notify_t *notify = source;

	REQUIRE(notify != NULL);
	REQUIRE(notify->common.rdclass == dns_rdataclass_in);
	REQUIRE(notify->common.rdtype == dns_rdatatype_notify);

	if (notify->mctx == NULL) {
		return;
	}

	dns_name_free(&notify->target, notify->mctx);
	notify->mctx = NULL;
}

static isc_result_t
additionaldata_in_notify(ARGS_ADDLDATA) {
	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static isc_result_t
digest_in_notify(ARGS_DIGEST) {
	isc_region_t r1, r2;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_notify);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &r1);
	r2 = r1;
	isc_region_consume(&r2, 6);
	r1.length = 6;
	RETERR((digest)(arg, &r1));
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r2);
	return (dns_name_digest(&name, digest, arg));
}

static bool
checkowner_in_notify(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_notify);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static bool
checknames_in_notify(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_notify);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 6);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return (false);
	}
	return (true);
}

static int
casecompare_in_notify(ARGS_COMPARE) {
	return (compare_in_notify(rdata1, rdata2));
}

#endif /* RDATA_IN_1_NOTIFY_UNDEFINED_C */

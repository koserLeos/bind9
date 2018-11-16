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

#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/util.h>

#include <dns/ecs.h>
#include <dns/nsec.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>

typedef struct {
	bool active;
	uint8_t bits4;
	uint8_t bits6;
} ecsset_t;

struct dns_ecszones {
	isc_mem_t *mctx;
	dns_rbt_t *rbt;
};

void
dns_ecs_init(dns_ecs_t *ecs) {
	isc_netaddr_unspec(&ecs->addr);
	ecs->source = 0;
	ecs->scope = 0xff;
}

bool
dns_ecs_type_allowed(isc_buffer_t *ecstypes, dns_rdatatype_t type) {
	unsigned int buflen;
	unsigned char *typebits;

	REQUIRE(ecstypes != NULL);

	switch (type) {
	/* These types should never be sent ECS-tagged queries. */
	case dns_rdatatype_ns:
		return (false);

	/*
	 * Always allow CNAME, since it may be returned along with other
	 * types which are allowed.
	 */
	case dns_rdatatype_cname:
		return (true);

	/* These types should never be sent ECS-tagged queries. */
	case dns_rdatatype_soa:
	case dns_rdatatype_ds:
	case dns_rdatatype_nsec:
	case dns_rdatatype_dnskey:
	case dns_rdatatype_nsec3:
	case dns_rdatatype_nsec3param:
		return (false);

	default:
		break;
	}

	typebits = isc_buffer_base(ecstypes);
	buflen = isc_buffer_usedlength(ecstypes);

	return (dns_rdata_typepresent(typebits, buflen, type, true));
}

static void
free_ecsset(dns_rbtnode_t *node, void *arg) {
	dns_ecszones_t *ed = arg;

	isc_mem_put(ed->mctx, node->data, sizeof(ecsset_t));
}

isc_result_t
dns_ecszones_create(isc_mem_t *mctx, dns_ecszones_t **edp) {
	dns_ecszones_t *ed;
	isc_result_t result;

	REQUIRE(edp != NULL && *edp == NULL);

	ed = isc_mem_get(mctx, sizeof(*ed));
	if (ed == NULL)
		return (ISC_R_NOMEMORY);

	ed->mctx = mctx;

	ed->rbt = NULL;
	result = dns_rbt_create(mctx, free_ecsset, ed, &ed->rbt);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, ed, sizeof(*ed));
		return (result);
	}

	*edp = ed;
	return (ISC_R_SUCCESS);
}

void
dns_ecszones_free(dns_ecszones_t **ecszonesp) {
	dns_ecszones_t *ed;
	isc_mem_t *mctx;

	REQUIRE(ecszonesp != NULL && *ecszonesp != NULL);

	ed = *ecszonesp;
	mctx = ed->mctx;

	dns_rbt_destroy(&ed->rbt);
	isc_mem_put(mctx, ed, sizeof(*ed));
	*ecszonesp = NULL;
}

isc_result_t
dns_ecszones_setdomain(dns_ecszones_t *ecszones, const dns_name_t *name,
		       bool negated, uint8_t bits4, uint8_t bits6)
{
	isc_result_t result;
	void *data = NULL;
	dns_rbtnode_t *node = NULL;
	ecsset_t *ecsset;

	REQUIRE(ecszones != NULL);
	REQUIRE(name != NULL);

	result = dns_rbt_findname(ecszones->rbt, name, 0, NULL, &data);
	if (result == ISC_R_SUCCESS) {
		return (ISC_R_EXISTS);
	} else if (result == DNS_R_PARTIALMATCH) {
		INSIST(data != NULL);

		ecsset = (ecsset_t *) data;
		if (negated || bits4 > ecsset->bits4)
			bits4 = ecsset->bits4;
		if (negated || bits6 > ecsset->bits6)
			bits6 = ecsset->bits6;
	} else if (result != ISC_R_NOTFOUND)
		return (result);

	result = dns_rbt_addnode(ecszones->rbt, name, &node);
	if (result == ISC_R_EXISTS && node->data == NULL)
		result = ISC_R_SUCCESS;
	if (result != ISC_R_SUCCESS)
		return (result);

	ecsset = isc_mem_get(ecszones->mctx, sizeof(ecsset_t));
	if (ecsset == NULL) {
		dns_rbt_deletenode(ecszones->rbt, node, false);
		return (ISC_R_NOMEMORY);
	}

	ecsset->active = !negated;
	ecsset->bits4 = bits4;
	ecsset->bits6 = bits6;
	node->data = ecsset;

	return (ISC_R_SUCCESS);
}

bool
dns_ecszones_name_allowed(dns_ecszones_t *ecszones, const dns_name_t *name,
			  uint8_t *bits4, uint8_t *bits6)
{
	isc_result_t result;
	void *data = NULL;
	ecsset_t *ecsset;

	if (ecszones == NULL)
		return (false);

	result = dns_rbt_findname(ecszones->rbt, name, 0, NULL, &data);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		return (false);

	ecsset = (ecsset_t *) data;
	if (ecsset->active) {
		if (bits4 != NULL)
			*bits4 = ecsset->bits4;
		if (bits6 != NULL)
			*bits6 = ecsset->bits6;
	}

	return (ecsset->active);
}

bool
dns_ecs_equals(const dns_ecs_t *ecs1, const dns_ecs_t *ecs2) {
	const unsigned char *addr1, *addr2;
	uint8_t mask;
	size_t alen;

	REQUIRE(ecs1 != NULL && ecs2 != NULL);

	if (ecs1->source != ecs2->source ||
	    ecs1->addr.family != ecs2->addr.family)
		return (false);

	alen = (ecs1->source + 7) / 8;
	if (alen == 0)
		return (true);

	switch (ecs1->addr.family) {
	case AF_INET:
		INSIST(alen <= 4);
		addr1 = (const unsigned char *) &ecs1->addr.type.in;
		addr2 = (const unsigned char *) &ecs2->addr.type.in;
		break;
	case AF_INET6:
		INSIST(alen <= 16);
		addr1 = (const unsigned char *) &ecs1->addr.type.in6;
		addr2 = (const unsigned char *) &ecs2->addr.type.in6;
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	/*
	 * Compare all octets except the final octet of the address
	 * prefix.
	 */
	if (alen > 1 && memcmp(addr1, addr2, alen - 1) != 0)
		return (false);

	/*
	 * It should not be necessary to mask the final octet; all
	 * bits past the source prefix length are supposed to be 0.
	 * However, it seems prudent not to omit them from the
	 * comparison anyway.
	 */
	mask = (~0U << (8 - (ecs1->source % 8))) & 0xff;
	if (mask == 0)
		mask = 0xff;
	if ((addr1[alen - 1] & mask) != (addr2[alen - 1] & mask))
		return (false);

	return (true);
}

void
dns_ecs_format(const dns_ecs_t *ecs, char *buf, size_t size) {
	size_t len;
	char *p;

	REQUIRE(ecs != NULL);
	REQUIRE(buf != NULL);
	REQUIRE(size >= DNS_ECS_FORMATSIZE);

	isc_netaddr_format(&ecs->addr, buf, size);
	len = strlen(buf);
	p = buf + len;
	snprintf(p, size - len, "/%d/%d", ecs->source, ecs->scope);
}

void
dns_ecs_formatfordump(const dns_ecs_t *ecs, char *buf, size_t size) {
	size_t len;
	char *p;

	REQUIRE(ecs != NULL);
	REQUIRE(buf != NULL);
	REQUIRE(size >= DNS_ECS_FORMATSIZE);

	isc_netaddr_format(&ecs->addr, buf, size);
	len = strlen(buf);
	p = buf + len;

	if (ecs->scope > ecs->source)
		snprintf(p, size - len, "/%d/%d", ecs->source, ecs->scope);
	else
		snprintf(p, size - len, "/%d", ecs->source);
}

bool
dns_ecs_isv4mappedprefix(const dns_ecs_t *ecs) {
	if ((ecs->source >= 96) && isc_netaddr_isv4mapped(&ecs->addr)) {
		return (true);
	}

	return (false);
}

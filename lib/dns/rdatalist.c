/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <stddef.h>

#include <isc/assertions.h>

#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>

static void disassociate(dns_rdataset_t *rdatasetp);
static dns_result_t first(dns_rdataset_t *rdataset);
static dns_result_t next(dns_rdataset_t *rdataset);
static void current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void clone(dns_rdataset_t *source, dns_rdataset_t *target);

static dns_rdatasetmethods_t methods = {
	disassociate,
	first,
	next,
	current,
	clone
};

dns_result_t
dns_rdatalist_tordataset(dns_rdatalist_t *rdatalist,
			 dns_rdataset_t *rdataset) {

	/*
	 * Make 'rdataset' refer to the rdata in 'rdatalist'.
	 */

	REQUIRE(rdatalist != NULL);
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);

	rdataset->methods = &methods;
	rdataset->rdclass = rdatalist->rdclass;
	rdataset->type = rdatalist->type;
	rdataset->ttl = rdatalist->ttl;
	rdataset->private1 = rdatalist;
	rdataset->private2 = NULL;
	rdataset->private3 = NULL;
	rdataset->private4 = NULL;
	rdataset->private5 = NULL;

	return (DNS_R_SUCCESS);
}

static void
disassociate(dns_rdataset_t *rdataset) {
	(void)rdataset;				/* Keep compiler quiet. */
}

static dns_result_t
first(dns_rdataset_t *rdataset) {
	dns_rdatalist_t *rdatalist;

	rdatalist = rdataset->private1;
	rdataset->private2 = ISC_LIST_HEAD(rdatalist->rdata);

	if (rdataset->private2 == NULL)
		return (DNS_R_NOMORE);

	return (DNS_R_SUCCESS);
}

static dns_result_t
next(dns_rdataset_t *rdataset) {
	dns_rdata_t *rdata;

	rdata = rdataset->private2;
	if (rdata == NULL)
		return (DNS_R_NOMORE);

	rdataset->private2 = ISC_LIST_NEXT(rdata, link);

	if (rdataset->private2 == NULL)
		return (DNS_R_NOMORE);

	return (DNS_R_SUCCESS);
}

static void
current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	dns_rdata_t *list_rdata;

	list_rdata = rdataset->private2;
	INSIST(list_rdata != NULL);

	*rdata = *list_rdata;
	ISC_LINK_INIT(rdata, link);
}

static void
clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	*target = *source;

	/*
	 * Reset iterator state.
	 */
	target->private2 = NULL;
}

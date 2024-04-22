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

#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/qp.h>
#include <dns/rbt.h>
#include <dns/types.h>

#include "fuzz.h"
#include "qp_p.h"

#include <tests/qp.h>

bool debug = true;

#if 1
#define TRACE(...) warnx(__VA_ARGS__)
#else
#define TRACE(...)
#endif

#if 1
#define ASSERT(p)                                               \
	do {                                                    \
		if (debug && !(p))				\
		warnx("%s:%d: %s (%s)", __func__, __LINE__, #p, \
		      (p) ? "OK" : "FAIL");                     \
		ok = ok && (p);                                 \
	} while (0)
#else
#define ASSERT(p) assert(p)
#endif

static struct {
	uint32_t refcount;
	bool exists;
	isc_buffer_t buf;
	dns_fixedname_t origin;
	dns_rbtnode_t *node;
        dns_name_t *name;
	dns_qpkey_t key;
	uint8_t len;
	uint8_t wire[DNS_NAME_MAXWIRE];
} item[256 * 256 / 4];

static void
fuzz_attach(void *ctx, void *pval, uint32_t ival) {
	assert(ctx == NULL);
	assert(pval == &item[ival]);
	item[ival].refcount++;
}

static void
fuzz_detach(void *ctx, void *pval, uint32_t ival) {
	assert(ctx == NULL);
	assert(pval == &item[ival]);
	item[ival].refcount--;
}

static size_t
fuzz_makekey(dns_qpkey_t key, void *ctx, void *pval, uint32_t ival) {
	assert(ctx == NULL);
	assert(pval == &item[ival]);
	memmove(key, item[ival].key, item[ival].len);
	return (dns_qpkey_fromname(key, item[ival].name));
}

static void
fuzz_triename(void *ctx, char *buf, size_t size) {
	assert(ctx == NULL);
	strlcpy(buf, "fuzz", size);
}

const dns_qpmethods_t fuzz_methods = {
	fuzz_attach,
	fuzz_detach,
	fuzz_makekey,
	fuzz_triename,
};

static uint8_t
random_byte(void) {
	uint8_t c = isc_random_uniform(128);
	if (c < '0') {
		c = '0';
	} else if (c > '9' && c < 'A') {
		c = '9';
	} else if (c > 'Z' && c < 'a') {
		c = 'a';
	} else if (c > 'z') {
		c = 'z';
	}
	return (c);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv) {
	UNUSED(argc);
	UNUSED(argv);

	/* WMM TODO: Add subdomains to trigger DNS_R_PARTIALMATCH */
        item[0].len = 1;
	item[0].wire[0] = 0;
	/* Make dname and key */
	dns_fixedname_init(&item[0].origin);
	item[0].name = dns_fixedname_name(&item[0].origin);
        isc_buffer_constinit(&item[0].buf, item[0].wire, item[0].len);
        isc_buffer_add(&item[0].buf, item[0].len);
        isc_buffer_setactive(&item[0].buf, item[0].len);

        dns_decompress_t dctx0 = DNS_DECOMPRESS_NEVER;
        isc_result_t result0 = dns_name_fromwire(item[0].name, &item[0].buf, dctx0, NULL);
	assert(result0 == ISC_R_SUCCESS);
	item[0].len = dns_qpkey_fromname(item[0].key, item[0].name);

        for (size_t i = 1; i < ARRAY_SIZE(item); i++) {
		/* Random domain name */
                size_t len = isc_random_uniform(254) + 1;
		size_t off = 0;
		while ((off+1) < len) {
			size_t llen = isc_random_uniform(63) + 1;
			if (llen > (len - off - 1)) {
				item[i].wire[off++] = 1;
	                        item[i].wire[off++] = random_byte();
				break;
			}
			item[i].wire[off++] = llen;
	                for (size_t loff = 0; loff < llen; loff++) {
	                        item[i].wire[off++] = random_byte();
	                }
		}
                item[i].len = off+1;
		item[i].wire[off] = 0;

		/* Make dname and key */
		dns_fixedname_init(&item[i].origin);
		item[i].name = dns_fixedname_name(&item[i].origin);
	        isc_buffer_constinit(&item[i].buf, item[i].wire, item[i].len);
	        isc_buffer_add(&item[i].buf, item[i].len);
	        isc_buffer_setactive(&item[i].buf, item[i].len);

	        dns_decompress_t dctx = DNS_DECOMPRESS_NEVER;
	        isc_result_t result = dns_name_fromwire(item[i].name, &item[i].buf, dctx, NULL);
		assert(result == ISC_R_SUCCESS);
		item[i].len = dns_qpkey_fromname(item[i].key, item[i].name);
        }

	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	isc_mem_t *mctx = NULL;
	isc_mem_create(&mctx);
	isc_mem_setdestroycheck(mctx, true);

	dns_qp_t *qp = NULL;
	dns_qp_create(mctx, &fuzz_methods, NULL, &qp);

	dns_rbt_t *rbt = NULL;
	dns_rbt_create(mctx, NULL, NULL, &rbt);

        /* avoid overrun */
        size = size & ~1;

	size_t count = 0;
        for (size_t in = 0; in < size; in += 2) {
		isc_result_t result, result2;
                bool ok = true;

		/* Read data */
                size_t what = data[in] + data[in + 1] * 256;
                size_t i = (what / 4) % (count * 2 + 2);
                bool exists = item[i].exists;
                uint32_t refcount = item[i].refcount;
		dns_name_t *name = item[i].name;
	        char namebuf[DNS_NAME_FORMATSIZE + 1];
	        dns_name_format(name, namebuf, sizeof(namebuf));

                if (what & 2) {
			/* Lookup */
			dns_fixedname_t fixed;
		        dns_name_t *found = dns_fixedname_initname(&fixed);
			dns_qpiter_t iter;
			dns_qpchain_t chain;
			void *pval = NULL;
			uint32_t ival = ~0U;
			result = dns_qp_lookup(qp, name, found, &iter, &chain, &pval, &ival);
			TRACE("count %zu qp lookup %zu %s %s", count, i, isc_result_toid(result), namebuf);

			dns_fixedname_t fixed2;
		        dns_name_t *found2 = dns_fixedname_initname(&fixed2);
		        dns_rbtnode_t *node = NULL;
		        dns_rbtnodechain_t nodechain;
		        dns_rbtnodechain_init(&nodechain);
			result2 = dns_rbt_findnode(rbt, name, found2, &node, &nodechain, DNS_RBTFIND_EMPTYDATA, NULL, NULL);
			TRACE("count %zu rbt lookup %zu %s %s", count, i, isc_result_toid(result2), namebuf);
			ASSERT(result == result2);
			//ASSERT(dns_name_compare(found, found2) == 0);

			if (result == ISC_R_SUCCESS) {
				ASSERT(pval == &item[i]);
				ASSERT(ival == i);
				ASSERT(item[i].refcount == 1);
				ASSERT(item[i].exists == true);
			} else if (result == DNS_R_PARTIALMATCH) {
				ASSERT(item[i].refcount == 0);
				ASSERT(item[i].exists == false);
			} else if (result == ISC_R_NOTFOUND) {
				ASSERT(pval == NULL);
				ASSERT(ival == ~0U);
				ASSERT(item[i].refcount == 0);
				ASSERT(item[i].exists == false);
			} else {
				UNREACHABLE();
			}

			/* WMM: TODO fuzz the zonecut callback against qp's check_zonecut */
		} else if (what & 1) {
			/* Insert */
			result = dns_qp_insert(qp, &item[i], i);
			TRACE("count %zu qp insert %zu %s %s", count, i, isc_result_toid(result), namebuf);

		        dns_rbtnode_t *node = NULL;
			result2 = dns_rbt_addnode(rbt, name, &node);
			TRACE("count %zu rbt insert %zu %s %s", count, i, isc_result_toid(result2), namebuf);
			ASSERT(result == result2);

			if (result == ISC_R_SUCCESS) {
				item[i].exists = true;
				item[i].node = node;
				ASSERT(exists == false);
				ASSERT(refcount == 0);
				ASSERT(item[i].refcount == 1);
				count += 1;
				ASSERT(qp->leaf_count == count);
			} else if (result == ISC_R_EXISTS) {
				ASSERT(exists == true);
				ASSERT(refcount == 1);
				ASSERT(item[i].refcount == 1);
				ASSERT(qp->leaf_count == count);
			} else {
				UNREACHABLE();
			}
		} else {
			/* Delete */
			result = dns_qp_deletename(qp, name, NULL, NULL);
			TRACE("count %zu qp delete %zu %s %s", count, i, isc_result_toid(result), namebuf);

		        dns_rbtnode_t *node = item[i].node;
			if (node != NULL) {
				result2 = dns_rbt_deletenode(rbt, node, 0);
				TRACE("count %zu rbt delete %zu %s %s", count, i, isc_result_toid(result2), namebuf);
				ASSERT(result == result2);
			}

			if (result == ISC_R_SUCCESS) {
				item[i].exists = false;
				item[i].node = NULL;
				ASSERT(exists == true);
				ASSERT(refcount == 1);
				ASSERT(item[i].refcount == 0);
				count -= 1;
				ASSERT(qp->leaf_count == count);
			} else if (result == ISC_R_NOTFOUND) {
				ASSERT(exists == false);
				ASSERT(refcount == 0);
				ASSERT(item[i].refcount == 0);
				ASSERT(qp->leaf_count == count);
			} else {
				UNREACHABLE();
			}
		}

		if (!ok) {
			qp_test_dumpqp(qp);
			qp_test_dumptrie(qp);
		}
		assert(ok);
	}

	dns_qp_destroy(&qp);
	dns_rbt_destroy(&rbt, 0);
	isc_mem_destroy(&mctx);
	isc_mem_checkdestroyed(stderr);

	return (0);
}

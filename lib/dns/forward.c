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

/*! \file */

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include <dns/forward.h>
#include <dns/name.h>
#include <dns/rbt.h>
#include <dns/types.h>

struct dns_fwdtable {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	isc_rwlock_t rwlock;
	/* Locked by lock. */
	dns_rbt_t *table;
};

#define FWDTABLEMAGIC	   ISC_MAGIC('F', 'w', 'd', 'T')
#define VALID_FWDTABLE(ft) ISC_MAGIC_VALID(ft, FWDTABLEMAGIC)

static void
auto_detach(void *, void *);

isc_result_t
dns_fwdtable_create(isc_mem_t *mctx, dns_fwdtable_t **fwdtablep) {
	dns_fwdtable_t *fwdtable;
	isc_result_t result;

	REQUIRE(fwdtablep != NULL && *fwdtablep == NULL);

	fwdtable = isc_mem_get(mctx, sizeof(*fwdtable));

	fwdtable->table = NULL;
	result = dns_rbt_create(mctx, auto_detach, fwdtable, 1,
				&fwdtable->table);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_fwdtable;
	}

	isc_rwlock_init(&fwdtable->rwlock, 0, 0);
	fwdtable->mctx = NULL;
	isc_mem_attach(mctx, &fwdtable->mctx);
	fwdtable->magic = FWDTABLEMAGIC;
	*fwdtablep = fwdtable;

	return (ISC_R_SUCCESS);

cleanup_fwdtable:
	isc_mem_put(mctx, fwdtable, sizeof(*fwdtable));

	return (result);
}

isc_result_t
dns_fwdtable_addfwd(dns_fwdtable_t *fwdtable, const dns_name_t *name,
		    dns_forwarderlist_t *fwdrs, dns_fwdpolicy_t fwdpolicy) {
	isc_result_t result;
	dns_forwarders_t *forwarders;
	dns_forwarder_t *fwd, *nfwd;

	REQUIRE(VALID_FWDTABLE(fwdtable));

	forwarders = isc_mem_get(fwdtable->mctx, sizeof(*forwarders));

	ISC_LIST_INIT(forwarders->fwdrs);
	for (fwd = ISC_LIST_HEAD(*fwdrs); fwd != NULL;
	     fwd = ISC_LIST_NEXT(fwd, link))
	{
		nfwd = isc_mem_get(fwdtable->mctx, sizeof(*nfwd));
		*nfwd = *fwd;

		if (fwd->tlsname != NULL) {
			nfwd->tlsname = isc_mem_get(fwdtable->mctx,
						    sizeof(*nfwd->tlsname));
			dns_name_init(nfwd->tlsname, NULL);
			dns_name_dup(fwd->tlsname, fwdtable->mctx,
				     nfwd->tlsname);
		}

		ISC_LINK_INIT(nfwd, link);
		ISC_LIST_APPEND(forwarders->fwdrs, nfwd, link);
	}
	forwarders->fwdpolicy = fwdpolicy;

	RWLOCK(&fwdtable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_addname(fwdtable->table, name, forwarders);
	RWUNLOCK(&fwdtable->rwlock, isc_rwlocktype_write);

	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	return (ISC_R_SUCCESS);

cleanup:
	while (!ISC_LIST_EMPTY(forwarders->fwdrs)) {
		fwd = ISC_LIST_HEAD(forwarders->fwdrs);
		ISC_LIST_UNLINK(forwarders->fwdrs, fwd, link);
		if (fwd->tlsname != NULL) {
			dns_name_free(fwd->tlsname, fwdtable->mctx);
			isc_mem_put(fwdtable->mctx, fwd->tlsname,
				    sizeof(*fwd->tlsname));
		}
		isc_mem_put(fwdtable->mctx, fwd, sizeof(*fwd));
	}
	isc_mem_put(fwdtable->mctx, forwarders, sizeof(*forwarders));
	return (result);
}

isc_result_t
dns_fwdtable_add(dns_fwdtable_t *fwdtable, const dns_name_t *name,
		 isc_sockaddrlist_t *addrs, dns_fwdpolicy_t fwdpolicy) {
	isc_result_t result;
	dns_forwarders_t *forwarders;
	dns_forwarder_t *fwd;
	isc_sockaddr_t *sa;

	REQUIRE(VALID_FWDTABLE(fwdtable));

	forwarders = isc_mem_get(fwdtable->mctx, sizeof(*forwarders));

	ISC_LIST_INIT(forwarders->fwdrs);
	for (sa = ISC_LIST_HEAD(*addrs); sa != NULL;
	     sa = ISC_LIST_NEXT(sa, link))
	{
		fwd = isc_mem_get(fwdtable->mctx, sizeof(*fwd));
		*fwd = (dns_forwarder_t){ .addr = *sa,
					  .link = ISC_LINK_INITIALIZER };
		ISC_LIST_APPEND(forwarders->fwdrs, fwd, link);
	}
	forwarders->fwdpolicy = fwdpolicy;

	RWLOCK(&fwdtable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_addname(fwdtable->table, name, forwarders);
	RWUNLOCK(&fwdtable->rwlock, isc_rwlocktype_write);

	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	return (ISC_R_SUCCESS);

cleanup:
	while (!ISC_LIST_EMPTY(forwarders->fwdrs)) {
		fwd = ISC_LIST_HEAD(forwarders->fwdrs);
		ISC_LIST_UNLINK(forwarders->fwdrs, fwd, link);
		isc_mem_put(fwdtable->mctx, fwd, sizeof(*fwd));
	}
	isc_mem_put(fwdtable->mctx, forwarders, sizeof(*forwarders));
	return (result);
}

isc_result_t
dns_fwdtable_delete(dns_fwdtable_t *fwdtable, const dns_name_t *name) {
	isc_result_t result;

	REQUIRE(VALID_FWDTABLE(fwdtable));

	RWLOCK(&fwdtable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_deletename(fwdtable->table, name, NULL);
	RWUNLOCK(&fwdtable->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_fwdtable_find(dns_fwdtable_t *fwdtable, const dns_name_t *name,
		  dns_name_t *foundname, dns_forwarders_t **forwardersp) {
	isc_result_t result;

	REQUIRE(VALID_FWDTABLE(fwdtable));

	RWLOCK(&fwdtable->rwlock, isc_rwlocktype_read);
	result = dns_rbt_findname(fwdtable->table, name, 0, foundname,
				  (void **)forwardersp);
	RWUNLOCK(&fwdtable->rwlock, isc_rwlocktype_read);

	return (result);
}

void
dns_fwdtable_destroy(dns_fwdtable_t **fwdtablep) {
	dns_fwdtable_t *fwdtable;

	REQUIRE(fwdtablep != NULL && VALID_FWDTABLE(*fwdtablep));

	fwdtable = *fwdtablep;
	*fwdtablep = NULL;

	dns_rbt_destroy(&fwdtable->table);
	isc_rwlock_destroy(&fwdtable->rwlock);
	fwdtable->magic = 0;

	isc_mem_putanddetach(&fwdtable->mctx, fwdtable, sizeof(*fwdtable));
}

/***
 *** Private
 ***/

static void
auto_detach(void *data, void *arg) {
	dns_forwarders_t *forwarders = data;
	dns_fwdtable_t *fwdtable = arg;
	dns_forwarder_t *fwd;

	UNUSED(arg);

	while (!ISC_LIST_EMPTY(forwarders->fwdrs)) {
		fwd = ISC_LIST_HEAD(forwarders->fwdrs);
		ISC_LIST_UNLINK(forwarders->fwdrs, fwd, link);
		if (fwd->tlsname != NULL) {
			dns_name_free(fwd->tlsname, fwdtable->mctx);
			isc_mem_put(fwdtable->mctx, fwd->tlsname,
				    sizeof(*fwd->tlsname));
		}
		isc_mem_put(fwdtable->mctx, fwd, sizeof(*fwd));
	}
	isc_mem_put(fwdtable->mctx, forwarders, sizeof(*forwarders));
}

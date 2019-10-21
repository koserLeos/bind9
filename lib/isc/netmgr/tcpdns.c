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

#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"

static void
dnslisten_readcb(void *arg, isc_nmhandle_t *handle, isc_region_t *region);

/*
 * Accept callback for TCP-DNS connection
 */
static void
dnslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *dnslistensocket = (isc_nmsocket_t *) cbarg;
	isc_nmsocket_t *dnssocket = NULL;

	REQUIRE(VALID_NMSOCK(dnslistensocket));
	REQUIRE(dnslistensocket->type == isc_nm_tcpdnslistener);

	/* If accept() was unnsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return;
	}

	/* We need to create a 'wrapper' dnssocket for this connection */
	dnssocket = isc_mem_get(handle->socket->mgr->mctx, sizeof(*dnssocket));
	isc__nmsocket_init(dnssocket, handle->socket->mgr,
			   isc_nm_tcpdnssocket);

	/* We need to copy read callbacks from outer socket */
	dnssocket->rcb.recv = dnslistensocket->rcb.recv;
	dnssocket->rcbarg = dnslistensocket->rcbarg;
	dnssocket->extrahandlesize = dnslistensocket->extrahandlesize;
	isc_nmsocket_attach(handle->socket, &dnssocket->outer);

	isc_nm_read(handle, dnslisten_readcb, dnssocket);
}

/*
 * We've got a read on our underlying socket, need to check if we have
 * a complete DNS packet and, if so - call the callback
 */
static void
dnslisten_readcb(void *arg, isc_nmhandle_t *handle, isc_region_t *region) {
	isc_nmsocket_t *dnssocket = (isc_nmsocket_t *) arg;
	isc_nmhandle_t *dnshandle = NULL;
	isc_region_t r2;

	if (region == NULL) {
		/* Connection closed */
		atomic_store(&dnssocket->closed, true);
		isc_nmsocket_detach(&dnssocket->outer);
		isc_nmsocket_detach(&dnssocket);
		return;
	}

	dnshandle = isc__nmhandle_get(dnssocket, &handle->peer);

	/*
	 * XXX This MUST be fixed; currently if we read a partial
	 * DNS packet we'll crash. We need to buffer it and wait for the
	 * rest.
	 */
	INSIST(((region->base[0] << 8) + (region->base[1]) ==
		(int) region->length - 2));

	r2.base = region->base + 2;
	r2.length = region->length - 2;

	dnssocket->rcb.recv(dnssocket->rcbarg, dnshandle, &r2);
	isc_nmhandle_detach(&dnshandle);
}

/*
 * isc_nm_listentcpdns listens for connections and accepts
 * them immediately, then calls the cb for each incoming DNS packet
 * (with 2-byte length stripped) - just like for UDP packet.
 */
isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface,
		    isc_nm_recv_cb_t cb, void *cbarg,
		    size_t extrahandlesize, isc_quota_t *quota,
		    isc_nmsocket_t **rv)
{
	/* A 'wrapper' socket object with outer set to true TCP socket */
	isc_nmsocket_t *dnslistensocket =
		isc_mem_get(mgr->mctx, sizeof(*dnslistensocket));
	isc_result_t result;

	isc__nmsocket_init(dnslistensocket, mgr, isc_nm_tcpdnslistener);
	dnslistensocket->iface = iface;
	dnslistensocket->rcb.recv = cb;
	dnslistensocket->rcbarg = cbarg;
	dnslistensocket->extrahandlesize = extrahandlesize;

	/* We set dnslistensocket->outer to a true listening socket */
	result = isc_nm_listentcp(mgr, iface, dnslisten_acceptcb,
				  dnslistensocket, extrahandlesize,
				  quota, &dnslistensocket->outer);

	dnslistensocket->listening = true;
	*rv = dnslistensocket;
	return (result);
}

void
isc_nm_tcpdns_stoplistening(isc_nmsocket_t *socket) {
	REQUIRE(socket->type == isc_nm_tcpdnslistener);

	isc_nm_tcp_stoplistening(socket->outer);
	atomic_store(&socket->listening, false);
	isc_nmsocket_detach(&socket->outer);
}


typedef struct tcpsend {
	isc_mem_t		*mctx;
	isc_nmhandle_t		*handle;
	isc_region_t		region;
	isc_nmhandle_t		*orighandle;
	isc_nm_send_cb_t	cb;
	void 			*cbarg;
} tcpsend_t;

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t *ts = (tcpsend_t *) cbarg;

	UNUSED(handle);

	ts->cb(ts->orighandle, result, ts->cbarg);
	isc_nmhandle_detach(&ts->orighandle);
	isc_mem_put(ts->mctx, ts->region.base, ts->region.length);
	isc_mem_putanddetach(&ts->mctx, ts, sizeof(*ts));
}
/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle, isc_region_t *region,
		    isc_nm_send_cb_t cb, void *cbarg)
{
	isc_nmsocket_t *socket = handle->socket;
	tcpsend_t *t = isc_mem_get(socket->mgr->mctx, sizeof(*t));

	REQUIRE(socket->type == isc_nm_tcpdnssocket);

	*t = (tcpsend_t) {};

	isc_mem_attach(socket->mgr->mctx, &t->mctx);
	t->handle = handle->socket->outer->tcphandle;
	t->cb = cb;
	t->cbarg = cbarg;

	t->region = (isc_region_t) {
		.base = isc_mem_get(t->mctx, region->length + 2),
		.length = region->length + 2
	};
	memmove(t->region.base + 2, region->base, region->length);
	t->region.base[0] = (uint8_t) (region->length >> 8);
	t->region.base[1] = (uint8_t) (region->length & 0xff);

	isc_nmhandle_attach(handle, &t->orighandle);

	return (isc__nm_tcp_send(t->handle, &t->region, tcpdnssend_cb, t));
}

void
isc__nm_tcpdns_close(isc_nmsocket_t *socket) {
	isc_nmsocket_detach(&socket->outer);
	socket->closed = true;
	isc__nmsocket_prep_destroy(socket);
}

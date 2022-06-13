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
#pragma once

#include "dnsbuffer.h"

typedef struct isc_dnsstream_assembler isc_dnsstream_assembler_t;

typedef bool (*isc_dnsstream_assembler_cb_t)(isc_dnsstream_assembler_t *dnsasm,
					     const isc_result_t		result,
					     isc_region_t *restrict region,
					     void *cbarg, void *userarg);

struct isc_dnsstream_assembler {
	isc_dnsbuffer_t		     dnsbuf;
	isc_dnsstream_assembler_cb_t onmsg_cb;
	void			    *cbarg;
	bool			     calling_cb;
	isc_result_t		     result;
	isc_mem_t		    *mctx;
};

static inline void
isc_dnsstream_assembler_setcb(isc_dnsstream_assembler_t *restrict dnsasm,
			      isc_dnsstream_assembler_cb_t cb, void *cbarg) {
	REQUIRE(cb != NULL);
	dnsasm->onmsg_cb = cb;
	dnsasm->cbarg = cbarg;
}

static inline void
isc_dnsstream_assembler_init(isc_dnsstream_assembler_t *restrict dnsasm,
			     isc_mem_t *memctx, isc_dnsstream_assembler_cb_t cb,
			     void *cbarg) {
	REQUIRE(dnsasm != NULL);
	REQUIRE(memctx != NULL);

	*dnsasm = (isc_dnsstream_assembler_t){ .result = ISC_R_UNSET };
	isc_dnsstream_assembler_setcb(dnsasm, cb, cbarg);
	isc_mem_attach(memctx, &dnsasm->mctx);
	isc_dnsbuffer_init(&dnsasm->dnsbuf, memctx);
}

static inline void
isc_dnsstream_assembler_uninit(isc_dnsstream_assembler_t *restrict dnsasm) {
	REQUIRE(dnsasm != NULL);
	/*
	 * Uninitialising the object from withing the callback does not
	 * make any sense.
	 */
	REQUIRE(dnsasm->calling_cb == false);
	isc_dnsbuffer_uninit(&dnsasm->dnsbuf);
	isc_mem_detach(&dnsasm->mctx);
}

static inline isc_dnsstream_assembler_t *
isc_dnsstream_assembler_new(isc_mem_t *memctx, isc_dnsstream_assembler_cb_t cb,
			    void *cbarg) {
	isc_dnsstream_assembler_t *newasm;

	REQUIRE(memctx != NULL);

	newasm = isc_mem_get(memctx, sizeof(*newasm));
	isc_dnsstream_assembler_init(newasm, memctx, cb, cbarg);

	return (newasm);
}

static inline void
isc_dnsstream_assembler_free(isc_dnsstream_assembler_t **restrict dnsasm) {
	isc_dnsstream_assembler_t *restrict oldasm = NULL;
	isc_mem_t *memctx = NULL;
	REQUIRE(dnsasm != NULL && *dnsasm != NULL);

	oldasm = *dnsasm;

	isc_mem_attach(oldasm->mctx, &memctx);
	isc_dnsstream_assembler_uninit(oldasm);
	isc_mem_putanddetach(&memctx, oldasm, sizeof(*oldasm));

	*dnsasm = NULL;
}

static inline bool
isc__dnsstream_assembler_handle_message(
	isc_dnsstream_assembler_t *restrict dnsasm, void *userarg) {
	bool	     cont = false;
	isc_region_t region = { 0 };
	isc_result_t result;
	uint16_t     dnslen = isc_dnsbuffer_peek_uint16be(&dnsasm->dnsbuf);

	REQUIRE(dnsasm->calling_cb == false);

	if (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf) < sizeof(uint16_t)) {
		result = ISC_R_NOMORE;
	} else if (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf) >=
			   sizeof(uint16_t) &&
		   dnslen == 0)
	{
		/*
		 * Someone seems to send us binary junk or output from /dev/zero
		 */
		result = ISC_R_FAILURE;
		isc_dnsbuffer_clear(&dnsasm->dnsbuf);
	} else if (dnslen <= (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf) -
			      sizeof(uint16_t)))
	{
		result = ISC_R_SUCCESS;
	} else {
		result = ISC_R_NOMORE;
	}

	dnsasm->result = result;
	dnsasm->calling_cb = true;
	if (result == ISC_R_SUCCESS) {
		(void)isc_dnsbuffer_consume_uint16be(&dnsasm->dnsbuf);
		isc_dnsbuffer_remainingregion(&dnsasm->dnsbuf, &region);
		region.length = dnslen;
		cont = dnsasm->onmsg_cb(dnsasm, ISC_R_SUCCESS, &region,
					dnsasm->cbarg, userarg);
		if (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf) >= dnslen) {
			isc_dnsbuffer_consume(&dnsasm->dnsbuf, dnslen);
		}
	} else {
		cont = false;
		(void)dnsasm->onmsg_cb(dnsasm, result, NULL, dnsasm->cbarg,
				       userarg);
	}
	dnsasm->calling_cb = false;

	return (cont);
}

static inline void
isc_dnsstream_assembler_incoming(isc_dnsstream_assembler_t *restrict dnsasm,
				 void		   *userarg, void *restrict buf,
				 const unsigned int buf_size) {
	REQUIRE(dnsasm != NULL);
	REQUIRE(!dnsasm->calling_cb);

	if (buf_size > 0) {
		INSIST(buf != NULL);
		isc_dnsbuffer_putmem(&dnsasm->dnsbuf, buf, buf_size);
	}

	while (isc__dnsstream_assembler_handle_message(dnsasm, userarg)) {
		if (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf) == 0) {
			break;
		}
	}
	isc_dnsbuffer_trycompact(&dnsasm->dnsbuf);
}

static inline isc_result_t
isc_dnsstream_assembler_result(
	const isc_dnsstream_assembler_t *restrict dnsasm) {
	REQUIRE(dnsasm != NULL);

	return (dnsasm->result);
}

static inline size_t
isc_dnsstream_assembler_remaininglength(
	const isc_dnsstream_assembler_t *restrict dnsasm) {
	REQUIRE(dnsasm != NULL);

	return (isc_dnsbuffer_remaininglength(&dnsasm->dnsbuf));
}

static inline void
isc_dnsstream_assembler_clear(isc_dnsstream_assembler_t *restrict dnsasm) {
	REQUIRE(dnsasm != NULL);

	isc_dnsbuffer_clear(&dnsasm->dnsbuf);
	dnsasm->result = ISC_R_UNSET;
}

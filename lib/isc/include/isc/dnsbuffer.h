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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/util.h>

#define ISC_DNSBUFFER_STATIC_BUFFER_SIZE	  (512)
#define ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE (ISC_BUFFER_INCR * 2)

typedef struct isc_dnsbuffer {
	isc_buffer_t *current;
	uint8_t	      buf[ISC_DNSBUFFER_STATIC_BUFFER_SIZE];
	isc_buffer_t  stbuf;
	isc_buffer_t *dynbuf;
	isc_mem_t    *mctx;
} isc_dnsbuffer_t;

static inline void
isc_dnsbuffer_init(isc_dnsbuffer_t *restrict dnsbuf, isc_mem_t *memctx) {
	REQUIRE(dnsbuf != NULL);
	REQUIRE(memctx != NULL);
	*dnsbuf = (isc_dnsbuffer_t){ .current = &dnsbuf->stbuf };
	isc_buffer_init(&dnsbuf->stbuf, &dnsbuf->buf[0], sizeof(dnsbuf->buf));
	isc_mem_attach(memctx, &dnsbuf->mctx);
}

static inline void
isc_dnsbuffer_uninit(isc_dnsbuffer_t *restrict dnsbuf) {
	isc_buffer_clear(&dnsbuf->stbuf);
	if (dnsbuf->dynbuf != NULL) {
		isc_buffer_free(&dnsbuf->dynbuf);
	}
	isc_mem_detach(&dnsbuf->mctx);
}

static inline isc_dnsbuffer_t *
isc_dnsbuffer_new(isc_mem_t *memctx) {
	isc_dnsbuffer_t *newbuf;

	REQUIRE(memctx != NULL);

	newbuf = isc_mem_get(memctx, sizeof(*newbuf));
	isc_dnsbuffer_init(newbuf, memctx);

	return (newbuf);
}

static inline void
isc_dnsbuffer_free(isc_dnsbuffer_t **restrict dnsbuf) {
	isc_dnsbuffer_t *restrict buf = NULL;
	isc_mem_t *memctx = NULL;
	REQUIRE(dnsbuf != NULL && *dnsbuf != NULL);

	buf = *dnsbuf;

	isc_mem_attach(buf->mctx, &memctx);
	isc_dnsbuffer_uninit(buf);
	isc_mem_putanddetach(&memctx, buf, sizeof(*buf));

	*dnsbuf = NULL;
}

static inline void
isc_dnsbuffer_clear(isc_dnsbuffer_t *restrict dnsbuf) {
	isc_buffer_clear(dnsbuf->current);
}

static inline unsigned int
isc_dnsbuffer_length(const isc_dnsbuffer_t *restrict dnsbuf) {
	return (isc_buffer_length(dnsbuf->current));
}

static inline unsigned int
isc_dnsbuffer_usedlength(const isc_dnsbuffer_t *restrict dnsbuf) {
	return (isc_buffer_usedlength(dnsbuf->current));
}

static inline unsigned int
isc_dnsbuffer_remaininglength(const isc_dnsbuffer_t *restrict dnsbuf) {
	return (isc_buffer_remaininglength(dnsbuf->current));
}

static inline void
isc_dnsbuffer_remainingregion(const isc_dnsbuffer_t *restrict dnsbuf,
			      isc_region_t *region) {
	isc_buffer_remainingregion(dnsbuf->current, region);
}

static inline void
isc_dnsbuffer_compact(const isc_dnsbuffer_t *restrict dnsbuf) {
	isc_buffer_compact(dnsbuf->current);
}

static inline bool
isc_dnsbuffer_trycompact(const isc_dnsbuffer_t *restrict dnsbuf) {
	if (isc_buffer_consumedlength(dnsbuf->current) >=
	    isc_dnsbuffer_remaininglength(dnsbuf))
	{
		isc_dnsbuffer_compact(dnsbuf);
		return (true);
	}

	return (false);
}

static inline void
isc_dnsbuffer_consume(isc_dnsbuffer_t *restrict dnsbuf, const unsigned int n) {
	isc_buffer_forward(dnsbuf->current, n);
}

static inline void
isc_dnsbuffer_putmem(isc_dnsbuffer_t *restrict dnsbuf, void *buf,
		     const unsigned int buf_size) {
	if (!(dnsbuf->current == &dnsbuf->stbuf &&
	      isc_buffer_availablelength(dnsbuf->current) >= buf_size) &&
	    dnsbuf->dynbuf == NULL)
	{
		isc_region_t remaining = { 0 };
		unsigned int total_size = 0;

		isc_buffer_remainingregion(&dnsbuf->stbuf, &remaining);
		total_size = remaining.length + buf_size;
		if (total_size < ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE) {
			total_size = ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE;
		}
		isc_buffer_allocate(dnsbuf->mctx, &dnsbuf->dynbuf, total_size);
		isc_buffer_setautorealloc(dnsbuf->dynbuf, true);
		if (remaining.length > 0) {
			isc_buffer_putmem(dnsbuf->dynbuf, remaining.base,
					  remaining.length);
		}

		dnsbuf->current = dnsbuf->dynbuf;
	}

	isc_buffer_putmem(dnsbuf->current, buf, buf_size);
}

static inline uint8_t *
isc_dnsbuffer_current(const isc_dnsbuffer_t *restrict dnsbuf) {
	return (isc_buffer_current(dnsbuf->current));
}

static inline uint16_t
isc__dnsbuffer_peek_uint16be(const isc_dnsbuffer_t *restrict dnsbuf) {
	uint16_t v;
	uint8_t *p = (uint8_t *)isc_dnsbuffer_current(dnsbuf);

	v = p[0] << 8;
	v |= p[1] & 0xFF;

	return (v);
}

static inline uint16_t
isc_dnsbuffer_peek_uint16be(const isc_dnsbuffer_t *restrict dnsbuf) {
	if (isc_dnsbuffer_remaininglength(dnsbuf) < sizeof(uint16_t)) {
		return (0);
	}

	return (isc__dnsbuffer_peek_uint16be(dnsbuf));
}

static inline uint16_t
isc_dnsbuffer_consume_uint16be(isc_dnsbuffer_t *restrict dnsbuf) {
	uint16_t v;

	if (isc_dnsbuffer_remaininglength(dnsbuf) < sizeof(uint16_t)) {
		return (0);
	}

	v = isc__dnsbuffer_peek_uint16be(dnsbuf);

	isc_dnsbuffer_consume(dnsbuf, sizeof(uint16_t));

	return (v);
}

static inline void
isc_dnsbuffer_putmem_uint16be(isc_dnsbuffer_t *restrict dnsbuf,
			      const uint16_t v) {
	uint8_t b[2] = { 0 };

	b[0] = v >> 8;
	b[1] = v & 0xFF;

	isc_dnsbuffer_putmem(dnsbuf, b, sizeof(b));
}

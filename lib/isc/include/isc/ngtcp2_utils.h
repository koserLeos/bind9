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

#include <ngtcp2/ngtcp2.h>

#include <isc/sockaddr.h>

#define ISC_NGTCP2_PROTO_VER_RESERVED ((uint32_t)0x1a2a3a4au)
/*%<
 * The versions in form of 0x?a?a?a?a are a reserved to test version
 * negotiation.
 */

void
isc_ngtcp2_gen_cid(ngtcp2_cid *restrict cid);
/*%<
 * Generate a new connection ID data.
 *
 * Requires:
 *\li	'cid' != NULL;
 *\li	'cid->datalen' >= NGTCP2_MIN_CIDLEN && 'cid->datalen' <=
 * NGTCP2_MAX_CIDLEN.
 */

void
isc_ngtcp2_copy_cid(ngtcp2_cid *restrict dst, const ngtcp2_cid *restrict src);
/*%<
 * Copy a connection ID data. 'dst->data' must point to a buffer
 * that is large enough to hold the copied address.
 *
 * Requires:
 *\li	'dst' != NULL && 'dst->data' != NULL && 'dst->datalen' > 0;
 *\li	'src' != NULL && 'src->data' != NULL && 'src->datalen' > 0.
 */

void
isc_ngtcp2_addr_init(ngtcp2_addr *restrict ngaddr,
		     const isc_sockaddr_t *restrict addr);
/*%<
 * Initialize the given 'ngtcp2_addr' object according the data from
 * the given 'isc_sockaddr_t' object.
 *
 * NOTE: Please keep in mind that no data is copied, only pointers are
 * set and they are valid for as long as the given isc_sockaddr_t'
 * object is valid.
 *
 * Requires:
 *\li	'ngaddr' != NULL;
 *\li	'addr' != NULL.
 */

void
isc_ngtcp2_path_init(ngtcp2_path *restrict path,
		     const isc_sockaddr_t *restrict local,
		     const isc_sockaddr_t *restrict peer);
/*%<
 * Initialize the given 'ngtcp2_path' according the data from the
 * given 'isc_sockaddr_t' objects.
 *
 * NOTE: Please keep in mind that no data is copied, only pointers are
 * set and they are valid for as long as the given isc_sockaddr_t'
 * objects are valid.
 *
 * Requires:
 *\li	'path' != NULL;
 *\li	'local' != NULL;
 *\li	'peer' != NULL.
 */

void
isc_ngtcp2_path_storage_init(ngtcp2_path_storage *restrict path_storage,
			     const isc_sockaddr_t *restrict local,
			     const isc_sockaddr_t *restrict peer);
/*%<
 * Initialize the given 'ngtcp2_path_storage' according the data
 * from the given 'isc_sockaddr_t' objects. The data from the provided
 * addresses is copied inside the path storage object.
 *
 * Requires:
 *\li	'path_storage' != NULL;
 *\li	'local' != NULL;
 *\li	'peer' != NULL.
 */

static inline ngtcp2_duration
isc_ngtcp2_make_duration(const uint32_t seconds, const uint32_t millis) {
	const ngtcp2_duration duration =
		((NGTCP2_SECONDS * seconds) + (NGTCP2_MILLISECONDS * millis));

	/*
	 * UINT64_MAX is an invalid value in ngtcp2. Often used as the no-value
	 * marker.
	 */
	INSIST(duration <= UINT64_MAX);

	return (duration);
}
/*%<
 * An utility to generate a duration/timestamp with nanosecond
 * accuracy that is suitable to use in ngtcp2.
 */

void
isc_ngtcp2_mem_init(ngtcp2_mem *restrict mem, isc_mem_t *mctx);
/*%<
 * Initialize an 'ngtcp2_mem' object so that it can be used to route
 * memory allocation operations to the given memory context.
 *
 * Requires:
 *\li	'mem' != NULL;
 *\li	'mctx' != NULL.
 */

bool
isc_ngtcp2_is_version_available(const uint32_t	version,
				const uint32_t *versions,
				const size_t	versions_len);
/*%<
 * Returns 'true' if the given QUIC version is available in the given
 * set of versions.
 *
 * Requires:
 *\li	'versions' != NULL.
 */

uint32_t
isc_ngtcp2_select_version(const uint32_t  client_original_chosen_version,
			  const uint32_t *client_preferred_versions,
			  const size_t	  client_preferred_versions_len,
			  const uint32_t *server_preferred_versions,
			  const size_t	  server_preferred_versions_len);
/*%<
 *
 * Get a negotiated QUIC version following the rules described in
 * RFC8999 and, especially, RFC9368.
 *
 * NOTE: Similar to 'ngtcp2_select_version()' but a bit more strict
 * according to the RFC9368.
 *
 * Requires:
 *\li	'client_preferred_versions' != NULL;
 *\li	'server_preferred_versions' != NULL.
 */

static inline bool
isc_ngtcp_pkt_header_is_long(const uint8_t *pkt, const size_t pktlen) {
	REQUIRE(pkt != NULL);
	REQUIRE(pktlen >= 5);

	if (pkt[0] & 0x80) {
		return (true);
	}

	return (false);
}
/*%<
 * Check if the QUIC packet uses a long form. The function is
 * expected to be used after a successful call to
 * 'ngtcp2_pkt_decode_version_cid()' which does some initial sanity
 * checks on a packet.
 *
 * See RFC8999 for more details about this and other version-agnostic
 * characteristics of QUIC.
 *
 * Requires:
 *\li	'pkt' != NULL;
 *\li	'pktlen' >= 5.
 */

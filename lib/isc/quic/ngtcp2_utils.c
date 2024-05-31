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

#include <string.h>

#include <isc/mem.h>
#include <isc/ngtcp2_utils.h>
#include <isc/random.h>

void
isc_ngtcp2_gen_cid(ngtcp2_cid *restrict cid) {
	REQUIRE(cid != NULL);
	REQUIRE(cid->datalen >= NGTCP2_MIN_CIDLEN &&
		cid->datalen <= NGTCP2_MAX_CIDLEN);

	isc_random_buf(cid->data, cid->datalen);
}

void
isc_ngtcp2_copy_cid(ngtcp2_cid *restrict dst, const ngtcp2_cid *restrict src) {
	REQUIRE(dst != NULL && dst->data != NULL && dst->datalen > 0);
	REQUIRE(src != NULL && src->data != NULL && src->datalen > 0);

	memmove(dst->data, src->data, src->datalen);
	dst->datalen = src->datalen;
}

void
isc_ngtcp2_addr_init(ngtcp2_addr *restrict ngaddr,
		     const isc_sockaddr_t *restrict addr) {
	REQUIRE(ngaddr != NULL);
	REQUIRE(addr != NULL);

	*ngaddr = (ngtcp2_addr){ 0 };

	ngaddr->addr = (ngtcp2_sockaddr *)&addr->type.sa;
	ngaddr->addrlen = (ngtcp2_socklen)addr->length;
}

void
isc_ngtcp2_path_init(ngtcp2_path *restrict path,
		     const isc_sockaddr_t *restrict local,
		     const isc_sockaddr_t *restrict peer) {
	REQUIRE(path != NULL);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	*path = (ngtcp2_path){ 0 };

	isc_ngtcp2_addr_init(&path->local, local);
	isc_ngtcp2_addr_init(&path->remote, peer);
}

void
isc_ngtcp2_path_storage_init(ngtcp2_path_storage *restrict path_storage,
			     const isc_sockaddr_t *restrict local,
			     const isc_sockaddr_t *restrict peer) {
	REQUIRE(path_storage != NULL);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	*path_storage = (ngtcp2_path_storage){ 0 };

	INSIST(local->length <= sizeof(path_storage->local_addrbuf));
	INSIST(peer->length <= sizeof(path_storage->remote_addrbuf));

	ngtcp2_path_storage_init(
		path_storage, (ngtcp2_sockaddr *)&local->type.sa, local->length,
		(ngtcp2_sockaddr *)&peer->type.sa, peer->length, NULL);
}

static void *
isc__ngtcp2_malloc(size_t sz, isc_mem_t *mctx) {
	return (isc_mem_allocate(mctx, sz));
}

static void *
isc__ngtcp2_calloc(size_t n, size_t sz, isc_mem_t *mctx) {
	return (isc_mem_callocate(mctx, n, sz));
}

static void *
isc__ngtcp2_realloc(void *p, size_t newsz, isc_mem_t *mctx) {
	return (isc_mem_reallocate(mctx, p, newsz));
}

static void
isc__ngtcp2_free(void *p, isc_mem_t *mctx) {
	if (p == NULL) { /* as standard free() behaves */
		return;
	}
	isc_mem_free(mctx, p);
}

void
isc_ngtcp2_mem_init(ngtcp2_mem *restrict mem, isc_mem_t *mctx) {
	REQUIRE(mem != NULL);
	REQUIRE(mctx != NULL);

	*mem = (ngtcp2_mem){ .malloc = (ngtcp2_malloc)isc__ngtcp2_malloc,
			     .calloc = (ngtcp2_calloc)isc__ngtcp2_calloc,
			     .realloc = (ngtcp2_realloc)isc__ngtcp2_realloc,
			     .free = (ngtcp2_free)isc__ngtcp2_free,
			     .user_data = (void *)mctx };
}

bool
isc_ngtcp2_is_version_available(const uint32_t version,
				const uint32_t *versions,
				const size_t versions_len) {
	REQUIRE(versions != NULL);

	if (version == 0) {
		return (false);
	}

	for (size_t i = 0; i < versions_len; i++) {
		if (versions[i] == version &&
		    ngtcp2_is_supported_version(version))
		{
			return (true);
		}
	}

	return (false);
}

uint32_t
isc_ngtcp2_select_version(const uint32_t client_original_chosen_version,
			  const uint32_t *client_preferred_versions,
			  const size_t client_preferred_versions_len,
			  const uint32_t *server_preferred_versions,
			  const size_t server_preferred_versions_len) {
	size_t i, k;

	REQUIRE(client_preferred_versions != NULL);
	REQUIRE(server_preferred_versions != NULL);

	/*
	 * RFC RFC9368, Section 4. Version Downgrade Prevention:

	 * Clients MUST ignore any received Version Negotiation packets
	 * that contain the Original Version.
	 * ...
	 * If an endpoint receives a Chosen Version equal to zero, or any
	 * Available Version equal to zero, it MUST treat it as a parsing
	 * failure.
	 */
	for (i = 0; i < server_preferred_versions_len; i++) {
		if (server_preferred_versions[i] ==
			    client_original_chosen_version ||
		    server_preferred_versions[i] == 0)
		{
			return (0);
		}
	}

	/* Choose a protocol version prioritising client's preferences. */
	for (i = 0; i < client_preferred_versions_len; i++) {
		const uint32_t client_version = client_preferred_versions[i];
		for (k = 0; k < server_preferred_versions_len; k++) {
			const uint32_t server_version =
				server_preferred_versions[k];
			if (client_version == server_version &&
			    ngtcp2_is_supported_version(client_version) &&
			    ngtcp2_is_supported_version(server_version))
			{
				return (client_version);
			}
		}
	}

	return (0);
}

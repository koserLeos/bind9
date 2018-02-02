/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef DNS_ECS_H
#define DNS_ECS_H 1

#include <isc/netaddr.h>
#include <isc/types.h>

#include <dns/rdatatype.h>
#include <dns/types.h>

struct dns_ecs {
	isc_netaddr_t addr;
	isc_uint8_t source;
	isc_uint8_t scope;
};

#define DNS_ECS_FORMATSIZE (ISC_NETADDR_FORMATSIZE + 9) /* <address>/NNN/NNN */

ISC_LANG_BEGINDECLS

void
dns_ecs_init(dns_ecs_t *ecs);
/*%<
 * Initialize a DNS ECS structure.
 *
 * Requires:
 * \li 'ecs' is not NULL and points to a valid dns_ecs structure.
 */

isc_boolean_t
dns_ecs_type_allowed(isc_buffer_t *ecstypes, dns_rdatatype_t type);
/*%<
 * Returns ISC_TRUE if a given rdatatype is set in the
 * type bitmap referenced in the buffer 'ecstypes', otherwise
 * returns ISC_FALSE.
 *
 * Note: regardless of 'ecstypes', CNAME is *always* allowed,
 * and DNS infrastructure types such as SOA, NS, DS, and DNSKEY
 * are never allowed.
 */

isc_result_t
dns_ecszones_create(isc_mem_t *mctx, dns_ecszones_t **edp);

void
dns_ecszones_free(dns_ecszones_t **ecszonesp);
/*%<
 * Create and free an "ecs-zones" red-black tree. This stores
 * data indicating what domains should be sent ECS-tagged queries by
 * a recursive resolver, and what the source prefix lengths should be
 * for IPv4 and IPv6 queries.
 */

isc_result_t
dns_ecszones_setdomain(dns_ecszones_t *ecszones, dns_name_t *name,
		       isc_boolean_t negated,
		       isc_uint8_t bits4, isc_uint8_t bits6);
/*%<
 * Mark domains under 'name' as supporting (or, if 'negated' is true,
 * not supporting) the ECS option.  If supporting, then the prefix length
 * for IPv4 queries is set to 'bits4' and IPv6 queries to 'bits6'.
 *
 * Requires:
 * \li  'ecszones' is not NULL.
 * \li  'name' is not NULL.
 */

isc_boolean_t
dns_ecszones_name_allowed(dns_ecszones_t *ecszones, dns_name_t *name,
			  isc_uint8_t *bits4, isc_uint8_t *bits6);
/*%<
 * Find out whether 'name' is in a zone which is marked as supporting
 * the ECS option. If so, update '*bits4' and '*bits6' with the
 * corresponding values from the 'ecszones' tree.
 *
 * Requires:
 * \li  'name' is not NULL.
 */

isc_boolean_t
dns_ecs_equals(dns_ecs_t *ecs1, dns_ecs_t *ecs2);
/*%<
 * Determine whether two ECS address prefixes are equal (except the
 * scope prefix-length field).
 *
 * 'ecs1->source' must exactly match 'ecs2->source'; the address families
 * must match; and the first 'ecs1->source' bits of the addresses must
 * match. Subsequent address bits and the 'scope' values are ignored.
 */

void
dns_ecs_format(dns_ecs_t *ecs, char *buf, size_t size);
/*%<
 * Format an ECS record as text. Result is guaranteed to be null-terminated.
 *
 * Requires:
 * \li  'ecs' is not NULL.
 * \li  'buf' is not NULL.
 * \li  'size' is at least DNS_ECS_FORMATSIZE
 */

void
dns_ecs_formatfordump(dns_ecs_t *ecs, char *buf, size_t size);
/*%<
 * Format an ECS record as text for dumping cache entries to a
 * file. Result is guaranteed to be null-terminated.
 *
 * Requires:
 * \li  'ecs' is not NULL.
 * \li  'buf' is not NULL.
 * \li  'size' is at least DNS_ECS_FORMATSIZE
 */
ISC_LANG_ENDDECLS
#endif /* DNS_ECS_H */

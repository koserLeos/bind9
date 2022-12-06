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

#include <inttypes.h>
#include <stdbool.h>

#include <isc/lang.h>
#include <isc/region.h>

#include <dns/name.h>
#include <dns/types.h>

ISC_LANG_BEGINDECLS

/*
 * A name compression context handles compression of multiple DNS names in
 * relation to a single DNS message. The context can be used to selectively
 * turn on/off compression for specific names (depending on the RR type,
 * according to RFC 3597) by using \c dns_compress_setpermitted().
 *
 * The nameserver can be configured not to use compression at all using
 * \c dns_compress_disable().
 *
 * DNS name compression only needs exact matches on (suffixes of) names. We
 * could use a data structure that supports longest-match lookups, but that
 * would introduce a lot of heavyweight machinery, and all we need is
 * something that exists very briefly to store a few names before it is
 * thrown away.
 *
 * In the abstract we need a map from DNS names to compression offsets. But
 * a compression offset refers to a point in the message where the name has
 * been written. So in fact all we need is a hash set of compression offsets.
 *
 * Typical messages do not contain more than a few dozen names, so by
 * default our hash set is small (64 entries, 256 bytes). It can be
 * enlarged when a message is likely to contain a lot of names, such as for
 * outgoing zone transfers (which are handled in lib/ns/xfrout.c) and
 * update requests (for which nsupdate uses DNS_REQUESTOPT_LARGE - see
 * request.h).
 */

/*
 * Logarithms of hash set sizes. In the usual (small) case, allow for for a
 * few dozen names in the hash set. (We can't actually use every slot because
 * space is reserved for performance reasons.) For large messages, the number
 * of names is limited by the minimum size of an RR (owner, type, class, ttl,
 * length) which is 12 bytes - call it 16 bytes to make space for a new label.
 * Divide the maximum compression offset 0x4000 by 16 and you get 0x400 == 1024.
 * In practice, the root zone (for example) uses less than 200 distinct names
 * per message.
 */
enum {
	DNS_COMPRESS_SMALLBITS = 6,
	DNS_COMPRESS_LARGEBITS = 10,
};

/*
 * Compression context flags
 */
enum dns_compress_flags {
	/* affecting the whole message */
	DNS_COMPRESS_DISABLED = 0x00000001U,
	DNS_COMPRESS_CASE = 0x00000002U,
	DNS_COMPRESS_LARGE = 0x00000004U,
	/* can toggle while rendering a message */
	DNS_COMPRESS_PERMITTED = 0x00000008U,
};

/*
 * The hash may be any 16 bit value. Unused slots have coff == 0. (Valid
 * compression offsets cannot be zero because of the DNS message header.)
 */
struct dns_compress_slot {
	uint16_t hash;
	uint16_t coff;
};

struct dns_compress {
	unsigned int	     magic;
	dns_compress_flags_t flags;
	uint16_t	     mask;
	uint16_t	     count;
	isc_mem_t	    *mctx;
	dns_compress_slot_t *set;
	dns_compress_slot_t  smallset[1 << DNS_COMPRESS_SMALLBITS];
};

/*
 *	*** WARNING ***
 *
 * THe dns_decompress routines deal with raw network data. An error in these
 * routines could result in the failure or hijacking of the server.
 *
 * A decompression context handles compression of multiple DNS names in
 * relation to a single DNS message.
 *
 * Depending on the caller's requirements, we either expect all names to be
 * uncompressed already, or we allow any name to need decompression
 * regardless of whether that is strictly allowed by RFC 3579. Decompression
 * is disabled by a NULL decompression context pointer, and allowed by an
 * initialized decompression context.
 *
 * The decompression context has two jobs. It allows us to avoid chasing
 * pointers multiple times by keeping a cache of compression pointer targets;
 * when we get a cache hit we can re-use a previous name, or part of a name,
 * without re-parsing. And it helps dns_message_parse() to match owner names
 * when collecting records into an rdataset.
 *
 * This does not entirely eliminate pointer chasing. We normally encounter
 * and cache names before they are used as pointer targets, but it is
 * possible for a pointer to refer to the RDATA of a record with an unknown
 * RRtype, which we will not have parsed. (Thanks to Peter "habbie" van Dijk
 * for pointing out this example.) This means that we can't defend against
 * malicious messages that force decompression cache misses.
 */

/*
 * The decompression cache needs to be very fast, ideally faster than
 * chasing pointers, or at least negligibly slower than chasing one
 * pointer. It also needs to avoid using lots of memory. It is
 * difficult to satisfy both of these requirements using a data
 * structure that is indexed with the compression pointer's value.
 *
 * Instead we use a dirty and dangerous trick. This is probably unwise.
 *
 * After we have parsed a name, we add the possible compression
 * pointer targets (the start of each label) to the cache. The label
 * length octet in the message is OVERWRITTEN by the cache slot
 * number. The cache slot contains the label length that we overwrote,
 * and its offset in the message, i.e. its pointer target value.
 *
 * To look up a compression pointer in the cache, we get the octet in
 * the message at the pointer's target, and use that as a cache slot
 * number. We cross-check by verifying that the slot's message offset
 * matches the pointer target.
 *
 * When parsing a message, there are two contexts for names.
 *
 * Inside rdata, the dns_name_t objects passed to dns_name_fromwire()
 * are ephemeral; the decompressed name is only retained in the
 * dns_rdata_fromwire() target buffer. This means the decompression
 * cache must contain enough information about the name without using
 * a dns_name_t pointer. All we need is a pointer into the target
 * buffer and the length of the name. These will describe a suffix of
 * the name when the compression pointer target is not the first label.
 *
 * Owner names are special because dns_message_parse() needs to match
 * them in order to collect records into RRsets. We know that they are
 * allocated as dns_fixedname_t objects, so with some offsetof()
 * tricks we can find the fixedname's address using its name_data
 * pointer. We only need to do this for the first label in a name,
 * because we only need to find exact matches.
 */
struct dns_decompress_slot {
	uint16_t message_offset : 14;
	uint16_t name_is_owner	: 1;
	uint8_t	 saved_label_length;
	uint8_t	 label_count;
	uint8_t	 name_length;
	uint8_t *name_data;
} __attribute__((__packed__));

/*
 * A decompression context contains a little extra state to help with
 * matching owner names.
 *
 * dns_message_parse() calls dns_decompress_findowner() to tell us we
 * should check for exact matches on the next call; if we find one, it
 * gets stashed in the `found` member so it can be retrieved.
 */
enum {
	DNS_DECOMPRESS_DEFAULT,
	DNS_DECOMPRESS_FINDOWNER,
	DNS_DECOMPRESS_EXISTS,
};

struct dns_decompress {
	unsigned int	      magic;
	unsigned int	      mode;   /*%< findowner state */
	unsigned int	      found;  /*%< matching owner */
	unsigned int	      count;  /*%< of cache entries */
	isc_buffer_t	     *source; /*%< for safety */
	dns_decompress_slot_t cache[256];
};

/**********************************************************************/

void
dns_compress_init(dns_compress_t *cctx, isc_mem_t *mctx,
		  dns_compress_flags_t flags);
/*%<
 *	Initialise the compression context structure pointed to by
 *	'cctx'.
 *
 *	The `flags` argument is usually zero; or some combination of:
 *\li		DNS_COMPRESS_DISABLED, so the whole message is uncompressed
 *\li		DNS_COMPRESS_CASE, for case-sensitive compression
 *\li		DNS_COMPRESS_LARGE, for messages with many names
 *
 *	(See also dns_request_create()'s options argument)
 *
 *	Requires:
 *\li		'cctx' is a dns_compress_t structure on the stack.
 *\li		'mctx' is an initialized memory context.
 *	Ensures:
 *\li		'cctx' is initialized.
 *\li		'dns_compress_getpermitted(cctx)' is true
 */

void
dns_compress_invalidate(dns_compress_t *cctx);
/*%<
 *	Invalidate the compression structure pointed to by
 *	'cctx', freeing any memory that has been allocated.
 *
 *	Requires:
 *\li		'cctx' is an initialized dns_compress_t
 */

void
dns_compress_setpermitted(dns_compress_t *cctx, bool permitted);
/*%<
 *	Sets whether compression is allowed, according to RFC 3597.
 *	This can vary depending on the rdata type.
 *
 *	Requires:
 *\li		'cctx' to be initialized.
 */

bool
dns_compress_getpermitted(dns_compress_t *cctx);
/*%<
 *	Find out whether compression is allowed, according to RFC 3597.
 *
 *	Requires:
 *\li		'cctx' to be initialized.
 *
 *	Returns:
 *\li		allowed compression bitmap.
 */

void
dns_compress_name(dns_compress_t *cctx, isc_buffer_t *buffer,
		  const dns_name_t *name, unsigned int *return_prefix,
		  unsigned int *return_coff);
/*%<
 *	Finds longest suffix matching 'name' in the compression table,
 *	and adds any remaining prefix of 'name' to the table.
 *
 *	This is used by dns_name_towire() for both compressed and uncompressed
 *	names; for uncompressed names, dns_name_towire() does not need to know
 *	about the matching suffix, but it still needs to add the name for use
 *	by later compression pointers. For example, an owner name of a record
 *	in the additional section will often need to refer back to an RFC 3597
 *	uncompressed name in the rdata of a record in the answer section.
 *
 *	Requires:
 *\li		'cctx' to be initialized.
 *\li		'buffer' contains the rendered message.
 *\li		'name' to be a absolute name.
 *\li		'return_prefix' points to an unsigned int.
 *\li		'return_coff' points to an unsigned int, which must be zero.
 *
 *	Ensures:
 *\li		When no suffix is found, the return variables
 *              'return_prefix' and 'return_coff' are unchanged
 *
 *\li		Otherwise, '*return_prefix' is set to the length of the
 *		prefix of the name that did not match, and '*suffix_coff'
 *		is set to a nonzero compression offset of the match.
 */

void
dns_compress_rollback(dns_compress_t *cctx, unsigned int offset);
/*%<
 *	Remove any compression pointers from the table that are >= offset.
 *
 *	Requires:
 *\li		'cctx' is initialized.
 */

/**********************************************************************/

/*%
 * The various per-rdatatype fromwire() functions call setpermitted(dctx)
 * according to whether RFC 3579 says name compression is allowed inside that
 * particular type's RDATA. But (apart from the tests) decompression contexts
 * were never initialized in a way that allowed these fromwire setpermitted()
 * calls to make any changes. So this function has become a no-op.
 *
 * The dns_decompress_setpermitted() calls remain as documentation of whether
 * an rdatatype allows compression or not, according to RFC 3579, and for
 * symmetry with the compression contexts in the towire() functions.
 */
#define dns_decompress_setpermitted(dctx, permitted) /* no-op */

/*%
 * Returns whether decompression is allowed here
 */
#define dns_decompress_getpermitted(dctx) (dctx != NULL)

void
dns_decompress_init(dns_decompress_t *dctx, isc_buffer_t *message);
/*%<
 * Initializes 'dctx'.
 *
 * A pointer to the message buffer is stored in the decompression
 * context so that we can ensure that later calls are consistent.
 *
 * Requires:
 *
 * \li	'dctx' is not NULL.
 *
 * \li	'message' is a buffer containing the message.
 */

void
dns_decompress_invalidate(dns_decompress_t *dctx);
/*%<
 * Invalidates 'dctx'.
 *
 * Requires:
 *
 * \li	'dctx' is a valid decompression context.
 */
void
dns_decompress_rollback(dns_decompress_t *dctx, isc_buffer_t *source);
void
dns_decompress_findowner(dns_decompress_t *dctx);
dns_name_t *
dns_decompress_getowner(dns_decompress_t *dctx);

void
dns_decompress_add(dns_decompress_t *dctx, isc_buffer_t *source,
		   dns_name_t *name);

isc_result_t
dns_decompress_pointer(dns_decompress_t *dctx, isc_buffer_t *source,
		       dns_name_t *name, isc_buffer_t *target);

ISC_LANG_ENDDECLS

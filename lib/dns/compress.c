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

#define DNS_NAME_USEINLINE 1

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>

#define HASH_INIT_DJB2 5381

#define CCTX_MAGIC    ISC_MAGIC('C', 'C', 'T', 'X')
#define CCTX_VALID(x) ISC_MAGIC_VALID(x, CCTX_MAGIC)

#define DCTX_MAGIC    ISC_MAGIC('D', 'C', 'T', 'X')
#define DCTX_VALID(x) ISC_MAGIC_VALID(x, DCTX_MAGIC)
#define DCTX_VALID_SOURCE(dctx, source) \
	(ISC_MAGIC_VALID(dctx, DCTX_MAGIC) && dctx->source == source)

void
dns_compress_init(dns_compress_t *cctx, isc_mem_t *mctx,
		  dns_compress_flags_t flags) {
	dns_compress_slot_t *set = NULL;
	uint16_t mask;

	REQUIRE(cctx != NULL);
	REQUIRE(mctx != NULL);

	if ((flags & DNS_COMPRESS_LARGE) != 0) {
		size_t size = (1 << DNS_COMPRESS_LARGEBITS);
		size_t bytes = size * sizeof(*set);
		set = isc_mem_allocatex(mctx, bytes, ISC_MEM_ZERO);
		mask = size - 1;
	} else {
		set = cctx->smallset;
		mask = ARRAY_SIZE(cctx->smallset) - 1;
	}

	/*
	 * The lifetime of this object is limited to the stack frame of the
	 * caller, so we don't need to attach to the memory context.
	 */
	*cctx = (dns_compress_t){
		.magic = CCTX_MAGIC,
		.flags = flags | DNS_COMPRESS_PERMITTED,
		.mctx = mctx,
		.mask = mask,
		.set = set,
	};
}

void
dns_compress_invalidate(dns_compress_t *cctx) {
	REQUIRE(CCTX_VALID(cctx));
	if (cctx->set != cctx->smallset) {
		isc_mem_free(cctx->mctx, cctx->set);
	}
	cctx->magic = 0;
	cctx->mctx = NULL;
	cctx->set = NULL;
}

void
dns_compress_setpermitted(dns_compress_t *cctx, bool permitted) {
	REQUIRE(CCTX_VALID(cctx));
	if (permitted) {
		cctx->flags |= DNS_COMPRESS_PERMITTED;
	} else {
		cctx->flags &= ~DNS_COMPRESS_PERMITTED;
	}
}

bool
dns_compress_getpermitted(dns_compress_t *cctx) {
	REQUIRE(CCTX_VALID(cctx));
	return ((cctx->flags & DNS_COMPRESS_PERMITTED) != 0);
}

/*
 * Our hash value needs to cover the entire suffix of a name, and we need
 * to calculate it one label at a time. So this function mixes a label into
 * an existing hash. (We don't use isc_hash32() because the djb2 hash is a
 * lot faster, and we limit the impact of collision attacks by restricting
 * the size and occupancy of the hash set.) The accumulator is 32 bits to
 * keep more of the fun mixing that happens in the upper bits.
 */
static uint16_t
hash_label(uint16_t init, uint8_t *ptr, bool sensitive) {
	unsigned int len = ptr[0] + 1;
	uint32_t hash = init;

	if (sensitive) {
		while (len-- > 0) {
			hash = hash * 33 + *ptr++;
		}
	} else {
		/* using the autovectorize-friendly tolower() */
		while (len-- > 0) {
			hash = hash * 33 + isc__ascii_tolower1(*ptr++);
		}
	}

	return (isc_hash_bits32(hash, 16));
}

static bool
match_wirename(uint8_t *a, uint8_t *b, unsigned int len, bool sensitive) {
	if (sensitive) {
		return (memcmp(a, b, len) == 0);
	} else {
		/* label lengths are < 'A' so unaffected by tolower() */
		return (isc_ascii_lowerequal(a, b, len));
	}
}

/*
 * We have found a hash set entry whose hash value matches the current
 * suffix of our name, which is passed to this function via `sptr` and
 * `slen`. We need to verify that the suffix in the message (referred to
 * by `new_coff`) actually matches, in case of hash collisions.
 *
 * We know that the previous suffix of this name (after the first label)
 * occurs in the message at `old_coff`, and all the compression offsets in
 * the hash set and in the message refer to the first occurrence of a
 * particular name or suffix.
 *
 * First, we need to match the label that was just added to our suffix,
 * and second, verify that it is followed by the previous suffix.
 *
 * There are a few ways to match the previous suffix:
 *
 * When the first occurrence of this suffix is also the first occurrence
 * of the previous suffix, `old_coff` points just after the new label.
 *
 * Otherwise, if this suffix occurs in a compressed name, it will be
 * followed by a compression pointer that refers to the previous suffix,
 * which must be equal to `old_coff`.
 *
 * The final possibility is that this suffix occurs in an uncompressed
 * name, so we have to compare the rest of the suffix in full.
 *
 * A special case is when this suffix is a TLD. That can be handled by
 * the case for uncompressed names, but it is common enough that it is
 * worth taking a short cut. (In the TLD case, the `old_coff` will be
 * zero, and the quick checks for the previous suffix will fail.)
 */
static bool
match_suffix(isc_buffer_t *buffer, unsigned int new_coff, uint8_t *sptr,
	     unsigned int slen, unsigned int old_coff, bool sensitive) {
	uint16_t ptr = old_coff | DNS_NAME_PTRBITS;
	uint8_t pptr[] = { ptr >> 8, ptr & 0xff };
	uint8_t *bptr = isc_buffer_base(buffer);
	unsigned int blen = isc_buffer_usedlength(buffer);
	unsigned int llen = sptr[0] + 1;

	INSIST(DNS_LABEL_ISNORMAL(llen) && llen < slen);

	if (blen < new_coff + llen) {
		return (false);
	}

	blen -= new_coff;
	bptr += new_coff;

	/* does the first label of the suffix appear here? */
	if (!match_wirename(bptr, sptr, llen, sensitive)) {
		return (false);
	}

	/* is this label followed by the previously matched suffix? */
	if (old_coff == new_coff + llen) {
		return (true);
	}

	blen -= llen;
	bptr += llen;
	slen -= llen;
	sptr += llen;

	/* are both labels followed by the root label? */
	if (blen >= 1 && slen == 1 && bptr[0] == 0 && sptr[0] == 0) {
		return (true);
	}

	/* is this label followed by a pointer to the previous match? */
	if (blen >= 2 && bptr[0] == pptr[0] && bptr[1] == pptr[1]) {
		return (true);
	}

	/* is this label followed by a copy of the rest of the suffix? */
	return (blen >= slen && match_wirename(bptr, sptr, slen, sensitive));
}

/*
 * Robin Hood hashing aims to minimize probe distance when inserting a
 * new element by ensuring that the new element does not have a worse
 * probe distance than any other element in its probe sequence. During
 * insertion, if an existing element is encountered with a shorter
 * probe distance, it is swapped with the new element, and insertion
 * continues with the displaced element.
 */
static unsigned int
probe_distance(dns_compress_t *cctx, unsigned int slot) {
	return ((slot - cctx->set[slot].hash) & cctx->mask);
}

static unsigned int
slot_index(dns_compress_t *cctx, unsigned int hash, unsigned int probe) {
	return ((hash + probe) & cctx->mask);
}

static bool
insert_label(dns_compress_t *cctx, isc_buffer_t *buffer, const dns_name_t *name,
	     unsigned int label, uint16_t hash, unsigned int probe) {
	/*
	 * hash set entries must have valid compression offsets
	 * and the hash set must not get too full (75% load)
	 */
	unsigned int prefix_len = name->offsets[label];
	unsigned int coff = isc_buffer_usedlength(buffer) + prefix_len;
	if (coff > DNS_NAME_MAXPTR || cctx->count > cctx->mask * 3 / 4) {
		return false;
	}
	for (;;) {
		unsigned int slot = slot_index(cctx, hash, probe);
		/* we can stop when we find an empty slot */
		if (cctx->set[slot].coff == 0) {
			cctx->set[slot].hash = hash;
			cctx->set[slot].coff = coff;
			cctx->count++;
			return true;
		}
		/* he steals from the rich and gives to the poor */
		if (probe > probe_distance(cctx, slot)) {
			probe = probe_distance(cctx, slot);
			ISC_SWAP(cctx->set[slot].hash, hash);
			ISC_SWAP(cctx->set[slot].coff, coff);
		}
		probe++;
	}
}

/*
 * Add the unmatched prefix of the name to the hash set.
 */
static void
insert(dns_compress_t *cctx, isc_buffer_t *buffer, const dns_name_t *name,
       unsigned int label, uint16_t hash, unsigned int probe) {
	bool sensitive = (cctx->flags & DNS_COMPRESS_CASE) != 0;
	/*
	 * this insertion loop continues from the search loop inside
	 * dns_compress_name() below, iterating over the remaining labels
	 * of the name and accumulating the hash in the same manner
	 */
	while (insert_label(cctx, buffer, name, label, hash, probe) &&
	       label-- > 0)
	{
		unsigned int prefix_len = name->offsets[label];
		uint8_t *suffix_ptr = name->ndata + prefix_len;
		hash = hash_label(hash, suffix_ptr, sensitive);
		probe = 0;
	}
}

void
dns_compress_name(dns_compress_t *cctx, isc_buffer_t *buffer,
		  const dns_name_t *name, unsigned int *return_prefix,
		  unsigned int *return_coff) {
	REQUIRE(CCTX_VALID(cctx));
	REQUIRE(ISC_BUFFER_VALID(buffer));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(name->labels > 0);
	REQUIRE(name->offsets != NULL);
	REQUIRE(return_prefix != NULL);
	REQUIRE(return_coff != NULL);
	REQUIRE(*return_coff == 0);

	if ((cctx->flags & DNS_COMPRESS_DISABLED) != 0) {
		return;
	}

	bool sensitive = (cctx->flags & DNS_COMPRESS_CASE) != 0;

	uint16_t hash = HASH_INIT_DJB2;
	unsigned int label = name->labels - 1; /* skip the root label */

	/*
	 * find out how much of the name's suffix is in the hash set,
	 * stepping backwards from the end one label at a time
	 */
	while (label-- > 0) {
		unsigned int prefix_len = name->offsets[label];
		unsigned int suffix_len = name->length - prefix_len;
		uint8_t *suffix_ptr = name->ndata + prefix_len;
		hash = hash_label(hash, suffix_ptr, sensitive);

		for (unsigned int probe = 0; true; probe++) {
			unsigned int slot = slot_index(cctx, hash, probe);
			unsigned int coff = cctx->set[slot].coff;

			/*
			 * if we would have inserted this entry here (as in
			 * insert_label() above), our suffix cannot be in the
			 * hash set, so stop searching and switch to inserting
			 * the rest of the name (its prefix) into the set
			 */
			if (coff == 0 || probe > probe_distance(cctx, slot)) {
				insert(cctx, buffer, name, label, hash, probe);
				return;
			}

			/*
			 * this slot matches, so provisionally set the
			 * return values and continue with the next label
			 */
			if (hash == cctx->set[slot].hash &&
			    match_suffix(buffer, coff, suffix_ptr, suffix_len,
					 *return_coff, sensitive))
			{
				*return_coff = coff;
				*return_prefix = prefix_len;
				break;
			}
		}
	}
}

void
dns_compress_rollback(dns_compress_t *cctx, unsigned int coff) {
	REQUIRE(CCTX_VALID(cctx));

	for (unsigned int slot = 0; slot <= cctx->mask; slot++) {
		if (cctx->set[slot].coff < coff) {
			continue;
		}
		/*
		 * The next few elements might be part of the deleted element's
		 * probe sequence, so we slide them down to overwrite the entry
		 * we are deleting and preserve the probe sequence. Moving an
		 * element to the previous slot reduces its probe distance, so
		 * we stop when we find an element whose probe distance is zero.
		 */
		unsigned int prev = slot;
		unsigned int next = slot_index(cctx, prev, 1);
		while (cctx->set[next].coff != 0 &&
		       probe_distance(cctx, next) != 0)
		{
			cctx->set[prev] = cctx->set[next];
			prev = next;
			next = slot_index(cctx, prev, 1);
		}
		cctx->set[prev].coff = 0;
		cctx->set[prev].hash = 0;
		cctx->count--;
	}
}

/**********************************************************************/

/*
 *	*** WARNING ***
 *
 * The dns_decompress routines deal with raw network data. An error in
 * these routines could result in the failure or hijacking of the
 * server. (It is more risky than dns_name_fromwire() because here we
 * have to handle compression pointers.)
 *
 * The description of name compression in RFC 1035 section 4.1.4 is
 * subtle wrt certain edge cases. The first important sentence is:
 *
 * > In this scheme, an entire domain name or a list of labels at the
 * > end of a domain name is replaced with a pointer to a prior
 * > occurance of the same name.
 *
 * The key word is "prior". This says that compression pointers must
 * point strictly earlier in the message (before our "marker" variable),
 * which is enough to prevent DoS attacks due to compression loops.
 *
 * It is possible that we might not have parsed a prior occurance of a
 * name as a name, for instance, if it was in the RDATA of a record
 * with an unknown RRtype. This makes it difficult to detect dirty
 * tricks with pointers and cut parsing short with a FORMERR.
 *
 * The next important sentence is:
 *
 * > If a domain name is contained in a part of the message subject to a
 * > length field (such as the RDATA section of an RR), and compression
 * > is used, the length of the compressed name is used in the length
 * > calculation, rather than the length of the expanded name.
 *
 * When decompressing, this means that the amount of the source buffer
 * that we consumed (which is checked wrt the container's length field)
 * is the length of the compressed name. A compressed name is defined as
 * a sequence of labels ending with the root label or a compression
 * pointer, that is, the segment of the name that dns_name_fromwire()
 * examines first.
 *
 * This matters when handling names that play dirty tricks, like:
 *
 *	+---+---+---+---+---+---+
 *	| 4 | 1 |'a'|192| 0 | 0 |
 *	+---+---+---+---+---+---+
 *
 * We start at octet 1. There is an ordinary single character label "a",
 * followed by a compression pointer that refers back to octet zero.
 * Here there is a label of length 4, which weirdly re-uses the octets
 * we already examined as the data for the label. It is followed by the
 * root label,
 *
 * The specification says that the compressed name ends after the first
 * zero octet (after the compression pointer) not the second zero octet,
 * even though the second octet is later in the message. This shows the
 * correct way to set our "consumed" variable.
 */

void
dns_decompress_init(dns_decompress_t *dctx, isc_buffer_t *source) {
	REQUIRE(dctx != NULL);
	REQUIRE(source != NULL);

	*dctx = (dns_decompress_t){
		.magic = CCTX_MAGIC,
		.source = source,
	};
}

void
dns_decompress_findowner(dns_decompress_t *dctx) {
	REQUIRE(DCTX_VALID(dctx));

	dctx->mode = DNS_DECOMPRESS_FINDOWNER;
}

dns_name_t *
dns_decompress_getowner(dns_decompress_t *dctx) {
	REQUIRE(DCTX_VALID(dctx));
	REQUIRE(dctx->mode == DNS_DECOMPRESS_EXISTS);
	REQUIRE(dctx->cache[dctx->found].name_is_owner);

	uint8_t *name_data = dctx->cache[dctx->found].name_data;
	uint8_t *offset_name = name_data - offsetof(dns_fixedname_t, data);
	dns_name_t *name = (dns_name_t *)offset_name;
	INSIST(name->magic == DNS_NAME_MAGIC);
	INSIST(name->ndata == name_data);
	dctx->mode = DNS_DECOMPRESS_DEFAULT;

	return (name);
}

/*
 * Restore the message buffer to its state before we marked its
 * pointer targets, between:
 *
 * - max_offset, always the end of the message;
 *
 * - min_offset, determined by the functions below
 */
static void
decompress_rollback(dns_decompress_t *dctx, uint32_t min_offset) {
	isc_buffer_t *source = dctx->source;
	uint8_t *base = isc_buffer_base(source);
	uint32_t max_offset = isc_buffer_usedlength(source);
	uint32_t slot = dctx->count;

	while (slot-- > 0) {
		uint32_t message_offset = dctx->cache[slot].message_offset;
		INSIST(message_offset < max_offset);
		if (message_offset < min_offset) {
			break;
		}
		base[message_offset] = dctx->cache[slot].saved_label_length;
		dctx->cache[slot] = (dns_decompress_slot_t){};
		dctx->count = slot;
	}
}

/*
 * When dns_rdata_fromwire() fails, it rolls back the consumed part of
 * the source buffer, and calls dns_decompress_rollback() to clean up
 * the unconsumed rdata.
 *
 * If it failed because there was not enough space in the rdata target
 * buffer, dns_message_parse() will reallocate the buffer and retry,
 * so we need to have cleaned up after the first attempt so the second
 * attempt does not encounter our mess.
 */
void
dns_decompress_rollback(dns_decompress_t *dctx, isc_buffer_t *source) {
	REQUIRE(DCTX_VALID_SOURCE(dctx, source));

	decompress_rollback(dctx, isc_buffer_consumedlength(source));
}

/*
 * At the end of dns_message_parse() the decompression context is
 * invalidated, and we clean up the whole message.
 */
void
dns_decompress_invalidate(dns_decompress_t *dctx) {
	REQUIRE(DCTX_VALID(dctx));

	decompress_rollback(dctx, 0);
	INSIST(dctx->count == 0);

	dctx->magic = 0;
	dctx->source = NULL;
}

/*
 * Add a name to the decompression cache after it has been parsed.
 *
 * It's mildly annoying that we have to loop over the labels a second
 * time, but it's necessary because we don't know the name length
 * until the end of the first loop. And it makes error cleanup easier,
 * so I guess it isn't too bad.
 */
static void
decompress_add(dns_decompress_t *dctx, dns_name_t *name) {
	uint32_t message_offset = isc_buffer_consumedlength(dctx->source);
	uint8_t *name_data = isc_buffer_current(dctx->source);
	uint8_t name_length = name->length;
	uint8_t label_count = name->labels;
	bool name_is_owner = dctx->mode == DNS_DECOMPRESS_FINDOWNER;

	while (message_offset <= DNS_NAME_MAXPTR &&
	       dctx->count < ARRAY_SIZE(dctx->cache))
	{
		uint8_t label_len = *name_data;

		if (DNS_LABEL_ISROOT(label_len) || DNS_LABEL_ISPTR(label_len)) {
			break;
		}
		*name_data = dctx->count;
		dctx->cache[dctx->count++] = (dns_decompress_slot_t){
			.saved_label_length = label_len,
			.message_offset = message_offset,
			.name_is_owner = name_is_owner,
			.label_count = label_count,
			.name_length = name_length,
			.name_data = name_data,
		};
		message_offset += label_len + 1;
		name_data += label_len + 1;
		name_length -= label_len + 1;
		label_count -= 1;
		name_is_owner = false;
	}
}

/*
 * dns_name_fromwire() parsed up to a root label
 */
void
dns_decompress_add(dns_decompress_t *dctx, isc_buffer_t *source,
		   dns_name_t *name) {
	REQUIRE(DCTX_VALID_SOURCE(dctx, source));
	REQUIRE(isc_buffer_remaininglength(source) >= name->length);

	decompress_add(dctx, name);
	isc_buffer_forward(source, name->length);
	/* we did not find an instant match */
	dctx->mode = DNS_DECOMPRESS_DEFAULT;
}

#define CHECK(condition, result)                      \
	if (!(condition)) {                           \
		dctx->mode == DNS_DECOMPRESS_DEFAULT; \
		dns_name_reset(name);                 \
		return (result);                      \
	} else

/*
 * dns_name_fromwire() parsed up to a compression pointer
 */
isc_result_t
dns_decompress_pointer(dns_decompress_t *dctx, isc_buffer_t *source,
		       dns_name_t *name, isc_buffer_t *target) {
	REQUIRE(DCTX_VALID_SOURCE(dctx, source));
	REQUIRE(name != NULL && name->magic == DNS_NAME_MAGIC);
	REQUIRE(!dns_name_isabsolute(name));

	uint32_t source_remaining = isc_buffer_remaininglength(source);
	uint32_t name_len = name->length;
	CHECK(name_len + 2 <= source_remaining, ISC_R_UNEXPECTEDEND);

	uint8_t *name_src = isc_buffer_current(source);
	uint8_t hi = name_src[name_len + 0];
	uint8_t lo = name_src[name_len + 1];
	uint16_t pointer = DNS_NAME_PTRTARGET(hi, lo);
	CHECK(pointer < isc_buffer_consumedlength(source), DNS_R_BADPOINTER);

	uint8_t *src_base = isc_buffer_base(source);
	uint8_t slot_number = src_base[pointer];
	dns_decompress_slot_t *slot = &dctx->cache[slot_number];
	/* here we should decompress the hard way instead of giving up */
	CHECK(slot->message_offset == pointer, ISC_R_NOTIMPLEMENTED);

	/* instant match: our name is just a pointer to another owner name */
	if (dctx->mode == DNS_DECOMPRESS_FINDOWNER && slot->name_is_owner &&
	    name_len == 0)
	{
		dctx->mode = DNS_DECOMPRESS_EXISTS;
		dctx->found = slot_number;
		return (ISC_R_EXISTS);
	}

	dns_name_t suffix = DNS_NAME_INITEMPTY;
	suffix.attributes.absolute = true;
	suffix.length = slot->name_length;
	suffix.labels = slot->label_count;
	suffix.ndata = slot->name_data;

	isc_result_t result = dns_name_append(name, &suffix, target);
	if (result == ISC_R_SUCCESS) {
		decompress_add(dctx, name);
		isc_buffer_forward(source, name_len + 2); /* and pointer */
	}
	dctx->mode = DNS_DECOMPRESS_DEFAULT;
	return (result);
}

#if 0

static isc_result_t
decompress_unmatched(dns_name_t *name, isc_buffer_t *source,
		     dns_decompress_t *dctx, isc_buffer_t *target) {
	REQUIRE(DCTX_VALID(dctx));
	REQUIRE(dctx->source == source);
	REQUIRE(name != NULL && name->magic == DNS_NAME_MAGIC);
	REQUIRE((target != NULL && ISC_BUFFER_VALID(target)) ||
		(target == NULL && ISC_BUFFER_VALID(name->buffer)));

	if (target == NULL && name->buffer != NULL) {
		target = name->buffer;
		isc_buffer_clear(target);
	}

	/* in case of failure */
	name->ndata = NULL;
	name->length = 0;
	name->labels = 0;
	name->attributes.absolute = false;

	uint8_t *const name_buf = isc_buffer_used(target);
	const uint32_t name_max = ISC_MIN(DNS_NAME_MAXWIRE,
					  isc_buffer_availablelength(target));
	dns_offsets_t odata;
	uint8_t *offsets = name->offsets != NULL ? name->offsets : odata;
	uint32_t name_len = 0;
	uint32_t labels = 0;

	/*
	 * After chasing a compression pointer, these variables refer to the
	 * source buffer as follows:
	 *
	 * sb --- mr --- cr --- st --- cd --- sm
	 *
	 * sb = source_buf (const)
	 * mr = marker
	 * cr = cursor
	 * st = start (const)
	 * cd = consumed
	 * sm = source_max (const)
	 *
	 * The marker jumps left for each pointer.
	 * The cursor steps right for each label.
	 * The amount of the source we consumed is set once.
	 */
	const uint8_t *const source_buf = isc_buffer_base(source);
	const uint8_t *const source_max = isc_buffer_used(source);
	const uint8_t *const start = isc_buffer_current(source);
	const uint8_t *marker = start;
	const uint8_t *cursor = start;
	const uint8_t *consumed = NULL;

	/*
	 * One iteration per label.
	 */
	while (cursor < source_max) {
		const uint8_t label_len = *cursor++;
		if (DNS_LABEL_ISNORMAL(label_len)) {
			/*
			 * Normal label: record its offset, and check bounds on
			 * the name length, which also ensures we don't overrun
			 * the offsets array. Don't touch any source bytes yet!
			 * The source bounds check will happen when we loop.
			 */
			offsets[labels++] = name_len;
			/* and then a step to the ri-i-i-i-i-ight */
			cursor += label_len;
			name_len += label_len + 1;
			if (name_len > name_max) {
				return (name_max == DNS_NAME_MAXWIRE
						? DNS_R_NAMETOOLONG
						: ISC_R_NOSPACE);
			} else if (DNS_LABEL_ISROOT(label_len)) {
				goto root_label;
			}
		} else if (DNS_LABEL_INVALID(label_len)) {
			return (DNS_R_BADLABELTYPE);
		} else if (cursor < source_max) {
			/*
			 * Compression pointer. Ensure it does not loop.
			 *
			 * Copy multiple labels in one go, to make the most of
			 * memmove() performance. Start at the marker and finish
			 * just before the pointer's hi+lo bytes, before the
			 * cursor. Bounds were already checked.
			 */
			const uint8_t *pointer = source_buf;
			pointer += DNS_NAME_PTRTARGET(label_len, *cursor++);
			if (pointer >= marker) {
				return (DNS_R_BADPOINTER);
			}
			const uint32_t copy_len = (cursor - 2) - marker;
			uint8_t *const dest = name_buf + name_len - copy_len;
			memmove(dest, marker, copy_len);
			consumed = consumed != NULL ? consumed : cursor;
			/* it's just a jump to the left */
			cursor = marker = pointer;
		}
	}
	return (ISC_R_UNEXPECTEDEND);

root_label:;
	/*
	 * Copy labels almost like we do for compression pointers,
	 * from the marker up to and including the root label.
	 */
	const uint32_t copy_len = cursor - marker;
	memmove(name_buf + name_len - copy_len, marker, copy_len);
	consumed = consumed != NULL ? consumed : cursor;
	isc_buffer_forward(source, consumed - start);

	name->attributes.absolute = true;
	name->ndata = name_buf;
	name->labels = labels;
	name->length = name_len;
	isc_buffer_add(target, name_len);

	return (ISC_R_SUCCESS);
}

#endif

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
#include <dns/name.h>

#define HASH_INIT_DJB2 5381

#define CCTX_MAGIC    ISC_MAGIC('C', 'C', 'T', 'X')
#define CCTX_VALID(x) ISC_MAGIC_VALID(x, CCTX_MAGIC)

void
dns_compress_init(dns_compress_t *cctx, isc_mem_t *mctx,
		  dns_compress_flags_t flags) {
	dns_compress_slot_t *set = NULL;
	uint16_t mask;

	REQUIRE(cctx != NULL);
	REQUIRE(mctx != NULL);

	if ((flags & DNS_COMPRESS_LARGE) != 0) {
		size_t count = (1 << DNS_COMPRESS_LARGEBITS);
		size_t size = count * sizeof(*set);
		mask = count - 1;
		set = isc_mem_allocatex(mctx, size, ISC_MEM_ZERO);
	} else {
		mask = ARRAY_SIZE(cctx->smallset) - 1;
		set = cctx->smallset;
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
	*cctx = (dns_compress_t){ 0 };
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

	hash = isc_hash_bits32(hash, 16);
	return (hash != 0 ? hash : HASH_INIT_DJB2);
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
 */
static bool
match_suffix(isc_buffer_t *buffer, uint16_t new_coff, uint8_t *sptr,
	     uint8_t slen, uint16_t old_coff, bool sensitive) {
	uint8_t llen = sptr[0] + 1;
	uint8_t pptr[] = { 0xC0 | (old_coff >> 8), old_coff & 0xff };
	uint8_t *bptr = isc_buffer_base(buffer);
	unsigned int blen = isc_buffer_usedlength(buffer);

	INSIST(llen <= 64 && llen < slen);

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

	/* is this label followed by a pointer to the previous match? */
	if (blen >= 2 && bptr[0] == pptr[0] && bptr[1] == pptr[1]) {
		return (true);
	}

	/* is this label followed by a copy of the rest of the suffix? */
	return (blen >= slen && match_wirename(bptr, sptr, slen, sensitive));
}

/*
 * Add the unmatched prefix of the name to the hash set.
 *
 * The insertion loop continues from the search loop inside
 * dns_compress_name() below, iterating over the remaining labels
 * of the name and accumulating the hash in the same manner.
 *
 * Hash set entries must have valid compression offsets and the
 * hash set must not get too full (75% load), so we stop if we
 * pass either of these thresholds.
 */
static void
insert(dns_compress_t *cctx, isc_buffer_t *buffer, const dns_name_t *name,
       uint8_t label, uint16_t hash, uint16_t slot) {
	bool sensitive = (cctx->flags & DNS_COMPRESS_CASE) != 0;
	uint8_t prefix_len = name->offsets[label];
	uint8_t *suffix_ptr;

	for (;;) {
		unsigned int coff = isc_buffer_usedlength(buffer) + prefix_len;
		if (coff >= 0x4000 || cctx->count > cctx->mask * 3 / 4) {
			return;
		}

		cctx->set[slot].hash = hash;
		cctx->set[slot].coff = coff;
		cctx->count++;

		if (label == 0) {
			return;
		}
		label--;

		prefix_len = name->offsets[label];
		suffix_ptr = name->ndata + prefix_len;
		hash = hash_label(hash, suffix_ptr, sensitive);

		for (slot = hash;; slot++) {
			slot &= cctx->mask;
			/* we can overwrite tombstones */
			if (cctx->set[slot].coff == 0) {
				/* continue outer loop, to insert here */
				break;
			}
		}
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
	uint8_t label = name->labels - 1; /* skip the root label */

	/*
	 * find out how much of the name's suffix is in the hash set,
	 * stepping backwards from the end one label at a time
	 */
	while (label-- > 0) {
		uint8_t prefix_len = name->offsets[label];
		uint8_t suffix_len = name->length - prefix_len;
		uint8_t *suffix_ptr = name->ndata + prefix_len;
		hash = hash_label(hash, suffix_ptr, sensitive);

		for (uint16_t slot = hash;; slot++) {
			slot &= cctx->mask;

			uint16_t coff = cctx->set[slot].coff;

			/*
			 * when we reach an empty non-tombstone slot,
			 * our suffix cannot be in the hash set, so stop
			 * searching and switch to inserting the rest of
			 * the name (its prefix) into the set
			 */
			if (coff == 0 && cctx->set[slot].hash == 0) {
				insert(cctx, buffer, name, label, hash, slot);
				return;
			}

			/*
			 * if this slot matches, provisionally set the
			 * return values and continue with the next
			 * label
			 */
			if (coff != 0 && cctx->set[slot].hash == hash &&
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

	for (uint16_t slot = 0; slot <= cctx->mask; slot++) {
		if (cctx->set[slot].coff >= coff) {
			/* tombstone: coff == 0 && hash != 0 */
			cctx->set[slot].coff = 0;
		}
	}
}

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

/*
 * This is an implementation of the original Robin Hood hash table algorithm as
 * described in Robin Hood Hashing [a].
 *
 * Further work:
 * 1. Implement 4.1 Speeding up Searches - 4.4 Smart Search
 * 2. Implement A Fast Concurrent and Resizable Robin Hood Hash Table [b]
 *
 * a. https://cs.uwaterloo.ca/research/tr/1986/CS-86-14.pdf paper.
 * b. https://dspace.mit.edu/bitstream/handle/1721.1/130693/1251799942-MIT.pdf
 */

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/siphash.h>
#include <isc/types.h>
#include <isc/util.h>

#define APPROX_99_PERCENT(x) (((x)*1013) >> 10)
#define APPROX_95_PERCENT(x) (((x)*972) >> 10)
#define APPROX_90_PERCENT(x) (((x)*921) >> 10)
#define APPROX_85_PERCENT(x) (((x)*870) >> 10)
#define APPROX_40_PERCENT(x) (((x)*409) >> 10)
#define APPROX_35_PERCENT(x) (((x)*359) >> 10)
#define APPROX_30_PERCENT(x) (((x)*308) >> 10)
#define APPROX_25_PERCENT(x) (((x)*256) >> 10)
#define APPROX_20_PERCENT(x) (((x)*205) >> 10)
#define APPROX_15_PERCENT(x) (((x)*154) >> 10)
#define APPROX_10_PERCENT(x) (((x)*103) >> 10)
#define APPROX_05_PERCENT(x) (((x)*52) >> 10)
#define APPROX_01_PERCENT(x) (((x)*11) >> 10)

#define ISC_HASHMAP_MAGIC	   ISC_MAGIC('H', 'M', 'a', 'p')
#define ISC_HASHMAP_VALID(hashmap) ISC_MAGIC_VALID(hashmap, ISC_HASHMAP_MAGIC)

#define HASHSIZE(bits) (UINT64_C(1) << (bits))

#define HASHMAP_NO_BITS	 0U
#define HASHMAP_MIN_BITS 1U
#define HASHMAP_MAX_BITS 32U

#define HASHMAP_TABLESIZE(size) ((size) * sizeof(isc_hashmap_node_t *))

static isc_result_t
hashmap_add(isc_hashmap_t *hashmap, isc_hashmap_node_t *entry,
	    const uint32_t hashval, const uint8_t *key, const uint32_t keysize,
	    void *value, uint8_t idx);

static void
hashmap_rehash_one(isc_hashmap_t *hashmap);
static void
hashmap_rehash_start_grow(isc_hashmap_t *hashmap);
static void
hashmap_rehash_start_shrink(isc_hashmap_t *hashmap);
static bool
over_threshold(isc_hashmap_t *hashmap);
static bool
under_threshold(isc_hashmap_t *hashmap);

struct isc_hashmap {
	unsigned int magic;
	bool case_sensitive;
	uint8_t hindex;
	uint32_t hiter; /* rehashing iterator */
	isc_mem_t *mctx;
	size_t count;
	uint8_t hash_key[16];
	size_t size[2];
	uint8_t hashbits[2];
	uint32_t hashmask[2];
	isc_hashmap_node_t **table[2];
};

struct isc_hashmap_iter {
	isc_hashmap_t *hashmap;
	size_t i;
	uint8_t hindex;
	isc_hashmap_node_t *cur;
};

static uint8_t
hashmap_nexttable(uint8_t idx) {
	return ((idx == 0) ? 1 : 0);
}

static bool
rehashing_in_progress(const isc_hashmap_t *hashmap) {
	return (hashmap->table[hashmap_nexttable(hashmap->hindex)] != NULL);
}

static bool
try_nexttable(const isc_hashmap_t *hashmap, uint8_t idx) {
	return (idx == hashmap->hindex && rehashing_in_progress(hashmap));
}

static void
hashmap_node_init(isc_hashmap_node_t *node, const uint32_t hashval,
		  const uint8_t *key, const uint32_t keysize, void *value) {
	REQUIRE(key != NULL && keysize > 0 && keysize <= UINT16_MAX);

	*node = (isc_hashmap_node_t){
		.value = value,
		.hashval = hashval,
		.key = key,
		.keysize = keysize,
		.psl = 0,
	};
}

static void
hashmap_node_clear(isc_hashmap_node_t *node) {
	*node = (isc_hashmap_node_t){ 0 };
}

static void __attribute__((__unused__))
hashmap_dump_table(const isc_hashmap_t *hashmap, const uint8_t idx) {
	fprintf(stderr,
		"====== %" PRIu8 " (bits = %" PRIu8 ", size = %zu =====\n", idx,
		hashmap->hashbits[idx], hashmap->size[idx]);
	for (size_t i = 0; i < hashmap->size[idx]; i++) {
		isc_hashmap_node_t *node = hashmap->table[idx][i];
		if (node != NULL) {
			uint32_t hash = isc_hash_bits32(node->hashval,
							hashmap->hashbits[idx]);
			fprintf(stderr,
				"%zu -> %p"
				", value = %p"
				", hash = %" PRIu32 ", hashval = %" PRIu32
				", psl = %" PRIu32 ", key = %s\n",
				i, node, node->value, hash, node->hashval,
				node->psl, (char *)node->key);
		}
	}
	fprintf(stderr, "================\n\n");
}

static void
hashmap_create_table(isc_hashmap_t *hashmap, const uint8_t idx,
		     const uint8_t bits) {
	size_t size;

	REQUIRE(hashmap->hashbits[idx] == HASHMAP_NO_BITS);
	REQUIRE(hashmap->table[idx] == NULL);
	REQUIRE(bits >= HASHMAP_MIN_BITS);
	REQUIRE(bits < HASHMAP_MAX_BITS);

	hashmap->hashbits[idx] = bits;
	hashmap->hashmask[idx] = HASHSIZE(bits) - 1;
	hashmap->size[idx] = HASHSIZE(bits);

	size = hashmap->size[idx] * sizeof(isc_hashmap_node_t *);

	hashmap->table[idx] = isc_mem_get(hashmap->mctx, size);
	memset(hashmap->table[idx], 0, size);
}

static void
hashmap_free_table(isc_hashmap_t *hashmap, const uint8_t idx, bool cleanup) {
	size_t size;

	if (cleanup) {
		for (size_t i = 0; i < hashmap->size[idx]; i++) {
			isc_hashmap_node_t *node = hashmap->table[idx][i];
			hashmap->table[idx][i] = NULL;
			if (node != NULL) {
				hashmap_node_clear(node);
				hashmap->count--;
			}
		}
	}

	size = hashmap->size[idx] * sizeof(isc_hashmap_node_t *);
	isc_mem_put(hashmap->mctx, hashmap->table[idx], size);

	hashmap->size[idx] = 0;
	hashmap->hashbits[idx] = HASHMAP_NO_BITS;
	hashmap->table[idx] = NULL;
}

void
isc_hashmap_create(isc_mem_t *mctx, uint8_t bits, unsigned int options,
		   isc_hashmap_t **hashmapp) {
	isc_hashmap_t *hashmap = isc_mem_get(mctx, sizeof(*hashmap));
	bool case_sensitive = ((options & ISC_HASHMAP_CASE_INSENSITIVE) == 0);

	REQUIRE(hashmapp != NULL && *hashmapp == NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(bits >= HASHMAP_MIN_BITS && bits < HASHMAP_MAX_BITS);

	*hashmap = (isc_hashmap_t){
		.magic = ISC_HASHMAP_MAGIC,
		.hash_key = { 0, 1 },
		.case_sensitive = case_sensitive,
	};
	isc_mem_attach(mctx, &hashmap->mctx);

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(UNIT_TESTING)
	isc_entropy_get(hashmap->hash_key, sizeof(hashmap->hash_key));
#endif /* if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

	hashmap_create_table(hashmap, 0, bits);

	hashmap->magic = ISC_HASHMAP_MAGIC;

	*hashmapp = hashmap;
}

void
isc_hashmap_destroy(isc_hashmap_t **hashmapp) {
	isc_hashmap_t *hashmap;

	REQUIRE(hashmapp != NULL && *hashmapp != NULL);
	REQUIRE(ISC_HASHMAP_VALID(*hashmapp));

	hashmap = *hashmapp;
	*hashmapp = NULL;

	hashmap->magic = 0;

	for (size_t i = 0; i <= 1; i++) {
		if (hashmap->table[i] != NULL) {
			hashmap_free_table(hashmap, i, true);
		}
	}
	INSIST(hashmap->count == 0);

	isc_mem_putanddetach(&hashmap->mctx, hashmap, sizeof(*hashmap));
}

#define isc_ascii_equal(a, b, len) (memcmp(node->key, key, keysize) == 0)

static bool
hashmap_match(isc_hashmap_node_t *node, const uint32_t hashval,
	      const uint8_t *key, const uint32_t keysize,
	      const bool case_sensitive) {
	return (node->hashval == hashval && node->keysize == keysize &&
		(case_sensitive
			 ? (isc_ascii_equal(node->key, key, keysize))
			 : (isc_ascii_lowerequal(node->key, key, keysize))));
}

static isc_hashmap_node_t **
hashmap_find(const isc_hashmap_t *hashmap, const uint32_t hashval,
	     const uint8_t *key, uint32_t keysize, uint32_t *pslp,
	     uint8_t *idxp) {
	uint32_t hash;
	uint32_t psl;
	uint8_t idx = *idxp;
	uint32_t pos;

nexttable:
	psl = 0;
	hash = isc_hash_bits32(hashval, hashmap->hashbits[idx]);

	while (true) {
		isc_hashmap_node_t **nodep = NULL;

		pos = (hash + psl) & hashmap->hashmask[idx];

		nodep = &hashmap->table[idx][pos];

		if (*nodep == NULL || psl > (*nodep)->psl) {
			break;
		}

		if (hashmap_match(*nodep, hashval, key, keysize,
				  hashmap->case_sensitive)) {
			*pslp = psl;
			*idxp = idx;
			return (nodep);
		}

		psl++;
	}
	if (try_nexttable(hashmap, idx)) {
		idx = hashmap_nexttable(idx);
		goto nexttable;
	}

	return (NULL);
}

isc_result_t
isc_hashmap_find(const isc_hashmap_t *hashmap, const uint8_t *key,
		 uint32_t keysize, void **valuep) {
	uint32_t hashval;
	isc_hashmap_node_t **nodep;
	uint8_t idx;
	uint32_t psl;

	REQUIRE(ISC_HASHMAP_VALID(hashmap));
	REQUIRE(key != NULL && keysize > 0 && keysize <= UINT16_MAX);

	idx = hashmap->hindex;

	isc_halfsiphash24(hashmap->hash_key, key, keysize,
			  hashmap->case_sensitive, (uint8_t *)&hashval);

	nodep = hashmap_find(hashmap, hashval, key, keysize, &psl, &idx);
	if (nodep == NULL) {
		return (ISC_R_NOTFOUND);
	}

	INSIST(*nodep != NULL);
	if (valuep != NULL) {
		*valuep = (*nodep)->value;
	}
	return (ISC_R_SUCCESS);
}

static void
hashmap_clear_node(isc_hashmap_t *hashmap, isc_hashmap_node_t **nodep,
		   uint32_t hashval, uint32_t psl, const uint8_t idx) {
	uint32_t pos;
	uint32_t hash;

	hashmap->count--;

	hash = isc_hash_bits32(hashval, hashmap->hashbits[idx]);
	pos = hash + psl;

	while (true) {
		isc_hashmap_node_t *node = NULL;

		pos = (pos + 1) & hashmap->hashmask[idx];

		REQUIRE(pos < hashmap->size[idx]);

		node = hashmap->table[idx][pos];

		if (node == NULL || node->psl == 0) {
			break;
		}

		node->psl--;
		*nodep = node;
		nodep = &hashmap->table[idx][pos];
	}

	*nodep = NULL;
}

static void
hashmap_delete_node(isc_hashmap_t *hashmap, isc_hashmap_node_t **nodep,
		    uint32_t hashval, uint32_t psl, const uint8_t idx) {
	REQUIRE(nodep != NULL && *nodep != NULL);

	hashmap_node_clear(*nodep);
	hashmap_clear_node(hashmap, nodep, hashval, psl, idx);
}

static void
hashmap_rehash_one(isc_hashmap_t *hashmap) {
	uint32_t oldsize = hashmap->size[hashmap_nexttable(hashmap->hindex)];
	isc_hashmap_node_t **oldtable =
		hashmap->table[hashmap_nexttable(hashmap->hindex)];
	isc_hashmap_node_t *node;
	isc_result_t result;

	/* Find first non-empty node */
	while (hashmap->hiter < oldsize && oldtable[hashmap->hiter] == NULL) {
		hashmap->hiter++;
	}

	/* Rehashing complete */
	if (hashmap->hiter == oldsize) {
		hashmap_free_table(hashmap, hashmap_nexttable(hashmap->hindex),
				   false);
		hashmap->hiter = 0;
		return;
	}

	/* Move the first non-empty node from old table to new table */
	node = oldtable[hashmap->hiter];

	hashmap_clear_node(hashmap, &oldtable[hashmap->hiter], node->hashval,
			   node->psl, hashmap_nexttable(hashmap->hindex));

	result = hashmap_add(hashmap, node, node->hashval, node->key,
			     node->keysize, node->value, hashmap->hindex);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * don't increase the hiter because the table has been reordeder with
	 * hashmap_clear_node
	 */
	/* hashmap->hiter++; */
}

static uint32_t
grow_bits(isc_hashmap_t *hashmap) {
	uint32_t newbits = hashmap->hashbits[hashmap->hindex] + 1;
	size_t newsize = HASHSIZE(newbits);

	while (hashmap->count > APPROX_40_PERCENT(newsize)) {
		newbits += 1;
		newsize = HASHSIZE(newbits);
	}
	if (newbits >= HASHMAP_MAX_BITS) {
		newbits = HASHMAP_MAX_BITS - 1;
	}

	return (newbits);
}

static uint32_t
shrink_bits(isc_hashmap_t *hashmap) {
	uint32_t newbits = hashmap->hashbits[hashmap->hindex] - 1;

	if (newbits <= HASHMAP_MIN_BITS) {
		newbits = HASHMAP_MIN_BITS;
	}

	return (newbits);
}

static void
hashmap_rehash_start_grow(isc_hashmap_t *hashmap) {
	uint32_t newbits;
	uint8_t oldindex = hashmap->hindex;
	uint32_t oldbits = hashmap->hashbits[oldindex];
	uint8_t newindex = hashmap_nexttable(oldindex);

	REQUIRE(!rehashing_in_progress(hashmap));

	newbits = grow_bits(hashmap);

	if (newbits > oldbits) {
		hashmap_create_table(hashmap, newindex, newbits);
		hashmap->hindex = newindex;
	}
}

static void
hashmap_rehash_start_shrink(isc_hashmap_t *hashmap) {
	uint32_t newbits;
	uint8_t oldindex = hashmap->hindex;
	uint32_t oldbits = hashmap->hashbits[oldindex];
	uint8_t newindex = hashmap_nexttable(oldindex);

	REQUIRE(!rehashing_in_progress(hashmap));

	newbits = shrink_bits(hashmap);

	if (newbits < oldbits) {
		hashmap_create_table(hashmap, newindex, newbits);
		hashmap->hindex = newindex;
	}
}

isc_result_t
isc_hashmap_delete(isc_hashmap_t *hashmap, const uint8_t *key,
		   uint32_t keysize) {
	uint32_t hashval;
	isc_hashmap_node_t **nodep;
	uint8_t idx;
	uint32_t psl;

	REQUIRE(ISC_HASHMAP_VALID(hashmap));
	REQUIRE(key != NULL && keysize > 0 && keysize <= UINT16_MAX);

	idx = hashmap->hindex;

	if (rehashing_in_progress(hashmap)) {
		hashmap_rehash_one(hashmap);
	} else if (under_threshold(hashmap)) {
		hashmap_rehash_start_shrink(hashmap);
		hashmap_rehash_one(hashmap);
	}

	isc_halfsiphash24(hashmap->hash_key, key, keysize,
			  hashmap->case_sensitive, (uint8_t *)&hashval);

	nodep = hashmap_find(hashmap, hashval, key, keysize, &psl, &idx);
	if (nodep != NULL) {
		INSIST(*nodep != NULL);
		hashmap_delete_node(hashmap, nodep, hashval, psl, idx);
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_NOTFOUND);
}

static bool
over_threshold(isc_hashmap_t *hashmap) {
	uint32_t bits = hashmap->hashbits[hashmap->hindex];
	if (bits == HASHMAP_MAX_BITS) {
		return (false);
	}
	size_t threshold = APPROX_90_PERCENT(HASHSIZE(bits));
	return (hashmap->count > threshold);
}

static bool
under_threshold(isc_hashmap_t *hashmap) {
	uint32_t bits = hashmap->hashbits[hashmap->hindex];
	if (bits == HASHMAP_MIN_BITS) {
		return (false);
	}
	size_t threshold = APPROX_20_PERCENT(HASHSIZE(bits));
	return (hashmap->count < threshold);
}

static isc_result_t
hashmap_add(isc_hashmap_t *hashmap, isc_hashmap_node_t *entry,
	    const uint32_t hashval, const uint8_t *key, const uint32_t keysize,
	    void *value, uint8_t idx) {
	uint32_t hash;
	uint32_t psl = 0;
	isc_hashmap_node_t node;
	isc_hashmap_node_t *current = NULL;
	uint32_t pos;

	hash = isc_hash_bits32(hashval, hashmap->hashbits[idx]);

	hashmap_node_init(&node, hashval, key, keysize, value);

	psl = 0;
	while (true) {
		pos = (hash + psl) & hashmap->hashmask[idx];

		current = hashmap->table[idx][pos];

		/* Found empty node */
		if (current == NULL) {
			break;
		}

		if (hashmap_match(current, hashval, key, keysize,
				  hashmap->case_sensitive)) {
			return (ISC_R_EXISTS);
		}
		/* Found rich node */
		if (node.psl > current->psl) {
			/* Swap the poor with the rich node */

			/* Store entry into current node */
			*entry = node;
			hashmap->table[idx][pos] = entry;

			/* Copy the old node to tmp */
			entry = current;
			node = *entry;
		}

		node.psl++;
		psl++;

		/* The safety break, so we don't loop forever on error */
		INSIST(psl < hashmap->size[idx]);
	}

	/*
	 * Possible optimalization - start growing when the poor node is too far
	 */
#if 0
	if (psl > hashmap->hashbits[idx]) {
		if (!rehashing_in_progress(hashmap)) {
			hashmap_rehash_start_grow(hashmap);
		}
	}
#endif

	hashmap->count++;

	/* We found an empty place, store entry into current node */
	*entry = node;
	hashmap->table[idx][pos] = entry;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_hashmap_add(isc_hashmap_t *hashmap, const uint8_t *key, uint32_t keysize,
		void *value, uint16_t offset) {
	uint32_t hashval;
	isc_result_t result;
	isc_hashmap_node_t *node;

	REQUIRE(ISC_HASHMAP_VALID(hashmap));

	isc_halfsiphash24(hashmap->hash_key, key, keysize,
			  hashmap->case_sensitive, (uint8_t *)&hashval);

	if (rehashing_in_progress(hashmap)) {
		hashmap_rehash_one(hashmap);
	} else if (over_threshold(hashmap)) {
		hashmap_rehash_start_grow(hashmap);
		hashmap_rehash_one(hashmap);
	}

	if (rehashing_in_progress(hashmap)) {
		uint8_t fidx = hashmap_nexttable(hashmap->hindex);
		uint32_t psl;

		/* Look for the value in the old table */
		if (hashmap_find(hashmap, hashval, key, keysize, &psl, &fidx)) {
			return (ISC_R_EXISTS);
		}
	}

	node = (isc_hashmap_node_t *)(((uint8_t *)value) + offset);

	result = hashmap_add(hashmap, node, hashval, key, keysize, value,
			     hashmap->hindex);
	switch (result) {
	case ISC_R_SUCCESS:
		return (ISC_R_SUCCESS);
	case ISC_R_EXISTS:
		return (ISC_R_EXISTS);
	default:
		UNREACHABLE();
	}
}

void
isc_hashmap_iter_create(isc_hashmap_t *hashmap, isc_hashmap_iter_t **iterp) {
	isc_hashmap_iter_t *iter;

	REQUIRE(ISC_HASHMAP_VALID(hashmap));
	REQUIRE(iterp != NULL && *iterp == NULL);

	iter = isc_mem_get(hashmap->mctx, sizeof(*iter));
	*iter = (isc_hashmap_iter_t){
		.hashmap = hashmap,
		.hindex = hashmap->hindex,
	};

	*iterp = iter;
}

void
isc_hashmap_iter_destroy(isc_hashmap_iter_t **iterp) {
	isc_hashmap_iter_t *iter;
	isc_hashmap_t *hashmap;

	REQUIRE(iterp != NULL && *iterp != NULL);

	iter = *iterp;
	*iterp = NULL;
	hashmap = iter->hashmap;
	isc_mem_put(hashmap->mctx, iter, sizeof(*iter));
}

static isc_result_t
isc__hashmap_iter_next(isc_hashmap_iter_t *iter) {
	isc_hashmap_t *hashmap = iter->hashmap;

	while (iter->i < hashmap->size[iter->hindex] &&
	       hashmap->table[iter->hindex][iter->i] == NULL)
	{
		iter->i++;
	}

	if (iter->i < hashmap->size[iter->hindex]) {
		iter->cur = hashmap->table[iter->hindex][iter->i];

		return (ISC_R_SUCCESS);
	}

	if (try_nexttable(hashmap, iter->hindex)) {
		iter->hindex = hashmap_nexttable(iter->hindex);
		iter->i = 0;
		return (isc__hashmap_iter_next(iter));
	}

	return (ISC_R_NOMORE);
}

isc_result_t
isc_hashmap_iter_first(isc_hashmap_iter_t *iter) {
	REQUIRE(iter != NULL);

	iter->hindex = iter->hashmap->hindex;
	iter->i = 0;

	return (isc__hashmap_iter_next(iter));
}

isc_result_t
isc_hashmap_iter_next(isc_hashmap_iter_t *iter) {
	REQUIRE(iter != NULL);
	REQUIRE(iter->cur != NULL);

	iter->i++;

	return (isc__hashmap_iter_next(iter));
}

isc_result_t
isc_hashmap_iter_delcurrent_next(isc_hashmap_iter_t *iter) {
	REQUIRE(iter != NULL);
	REQUIRE(iter->cur != NULL);

	isc_hashmap_node_t **nodep =
		&iter->hashmap->table[iter->hindex][iter->i];

	hashmap_delete_node(iter->hashmap, nodep, (*nodep)->hashval,
			    (*nodep)->psl, iter->hindex);

	return (isc__hashmap_iter_next(iter));
}

void
isc_hashmap_iter_current(isc_hashmap_iter_t *it, void **valuep) {
	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);
	REQUIRE(valuep != NULL && *valuep == NULL);

	*valuep = it->cur->value;
}

void
isc_hashmap_iter_currentkey(isc_hashmap_iter_t *it, const unsigned char **key,
			    size_t *keysize) {
	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);
	REQUIRE(key != NULL && *key == NULL);

	*key = it->cur->key;
	*keysize = it->cur->keysize;
}

unsigned int
isc_hashmap_count(isc_hashmap_t *hashmap) {
	REQUIRE(ISC_HASHMAP_VALID(hashmap));

	return (hashmap->count);
}

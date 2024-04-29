#include <inttypes.h>
#include <stdint.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/rwlock.h>
#include <isc/skiplist.h>
#include <isc/util.h>

#define ISC_SKIPLIST_MAGIC ISC_MAGIC('S', 'k', 'i', 'p')
#define SKIPLIST_VALID(s)  ISC_MAGIC_VALID(s, ISC_SKIPLIST_MAGIC)

#define MAX_LEVEL   32
#define MAX_INDEX   (MAX_LEVEL - 1)
#define MAX_SEGMENT 16777215

STATIC_ASSERT(sizeof(void *) <= sizeof(uint64_t),
	      "pointers must fit in 64 bits");

typedef struct skiplist_node skiplist_node_t;

struct skiplist_node {
	uint32_t level;
	uint32_t key;

	uint32_t value_size;
	uint32_t segments;

	uint32_t *cursors;
	uint64_t **values;

	skiplist_node_t *nodes[];
};

struct isc_skiplist {
	uint32_t magic;
	isc_mem_t *mctx;
	isc_skiplist_key_fn_t key_fn;
	skiplist_node_t *head;
};

static skiplist_node_t *
node_create_raw(isc_mem_t *mctx, uint32_t key) {
	skiplist_node_t *node;
	uint32_t level;

	STATIC_ASSERT(MAX_LEVEL == 32, "fix 0x1f masking in level generation");

	level = (isc_random32() & 0x1f) + 1;

	node = isc_mem_get(mctx, STRUCT_FLEX_SIZE(node, nodes, level));
	*node = (skiplist_node_t){
		.level = level,
		.key = key,

		.segments = 1,
	};

	node->cursors = isc_mem_get(mctx, 1 * sizeof(uint32_t));
	node->cursors[0] = 0;

	node->values = isc_mem_get(mctx, 1 * sizeof(uint64_t *));
	node->values[0] = isc_mem_get(mctx, 1 * sizeof(uint64_t));

	return node;
}

static void
node_destroy(isc_mem_t *mctx, skiplist_node_t *node) {
	isc_mem_put(mctx, node->cursors, node->segments * sizeof(uint32_t));

	for (size_t i = 0; i < node->segments; i++) {
		isc_mem_put(mctx, node->values[i], (1 << i) * sizeof(uint64_t));
	}

	isc_mem_put(mctx, node->values, node->segments * sizeof(uint64_t *));

	isc_mem_put(mctx, node, STRUCT_FLEX_SIZE(node, nodes, node->level));
}

static uint32_t
insert_value(isc_mem_t *mctx, skiplist_node_t *node, void *value) {
	uint32_t hi, lo;

	node->value_size++;

	for (lo = 0; lo < node->segments - 1; lo++) {
		if (node->cursors[lo] < (1 << lo)) {
			hi = node->cursors[lo];
			node->values[lo][hi] = (uint64_t)((uintptr_t)value);

			node->cursors[lo] = (1 << lo);

			return (lo | (hi << 8));
		}
	}

	/* unroll last iteration for special case */
	if (node->cursors[lo] < (1 << lo)) {
		hi = node->cursors[lo];
		node->cursors[lo]++;

		node->values[lo][hi] = (uint64_t)((uintptr_t)value);

		return (lo | (hi << 8));
	}

	lo++;

	INSIST(lo == node->segments);

	node->cursors = isc_mem_reget(
		mctx, node->cursors, ISC_CHECKED_MUL(lo, sizeof(uint32_t)),
		ISC_CHECKED_MUL(lo + 1, sizeof(uint32_t)));

	node->cursors[lo] = 1;

	node->values = isc_mem_reget(
		mctx, node->values, ISC_CHECKED_MUL(lo, sizeof(uint64_t *)),
		ISC_CHECKED_MUL(lo + 1, sizeof(uint64_t *)));

	node->values[lo] = isc_mem_get(mctx, (1 << lo) * sizeof(uint64_t));
	node->values[lo][0] = (uint64_t)((uintptr_t)value);

	node->segments = lo + 1;

	return lo;
}

void
isc_skiplist_create(isc_mem_t *mctx, isc_skiplist_key_fn_t key_fn,
		    isc_skiplist_t **slistp) {
	isc_skiplist_t *slist;
	skiplist_node_t *node;

	REQUIRE(slistp != NULL);
	REQUIRE(*slistp == NULL);

	node = isc_mem_get(mctx, STRUCT_FLEX_SIZE(node, nodes, MAX_LEVEL));
	*node = (skiplist_node_t){
		.level = MAX_LEVEL,
		.key = UINT32_MAX,
		.value_size = UINT32_MAX,
	};

	for (size_t i = 0; i < node->level; i++) {
		node->nodes[i] = node;
	}

	slist = isc_mem_get(mctx, sizeof(*slist));
	*slist = (isc_skiplist_t){
		.magic = ISC_SKIPLIST_MAGIC,
		.key_fn = key_fn,
		.head = node,
	};

	isc_mem_attach(mctx, &slist->mctx);

	*slistp = slist;
}

void
isc_skiplist_destroy(isc_skiplist_t **slistp) {
	skiplist_node_t *node, *next;
	isc_skiplist_t *slist;

	REQUIRE(slistp != NULL);
	REQUIRE(SKIPLIST_VALID(*slistp));

	slist = *slistp;
	*slistp = NULL;

	slist->magic = 0;

	node = slist->head->nodes[0];
	while (node != slist->head) {
		next = node->nodes[0];
		node_destroy(slist->mctx, node);
		node = next;
	}

	/* head doesn't have any data, so it's cleaned by hand */
	isc_mem_put(slist->mctx, node,
		    STRUCT_FLEX_SIZE(node, nodes, MAX_LEVEL));

	isc_mem_putanddetach(&slist->mctx, slist, sizeof(*slist));
}

uint32_t
isc_skiplist_insert(isc_skiplist_t *slist, void *value) {
	skiplist_node_t *updates[MAX_LEVEL];
	skiplist_node_t *node;
	uint32_t key;
	int32_t level;

	REQUIRE(SKIPLIST_VALID(slist));

	key = slist->key_fn(value);

	INSIST(key != UINT32_MAX);

	node = slist->head;
	for (level = MAX_INDEX; level >= 0; level--) {
		while (node->nodes[level]->key < key) {
			node = node->nodes[level];
		}

		if (node->nodes[level]->key == key) {
			return insert_value(slist->mctx, node->nodes[level],
					    value);
		}

		updates[level] = node;
	}

	node = node_create_raw(slist->mctx, key);

	for (uint32_t i = 0; i < node->level; i++) {
		node->nodes[i] = updates[i]->nodes[i];
		updates[i]->nodes[i] = node;
	}

	return insert_value(slist->mctx, node, value);
}

isc_result_t
isc_skiplist_delete(isc_skiplist_t *slist, void *value, uint32_t index) {
	skiplist_node_t *node;
	uint32_t hi, lo, key;
	int32_t level;

	REQUIRE(SKIPLIST_VALID(slist));

	key = slist->key_fn(value);

	INSIST(key != UINT32_MAX);

	node = slist->head;
	for (level = MAX_INDEX; level >= 0; level--) {
		while (node->nodes[level]->key < key) {
			node = node->nodes[level];
		}

		if (node->nodes[level]->key == key) {
			lo = index & 0xFF;
			hi = index >> 8;

			node->nodes[level]->value_size--;
			node->nodes[level]->values[lo][hi] = 0x00;

			if (lo != node->segments - 1) {
				node->nodes[level]->cursors[lo] = lo;
			}

			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}

size_t
isc_skiplist_poprange(isc_skiplist_t *slist, uint32_t range, size_t limit,
		      void *user, isc_skiplist_popaction_t action) {
	skiplist_node_t *updates[MAX_LEVEL];
	size_t processed, removed;
	skiplist_node_t *node;
	size_t i, j;
	void *value;

	REQUIRE(SKIPLIST_VALID(slist));

	if (limit == 0) {
		limit = SIZE_MAX;
	}

	memmove(updates, slist->head->nodes, sizeof(updates));

	removed = 0;
	processed = 0;

	node = slist->head->nodes[0];
	while (node->key < range) {
		for (i = 0; i < node->segments; i++) {
			for (j = 0; j < node->cursors[i]; j++) {
				value = (void *)((uintptr_t)node->values[i][j]);

				if (value != NULL) {
					if ((action)(user, value, range)) {
						node->values[i][j] = 0x00;
						node->value_size--;
						removed++;
					}

					processed++;
					if (processed >= limit) {
						goto out;
					}
				}
			}
		}

		if (node->value_size != 0) {
			node = node->nodes[0];
		} else {
			value = node->nodes[0];
			memmove(updates, node->nodes,
				node->level * sizeof(skiplist_node_t *));
			node_destroy(slist->mctx, node);
			node = value;
		}
	}

out:
	if (node->value_size == 0) {
		memmove(updates, node->nodes,
			node->level * sizeof(skiplist_node_t *));
		node_destroy(slist->mctx, node);
	}

	memmove(slist->head->nodes, updates, sizeof(updates));

	return removed;
}

#include <inttypes.h>
#include <stdint.h>

#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/rwlock.h>
#include <isc/skiplist.h>
#include <isc/util.h>

#define ISC_SKIPLIST_MAGIC ISC_MAGIC('S', 'k', 'i', 'p')
#define SKIPLIST_VALID(s)  ISC_MAGIC_VALID(s, ISC_SKIPLIST_MAGIC)

#define MAX_LEVEL 32
#define MAX_INDEX (MAX_LEVEL - 1)

#define SEGMENT_SATURATED_INDEX 26
#define SEGMENT_SATURATED_SIZE	(32U << 26)

#define UNSATURATED_INDEX(x) ISC_MIN(26, x)

STATIC_ASSERT(sizeof(void *) <= sizeof(uint64_t),
	      "pointers must fit in 64 bits");

typedef struct skiplist_node skiplist_node_t;
typedef struct skiplist_entry skiplist_entry_t;
typedef ISC_LIST(skiplist_entry_t) skiplist_entrylist_t;

struct skiplist_entry {
	void *value;
	ISC_LINK(skiplist_entry_t) link;
};

struct skiplist_node {
	uint32_t level;
	uint32_t key;

	uint64_t count;

	skiplist_entrylist_t entries;

	skiplist_node_t *nodes[];
};

struct isc_skiplist {
	uint32_t magic;
	isc_mem_t *mctx;
	isc_skiplist_key_fn_t key_fn;

	uint64_t entry_chunk_span;
	uint32_t *cursors;
	skiplist_entry_t **entries;

	skiplist_entrylist_t frees;

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
		.entries = ISC_LIST_INITIALIZER,
	};

	return (node);
}

static uint64_t
insert_value(isc_skiplist_t *slist, skiplist_node_t *node, void *value) {
	skiplist_entry_t *entry;
	uint32_t cursor;
	size_t i;

	if (!ISC_LIST_EMPTY(slist->frees)) {
		fprintf(stderr, "===================== FREE!\n");
		entry = ISC_LIST_HEAD(slist->frees);
		ISC_LIST_UNLINK(slist->frees, entry, link);
		goto found;
	}

	for (i = 0; i < UNSATURATED_INDEX(slist->entry_chunk_span - 1); i++) {
		cursor = slist->cursors[i];
		if (cursor < (32U << i)) {
			fprintf(stderr, "======== EARLY %zu, %u\n", i, cursor);
			slist->cursors[i] = 32U << i;
			entry = &slist->entries[i][cursor];
			goto found;
		}
	}

	for (; i < slist->entry_chunk_span - 1; i++) {
		cursor = slist->cursors[i];
		if (cursor < SEGMENT_SATURATED_SIZE) {
			fprintf(stderr, "======== SATURATED %zu, %u\n", i,
				cursor);
			slist->cursors[i] = SEGMENT_SATURATED_SIZE;
			entry = &slist->entries[i][cursor];
			goto found;
		}
	}

	INSIST(i == slist->entry_chunk_span - 1);

	cursor = slist->cursors[i];
	if (cursor < SEGMENT_SATURATED_SIZE) {
		fprintf(stderr, "======== CURSOR MOVE %zu,%u\n", i, cursor);
		slist->cursors[i]++;
		entry = &slist->entries[i][cursor];
		goto found;
	}

	i++;

	fprintf(stderr, "=================RESIZING TO %zu\n", i);

	slist->cursors = isc_mem_creget(slist->mctx, slist->cursors, i, i + 1,
					sizeof(uint32_t));

	slist->cursors[i] = 0;

	slist->entries = isc_mem_creget(slist->mctx, slist->entries, i, i + 1,
					sizeof(skiplist_entry_t *));

	slist->entries[i] = isc_mem_cget(slist->mctx, 32U << (i < 26 ? i : 26),
					 sizeof(skiplist_entry_t));

	slist->entry_chunk_span = i + 1;

	entry = &slist->entries[i][0];

found:
	*entry = (skiplist_entry_t){
		.value = value,
		.link = ISC_LINK_INITIALIZER,
	};

	ISC_LIST_APPEND(node->entries, entry, link);

	node->count++;

	fprintf(stderr, "\n>>>>>\ninsert,ttl:%u,value:%p,node:%p\n<<<<<\n\n",
		node->key, value, entry);

	return ((uint64_t)(uintptr_t)entry);
}

void
isc_skiplist_create(isc_mem_t *mctx, isc_skiplist_key_fn_t key_fn,
		    isc_skiplist_t **slistp) {
	skiplist_entry_t **entries;
	skiplist_node_t *node;
	isc_skiplist_t *slist;
	uint32_t *cursors;

	REQUIRE(slistp != NULL);
	REQUIRE(*slistp == NULL);

	node = isc_mem_get(mctx, STRUCT_FLEX_SIZE(node, nodes, MAX_LEVEL));
	*node = (skiplist_node_t){
		.level = MAX_LEVEL,
		.key = UINT32_MAX,
		.entries = ISC_LIST_INITIALIZER,
	};

	for (size_t i = 0; i < node->level; i++) {
		node->nodes[i] = node;
	}

	cursors = isc_mem_cget(mctx, 1, sizeof(uint32_t));
	cursors[0] = 0;

	entries = isc_mem_cget(mctx, 1, sizeof(skiplist_node_t *));
	entries[0] = isc_mem_cget(mctx, 32, sizeof(skiplist_node_t));

	slist = isc_mem_get(mctx, sizeof(*slist));
	*slist = (isc_skiplist_t){
		.magic = ISC_SKIPLIST_MAGIC,
		.key_fn = key_fn,
		.entry_chunk_span = 1,
		.cursors = cursors,
		.entries = entries,
		.frees = ISC_LIST_INITIALIZER,
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
		isc_mem_put(slist->mctx, node,
			    STRUCT_FLEX_SIZE(node, nodes, node->level));
		node = next;
	}

	isc_mem_put(slist->mctx, node,
		    STRUCT_FLEX_SIZE(node, nodes, MAX_LEVEL));

	isc_mem_cput(slist->mctx, slist->cursors, slist->entry_chunk_span,
		     sizeof(uint32_t));

	for (size_t i = 0; i < slist->entry_chunk_span; i++) {
		isc_mem_cput(slist->mctx, slist->entries[i],
			     32U << (i < 26 ? i : 26),
			     sizeof(skiplist_entry_t));
	}

	isc_mem_cput(slist->mctx, slist->entries, slist->entry_chunk_span,
		     sizeof(skiplist_entry_t *));

	isc_mem_putanddetach(&slist->mctx, slist, sizeof(*slist));
}

uint64_t
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
			return (insert_value(slist, node->nodes[level], value));
		}

		updates[level] = node;
	}

	node = node_create_raw(slist->mctx, key);

	for (uint32_t i = 0; i < node->level; i++) {
		node->nodes[i] = updates[i]->nodes[i];
		updates[i]->nodes[i] = node;
	}

	return (insert_value(slist, node, value));
}

isc_result_t
isc_skiplist_delete(isc_skiplist_t *slist, void *value, uint64_t index) {
	skiplist_entry_t *entry;
	skiplist_node_t *node;
	uint32_t key;
	int32_t level;

	REQUIRE(SKIPLIST_VALID(slist));
	REQUIRE(index != 0 && index != UINT32_MAX);

	key = slist->key_fn(value);

	INSIST(key != UINT32_MAX);

	entry = (void *)((uintptr_t)index);

	node = slist->head;
	for (level = MAX_INDEX; level >= 0; level--) {
		while (node->nodes[level]->key < key) {
			node = node->nodes[level];
		}

		if (node->nodes[level]->key == key) {
			fprintf(stderr, ">>>>> del,ttl:%u,node:%p ...", key,
				node);
			INSIST(node->nodes[level]->count > 0);
			INSIST(entry->value == value);
			node->nodes[level]->count--;
			ISC_LIST_UNLINK(node->nodes[level]->entries, entry,
					link);
			*entry = (skiplist_entry_t){
				.value = NULL,
				.link = ISC_LINK_INITIALIZER,
			};
			ISC_LIST_APPEND(slist->frees, entry, link);
			fprintf(stderr, "ok\n");
			return (ISC_R_SUCCESS);
		}
	}

	return (ISC_R_NOTFOUND);
}

size_t
isc_skiplist_poprange(isc_skiplist_t *slist, uint32_t range, size_t limit,
		      void *user, isc_skiplist_popaction_t action) {
	skiplist_entry_t *entry, *next_entry;
	skiplist_node_t *updates[MAX_LEVEL];
	size_t processed, removed;
	skiplist_node_t *node, *next_node;
	void *value;

	REQUIRE(SKIPLIST_VALID(slist));
	REQUIRE(action != NULL);

	if (limit == 0) {
		limit = SIZE_MAX;
	}

	memmove(updates, slist->head->nodes, sizeof(updates));

	removed = 0;
	processed = 0;

	node = slist->head->nodes[0];
	while (node->key < range) {
		INSIST(node != slist->head);

		fprintf(stderr, "\n!!!!!\nrange,ttl:%u\n!!!!!\n", node->key);

		ISC_LIST_FOREACH_SAFE (node->entries, entry, link, next_entry) {
			value = entry->value;

			fprintf(stderr,
				">>>>> range,ttl:%u,value:%p,node:%p ...",
				node->key, value, entry);

			INSIST(value != NULL);

			if ((action)(user, value, range)) {
				node->count--;
				removed++;

				ISC_LIST_UNLINK(node->entries, entry, link);
				*entry = (skiplist_entry_t){
					.value = NULL,
					.link = ISC_LINK_INITIALIZER,
				};
				ISC_LIST_APPEND(slist->frees, entry, link);
			}

			fprintf(stderr, "ok\n");

			processed++;
			if (processed >= limit) {
				goto out;
			}
		}

		if (ISC_LIST_EMPTY(node->entries)) {
			INSIST(node->count == 0);
			next_node = node->nodes[0];
			memmove(updates, node->nodes,
				node->level * sizeof(skiplist_node_t *));
			isc_mem_put(slist->mctx, node,
				    STRUCT_FLEX_SIZE(node, nodes, node->level));
			node = next_node;
		} else {
			node = node->nodes[0];
		}
	}

out:
	if (ISC_LIST_EMPTY(node->entries) && node != slist->head) {
		memmove(updates, node->nodes,
			node->level * sizeof(skiplist_node_t *));
		isc_mem_put(slist->mctx, node,
			    STRUCT_FLEX_SIZE(node, nodes, node->level));
	}

	memmove(slist->head->nodes, updates, sizeof(updates));

	return (removed);
}

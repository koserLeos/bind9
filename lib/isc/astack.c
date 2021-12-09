/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <string.h>

#include <isc/astack.h>
#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/types.h>
#include <isc/util.h>

typedef struct nodes {
	size_t size;
	size_t pos;
	void **nodes;
} nodes_t;

struct isc_astack {
	isc_mem_t *mctx;
	isc_mutex_t lock;
	size_t min_size;
	size_t max_size;
	nodes_t cur;
	nodes_t old;
};

static void
nodes_new(isc_mem_t *mctx, nodes_t *cur, size_t size) {
	*cur = (nodes_t){ .size = size };

	if (size > 0) {
		cur->nodes = isc_mem_get(mctx, cur->size * sizeof(void *));
		memset(cur->nodes, 0, cur->size * sizeof(void *));
	}
}

static void
nodes_free(isc_mem_t *mctx, nodes_t *cur) {
	REQUIRE(cur->pos == 0);

	if (cur->size > 0) {
		REQUIRE(cur->nodes != NULL);
		isc_mem_put(mctx, cur->nodes, cur->size * sizeof(void *));
	}

	*cur = (nodes_t){ .size = 0 };
}

#define IS_POWEROF2(bits) (bits && !(bits & (bits - 1)))

isc_astack_t *
isc_astack_new(isc_mem_t *mctx, size_t min_size, size_t max_size) {
	isc_astack_t *stack = isc_mem_get(mctx, sizeof(isc_astack_t));

	REQUIRE(IS_POWEROF2(min_size));
	REQUIRE(IS_POWEROF2(max_size));

	*stack = (isc_astack_t){ .min_size = min_size, .max_size = max_size };
	isc_mem_attach(mctx, &stack->mctx);
	isc_mutex_init(&stack->lock);

	nodes_new(mctx, &stack->cur, stack->min_size);
	nodes_new(mctx, &stack->old, 0);

	return (stack);
}

bool
isc_astack_trypush(isc_astack_t *stack, void *obj) {
	if (isc_mutex_trylock(&stack->lock) != ISC_R_SUCCESS) {
		return (false);
	}

	if (stack->cur.pos >= stack->cur.size) {
		if (stack->old.size > 0) {
			UNLOCK(&stack->lock);
			return (false);
		}

		if (stack->cur.size * 2 > stack->max_size) {
			UNLOCK(&stack->lock);
			return (false);
		}

		stack->old = stack->cur;
		nodes_new(stack->mctx, &stack->cur, stack->old.size * 2);
	}

	stack->cur.nodes[stack->cur.pos++] = obj;
	UNLOCK(&stack->lock);
	return (true);
}

void *
isc_astack_pop(isc_astack_t *stack) {
	void *rv;

	if (isc_mutex_trylock(&stack->lock) != ISC_R_SUCCESS) {
		return (false);
	}

	if (stack->old.size > 0) {
		REQUIRE(stack->old.pos > 0);

		rv = stack->old.nodes[--stack->old.pos];

		if (stack->old.pos == 0) {
			nodes_free(stack->mctx, &stack->old);
		}
	} else if (stack->cur.pos > 0) {
		rv = stack->cur.nodes[--stack->cur.pos];
	} else {
		rv = NULL;
	}
	UNLOCK(&stack->lock);
	return (rv);
}

void
isc_astack_destroy(isc_astack_t *stack) {
	LOCK(&stack->lock);
	REQUIRE(stack->cur.pos == 0);
	REQUIRE(stack->old.size == 0);
	UNLOCK(&stack->lock);

	nodes_free(stack->mctx, &stack->cur);

	isc_mutex_destroy(&stack->lock);

	isc_mem_putanddetach(&stack->mctx, stack, sizeof(struct isc_astack));
}

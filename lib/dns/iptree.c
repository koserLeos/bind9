/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include "config.h"

#include <dns/iptree.h>
#include <dns/ecs.h>

#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/util.h>

#include <stdio.h>
#include <string.h>

#define WORD_MASK(b) ((b) == 0 ? (uint32_t) (-1) \
		      : ((uint32_t) (-1) << (32 - (b))))
#define IP_BIT(ip, n) (1 & ((ip)[(n)/32] >> (31 - ((n) % 32))))
/*
 * In the struct below, IPv4 and IPv4 addresses use a common address
 * prefix representation. IPv6 addresses occupy the entire 128 bits in
 * `address_prefix`. IPv4 addresses have address_prefix[0] set to 0,
 * address_prefix[1] set to 0, address_prefix[2] set to 0x0000ffff and
 * address_prefix[3] set to the IPv4 address prefix bits.
 *
 * Note: Avoid packing gaps between members when updating this struct.
 */
struct dns_iptree_node {
	/** Left and right child pointers */
	dns_iptree_node_t *child[2];

	/** Pointer to the value for this node (may be NULL) */
	void *data;

	/** Address prefix bits */
	uint32_t address_prefix[4];

	/** Address prefix length */
	uint8_t address_prefix_length;

	/** Scope prefix length (always >= address_prefix_length) */
	uint8_t scope_prefix_length;
};

/**
 * \brief Return the address prefix family of the node.
 */
static unsigned int
get_address_family(const dns_iptree_node_t *node) {
	const uint32_t *address_prefix;

	address_prefix = node->address_prefix;

	return (address_prefix[0] == 0x00000000 &&
		address_prefix[1] == 0x00000000 &&
		address_prefix[2] == 0x0000ffff ? AF_INET : AF_INET6);
}

/**
 * \brief Create a new IP tree node.
 */
static dns_iptree_node_t *
new_node(isc_mem_t *mctx,
	 const uint32_t *address_prefix,
	 uint8_t address_prefix_length,
	 uint8_t scope_prefix_length)
{
	dns_iptree_node_t *node;
	int i, words, wlen;

	INSIST(scope_prefix_length >= address_prefix_length);

	node = isc_mem_get(mctx, sizeof(*node));
	if (ISC_UNLIKELY(node == NULL))
		return (NULL);

	node->child[0] = NULL;
	node->child[1] = NULL;
	node->data = NULL;

	node->address_prefix_length = address_prefix_length;
	node->scope_prefix_length = scope_prefix_length;

	words = address_prefix_length / 32;
	wlen = address_prefix_length % 32;
	for (i = 0; i < words; i++)
		node->address_prefix[i] = address_prefix[i];
	if (wlen != 0) {
		node->address_prefix[i] = address_prefix[i] & WORD_MASK(wlen);
		i++;
	}
	while (i < 4)
		node->address_prefix[i++] = 0;

	return (node);
}

#ifndef HAVE_BUILTIN_CLZ
/**
 * \brief Count Leading Zeros: Find the location of the left-most set
 * bit in an address prefix.
 */
static inline unsigned int
clz(uint32_t w) {
	unsigned int bit;

	bit = 31;

	if ((w & 0xffff0000) != 0) {
		w >>= 16;
		bit -= 16;
	}

	if ((w & 0xff00) != 0) {
		w >>= 8;
		bit -= 8;
	}

	if ((w & 0xf0) != 0) {
		w >>= 4;
		bit -= 4;
	}

	if ((w & 0xc) != 0) {
		w >>= 2;
		bit -= 2;
	}

	if ((w & 2) != 0)
		--bit;

	return (bit);
}
#endif

/**
 * \brief Find the first differing bit in two address prefixes.
 */
uint8_t
dns_iptree_common_prefix(const uint32_t *key1, uint8_t prefix1,
			 const uint32_t *key2, uint8_t prefix2)
{
	uint32_t delta;
	uint8_t maxbit, bit;
	uint8_t i;

	REQUIRE(key1 != NULL);
	REQUIRE(key2 != NULL);

	bit = 0;
	maxbit = ISC_MIN(prefix1, prefix2);

	/*
	 * find the first differing words
	 */
	for (i = 0; bit < maxbit; i++, bit += 32) {
		delta = key1[i] ^ key2[i];
		if (ISC_UNLIKELY(delta != 0)) {
#ifdef HAVE_BUILTIN_CLZ
			bit += __builtin_clz(delta);
#else
			bit += clz(delta);
#endif
			break;
		}
	}
	return (ISC_MIN(bit, maxbit));
}

static void
netaddr_to_array(const isc_netaddr_t *search_addr,
		 uint32_t *search_prefix)
{
	const unsigned char *addr6;
	uint32_t word;

	switch (search_addr->family) {
	case AF_INET:
		search_prefix[0] = 0x00000000;
		search_prefix[1] = 0x00000000;
		search_prefix[2] = 0x0000ffff;
		search_prefix[3] = ntohl(search_addr->type.in.s_addr);
		break;

	case AF_INET6:
		addr6 = search_addr->type.in6.s6_addr;

		word  = addr6[0] << 24;
		word |= addr6[1] << 16;
		word |= addr6[2] << 8;
		word |= addr6[3];
		search_prefix[0] = word;

		word  = addr6[4] << 24;
		word |= addr6[5] << 16;
		word |= addr6[6] << 8;
		word |= addr6[7];
		search_prefix[1] = word;

		word  = addr6[8] << 24;
		word |= addr6[9] << 16;
		word |= addr6[10] << 8;
		word |= addr6[11];
		search_prefix[2] = word;

		word  = addr6[12] << 24;
		word |= addr6[13] << 16;
		word |= addr6[14] << 8;
		word |= addr6[15];
		search_prefix[3] = word;

		break;

	default:
		INSIST(0);
	}
}

static void
array_to_netaddr(const uint32_t *search_prefix,
		 isc_netaddr_t *search_addr)
{
	memset(search_addr, 0, sizeof(isc_netaddr_t));

	if (search_prefix[0] == 0x00000000 &&
	    search_prefix[1] == 0x00000000 &&
	    search_prefix[2] == 0x0000ffff)
	{
		search_addr->family = AF_INET;

		search_addr->type.in.s_addr = htonl(search_prefix[3]);
	} else {
		unsigned char *addr6;
		uint32_t word;

		search_addr->family = AF_INET6;

		addr6 = search_addr->type.in6.s6_addr;

		word = search_prefix[0];
		addr6[0] = (word >> 24) & 0xff;
		addr6[1] = (word >> 16) & 0xff;
		addr6[2] = (word >> 8) & 0xff;
		addr6[3] = word & 0xff;

		word = search_prefix[1];
		addr6[4] = (word >> 24) & 0xff;
		addr6[5] = (word >> 16) & 0xff;
		addr6[6] = (word >> 8) & 0xff;
		addr6[7] = word & 0xff;

		word = search_prefix[2];
		addr6[8] = (word >> 24) & 0xff;
		addr6[9] = (word >> 16) & 0xff;
		addr6[10] = (word >> 8) & 0xff;
		addr6[11] = word & 0xff;

		word = search_prefix[3];
		addr6[12] = (word >> 24) & 0xff;
		addr6[13] = (word >> 16) & 0xff;
		addr6[14] = (word >> 8) & 0xff;
		addr6[15] = word & 0xff;
	}
}

isc_result_t
dns_iptree_search(dns_iptree_node_t **root,
		  isc_mem_t *mctx,
		  const isc_netaddr_t *search_addr,
		  uint8_t source_prefix_length,
		  uint8_t scope_prefix_length,
		  bool create,
		  dns_iptree_callbackfunc_t match_fn,
		  void *match_arg,
		  dns_iptree_node_t **found_node)
{
	isc_result_t result;
	uint32_t search_prefix[4];
	dns_iptree_node_t *cur, *child, *new_parent, *sibling;
	uint8_t diff_bit;
	int child_num, cur_num;
	unsigned int family;
	dns_iptree_node_t *target_node;
	uint8_t search_prefix_length;

	REQUIRE(root != NULL);
	REQUIRE(mctx != NULL || !create);
	REQUIRE(search_addr != NULL);
	REQUIRE(source_prefix_length > 0);
	REQUIRE((search_addr->family == AF_INET &&
		 source_prefix_length <= 32 &&
		 scope_prefix_length <= 32) ||
		(search_addr->family == AF_INET6 &&
		 source_prefix_length <= 128 &&
		 scope_prefix_length <= 128));
	REQUIRE(create || scope_prefix_length == 0);
	REQUIRE(!create || (match_fn == NULL && match_arg == NULL));
	REQUIRE(found_node != NULL && *found_node == NULL);

	if (ISC_LIKELY(!create)) {
		search_prefix_length = source_prefix_length;
		scope_prefix_length = source_prefix_length;
	} else {
		/* Search based on the shorter of source/scope */
		if (scope_prefix_length <= source_prefix_length)
			search_prefix_length = scope_prefix_length;
		else
			search_prefix_length = source_prefix_length;
	}

	netaddr_to_array(search_addr, search_prefix);
	family = search_addr->family;
	/* IPv4 addresses are represented as mapped IPv6, so offset 96 bits */
	if (family == AF_INET) {
		search_prefix_length += 96;
		scope_prefix_length += 96;
		source_prefix_length += 96;
	}

	result = ISC_R_NOTFOUND;
	cur = *root;
	target_node = NULL;

	for (;;) {
		if (ISC_UNLIKELY(cur == NULL)) {
			/*
			 * No child so we cannot go down.  Quit with
			 * whatever we already found or add the target
			 * as a child of the current parent.
			 */
			if (ISC_LIKELY(!create))
				break;
			child = new_node(mctx, search_prefix,
					 search_prefix_length,
					 scope_prefix_length);
			if (ISC_UNLIKELY(child == NULL))
				return (ISC_R_NOMEMORY);
			*root = child;

			target_node = child;
			result = ISC_R_SUCCESS;
			break;
		}

		diff_bit = dns_iptree_common_prefix(search_prefix,
						    search_prefix_length,
						    cur->address_prefix,
						    cur->address_prefix_length);
		/*
		 * diff_bit <= search_prefix_length and diff_bit <=
		 * cur->address_prefix_length always.  We are finished
		 * searching if we matched all of the search prefix.
		 */
		if (diff_bit == search_prefix_length) {
			if (search_prefix_length == cur->address_prefix_length)
			{
				/*
				 * If create is true and the node has
				 * data, only then return ISC_R_EXISTS.
				 * A node may have been created as a
				 * fork with no data, and we should
				 * not return ISC_R_EXISTS for
				 * such nodes.
				 */
				if (!create) {
					bool use_as_match = true;

					if (match_fn != NULL)
						use_as_match =
							match_fn(&cur->data,
								 match_arg);
					if (use_as_match) {
						target_node = cur;
						result = ISC_R_SUCCESS;
					}
					break;
				}

				if (cur->data != NULL) {
					target_node = cur;
					result = ISC_R_EXISTS;
					break;
				}

				/*
				 * At this node, data is NULL, so the
				 * address prefix corresponding to this
				 * node effectively doesn't exist, so we
				 * can modify scope_prefix_length at
				 * will.
				 */
				cur->scope_prefix_length = scope_prefix_length;
				target_node = cur;
				result = ISC_R_SUCCESS;
				break;
			}

			/*
			 * We know search_prefix_length <
			 * cur->address_prefix_length which means that
			 * the search prefix is shorter than the current
			 * node. Add the target as the current node's
			 * parent.
			 */
			if (ISC_LIKELY(!create))
				break;

			new_parent = new_node(mctx, search_prefix,
					      search_prefix_length,
					      scope_prefix_length);
			if (new_parent == NULL)
				return (ISC_R_NOMEMORY);
			*root = new_parent;
			child_num = IP_BIT(cur->address_prefix,
					   search_prefix_length);
			new_parent->child[child_num] = cur;
			target_node = new_parent;
			result = ISC_R_SUCCESS;
			break;
		}

		if (diff_bit == cur->address_prefix_length) {
			if ((cur->address_prefix_length ==
			     cur->scope_prefix_length) &&
			    (cur->data != NULL) &&
			    (family == AF_INET6 ||
			     cur->address_prefix_length >= 96))
			{
				bool use_as_match = true;

				if (match_fn != NULL)
					use_as_match = match_fn(&cur->data,
								match_arg);
				if (use_as_match) {
					/*
					 * We have a partial match
					 * between of all of the current
					 * node but only part of the
					 * search prefix. Continue
					 * searching for other hits.
					 */
					target_node = cur;
					result = DNS_R_PARTIALMATCH;
				}
			}
			cur_num = IP_BIT(search_prefix, diff_bit);
			root = &cur->child[cur_num];
			cur = *root;
			continue;
		}

		/*
		 * diff_bit < search_prefix_length and diff_bit <
		 * cur->address_prefix_length, so we failed to match
		 * both the target and the current node.  Insert a fork
		 * of a parent above the current node and add the target
		 * as a sibling of the current node
		 */
		if (ISC_LIKELY(!create))
			break;

		sibling = new_node(mctx, search_prefix, search_prefix_length,
				   scope_prefix_length);
		if (ISC_UNLIKELY(sibling == NULL))
			return (ISC_R_NOMEMORY);
		new_parent = new_node(mctx, search_prefix, diff_bit, diff_bit);
		if (ISC_UNLIKELY(new_parent == NULL)) {
			isc_mem_put(mctx, sibling, sizeof(*sibling));
			return (ISC_R_NOMEMORY);
		}
		*root = new_parent;
		child_num = IP_BIT(search_prefix, diff_bit);
		new_parent->child[child_num] = sibling;
		new_parent->child[1 - child_num] = cur;
		target_node = sibling;
		result = ISC_R_SUCCESS;
		break;
	}

	if (result != ISC_R_NOTFOUND)
		*found_node = target_node;

	return (result);
}

void
dns_iptree_get_data(dns_iptree_node_t *found_node,
		    void **found_data,
		    uint8_t *found_address_prefix_length,
		    uint8_t *found_scope_prefix_length)
{
	unsigned int family;

	REQUIRE(found_node != NULL);
	REQUIRE(found_data != NULL && *found_data == NULL);

	family = get_address_family(found_node);

	*found_data = &found_node->data;

	if (found_address_prefix_length != NULL) {
		*found_address_prefix_length = (family == AF_INET6) ?
			found_node->address_prefix_length :
			found_node->address_prefix_length - 96;
	}

	if (found_scope_prefix_length != NULL) {
		*found_scope_prefix_length = (family == AF_INET6) ?
			found_node->scope_prefix_length :
			found_node->scope_prefix_length - 96;
	}
}

void
dns_iptree_set_data(dns_iptree_node_t *node, void *data) {
	REQUIRE(node != NULL);

	node->data = data;
}

void
dns_iptree_set_scope(dns_iptree_node_t *node, uint8_t scope_prefix_length) {
	unsigned int family;

	REQUIRE(node != NULL);

	family = get_address_family(node);

	REQUIRE((family == AF_INET &&
		 scope_prefix_length <= 32) ||
		(family == AF_INET6 &&
		 scope_prefix_length <= 128));

	if (family == AF_INET)
		scope_prefix_length += 96;

	INSIST(scope_prefix_length >= node->address_prefix_length);

	node->scope_prefix_length = scope_prefix_length;
}

void
dns_iptree_foreach(dns_iptree_node_t *root,
		   dns_iptree_callbackfunc_t callback_fn,
		   void *callback_args)
{
	REQUIRE(callback_fn != NULL);

	if (root == NULL)
		return;

	dns_iptree_foreach(root->child[0], callback_fn, callback_args);

	if (ISC_LIKELY(callback_fn && root->data != NULL))
		callback_fn(&root->data, callback_args);

	dns_iptree_foreach(root->child[1], callback_fn, callback_args);
}

void
dns_iptree_destroy_foreach(dns_iptree_node_t **root,
			   isc_mem_t *mctx,
			   dns_iptree_callbackfunc_t destroy_fn,
			   void *destroy_args)
{
	dns_iptree_node_t *cur;

	REQUIRE(root != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(destroy_fn != NULL);

	cur = *root;
	if (cur == NULL)
		return;

	dns_iptree_destroy_foreach(&cur->child[0], mctx,
				   destroy_fn, destroy_args);
	dns_iptree_destroy_foreach(&cur->child[1], mctx,
				   destroy_fn, destroy_args);

	if (cur->data != NULL)
		destroy_fn(&cur->data, destroy_args);

	/* Free empty nodes if possible. */
	if (cur->data == NULL) {
		if ((cur->child[0] == NULL) || (cur->child[1] == NULL))	{
			*root = (cur->child[0] == NULL) ?
				cur->child[1] :	cur->child[0];
			isc_mem_put(mctx, cur, sizeof(*cur));
		}
	}
}

size_t
dns_iptree_get_nodecount(const dns_iptree_node_t *root) {
	size_t count = 0;

	if (root != NULL) {
		count += dns_iptree_get_nodecount(root->child[0]);
		count += dns_iptree_get_nodecount(root->child[1]);
		count++;
	}

	return (count);
}

static void
print_address_prefix(const dns_iptree_node_t *node, FILE *f) {
	isc_netaddr_t netaddr;
	char buf[ISC_NETADDR_FORMATSIZE];
	uint8_t source;
	uint8_t scope;

	array_to_netaddr(node->address_prefix, &netaddr);
	isc_netaddr_format(&netaddr, buf, sizeof(buf));

	source = node->address_prefix_length;
	scope = node->scope_prefix_length;
	if (netaddr.family == AF_INET) {
		source -= 96;
		scope -= 96;
	}

	fprintf(f, "%s/%u/%u", buf, source, scope);
}

static int
print_dot_helper(const dns_iptree_node_t *node, unsigned int *nodecount,
		 bool show_pointers, FILE *f)
{
	unsigned int l, r;

	if (node == NULL)
		return (0);

	l = print_dot_helper(node->child[0], nodecount, show_pointers, f);
	r = print_dot_helper(node->child[1], nodecount, show_pointers, f);

	*nodecount += 1;

	fprintf(f, "node%u[label = \"<f0> |<f1> ", *nodecount);
	print_address_prefix(node, f);
	fprintf(f, "|<f2>");

	if (show_pointers)
		fprintf(f, "|<f3> n=%p", node);

	fprintf(f, "\"] [");

	if (node->data == NULL)
		fprintf(f, "color=gray,style=filled,fillcolor=lightgrey");
	else
		fprintf(f, "color=black");

	fprintf(f, "];\n");

	if (node->child[0] != NULL)
		fprintf(f, "\"node%u\":f0 -> \"node%u\":f1;\n", *nodecount, l);

	if (node->child[1] != NULL)
		fprintf(f, "\"node%u\":f2 -> \"node%u\":f1;\n", *nodecount, r);

	return (*nodecount);
}

void
dns_iptree_print_dot(const dns_iptree_node_t *root,
		     bool show_pointers, FILE *f)
{
	unsigned int nodecount = 0;

	fprintf(f, "digraph g {\n");
	fprintf(f, "node [shape = record,height=.1];\n");
	print_dot_helper(root, &nodecount, show_pointers, f);
	fprintf(f, "}\n");
}

struct dns_iptree_iter {
	isc_mem_t *mctx;
	dns_iptree_node_t *levels[129];
	int current;
};

isc_result_t
dns_iptree_iter_create(isc_mem_t *mctx, dns_iptree_node_t *root,
		       dns_iptree_iter_t **iterp)
{
	unsigned int i;

	REQUIRE(mctx != NULL);
	REQUIRE(iterp != NULL && *iterp == NULL);

	*iterp = isc_mem_get(mctx, sizeof(**iterp));
	if (ISC_UNLIKELY(*iterp == NULL))
		return (ISC_R_NOMEMORY);

	(*iterp)->mctx = mctx;
	(*iterp)->levels[0] = root;
	for (i = 1; i < 129; i++)
		(*iterp)->levels[i] = NULL;

	(*iterp)->current = -1;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_iptree_iter_next(dns_iptree_iter_t *iter, void **data, dns_ecs_t *ecs) {
	dns_iptree_node_t *node;
	isc_result_t result;

	REQUIRE(iter != NULL);
	REQUIRE(data != NULL && *data == NULL);
	REQUIRE(ecs != NULL);

	if (iter->current == -1) {
		if (iter->levels[0] == NULL) {
			result = ISC_R_NOMORE;
			goto done;
		}
		iter->current++;
		INSIST(iter->current <= 128);
		node = iter->levels[iter->current];
		goto go_left;
	}

	node = iter->levels[iter->current];

	if (node->child[0] != NULL) {
		node = node->child[0];
		iter->current++;
		INSIST(iter->current <= 128);
		iter->levels[iter->current] = node;
		goto go_left;
	}

	goto go_right;

go_left:
	while ((node->data == NULL) && (node->child[0] != NULL)) {
		node = node->child[0];
		iter->current++;
		INSIST(iter->current <= 128);
		iter->levels[iter->current] = node;
	}
	if (node->data != NULL) {
		*data = node->data;
		array_to_netaddr(node->address_prefix, &ecs->addr);
		ecs->source = node->address_prefix_length;
		ecs->scope = node->scope_prefix_length;
		if (ecs->addr.family == AF_INET) {
			ecs->source -= 96;
			ecs->scope -= 96;
		}

		result = ISC_R_SUCCESS;
		goto done;
	}
go_right:
	if (node->child[1] != NULL) {
		node = node->child[1];
		iter->current++;
		INSIST(iter->current <= 128);
		iter->levels[iter->current] = node;
		goto go_left;
	}
go_parent:
	iter->levels[iter->current] = NULL;
	iter->current--;
	if (iter->current < 0) {
		result = ISC_R_NOMORE;
		goto done;
	}
	if (iter->levels[iter->current]->child[1] == node) {
		node = iter->levels[iter->current];
		goto go_parent;
	}
	node = iter->levels[iter->current];
	goto go_right;

done:
	return (result);
}

void
dns_iptree_iter_destroy(dns_iptree_iter_t **iterp) {
	isc_mem_t *mctx;

	REQUIRE(iterp != NULL && *iterp != NULL);

	mctx = (*iterp)->mctx;

	isc_mem_put(mctx, *iterp, sizeof(**iterp));
	*iterp = NULL;
}

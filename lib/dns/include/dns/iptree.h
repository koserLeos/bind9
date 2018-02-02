/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.	 IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file isc/iptree.h
 * \brief IP address tree for EDNS client-subnet option.
 *
 * This file provides an IP address tree supporting longest prefix match
 * lookup specifically for the EDNS client-subnet (ECS) option. Keys are
 * IP address prefixes (address, family and prefix length) and values
 * can be anything (`void *` pointer).
 *
 * The IP tree is meant to be used to implement a resolver's ECS cache,
 * but it can also be used to store ECS zone data for an authoritative
 * server.
 *
 * The tree is raw, i.e., there is no tree object and functions accept a
 * pointer to the root node of the tree data structure.
 *
 * Both IPv4 and IPv6 address prefixes can be stored in the same
 * tree. The relevant functions allow the address family to be
 * specified. IPv4 address prefixes are stored as "IPv4-mapped" address
 * prefixes (RFC 2765), i.e., as 0::ffff:a.b.c.d where a.b.c.d is the
 * IPv4 address. Longest prefix matching starts searching in the tree
 * from /0 for IPv6 lookups and [mapped-prefix/96] for mapped prefix
 * lookups.
 *
 * The tree is a utility data structure for ECS, so the search interface
 * accepts source/scope information and provides a relevant return
 * prefix length that a resolver can use in the reply message. The tree
 * implements all the SOURCE/SCOPE PREFIX-LENGTH behavior
 * internally. The caller need not concern themselves with ECS address
 * prefix caching details.
 *
 * Answers with SOURCE PREFIX-LENGTH as 0 cannot be handled by this
 * tree. They could be stored outside this tree in a regular non-ECS
 * resolver cache, but that is not this interface's concern.
 *
 * The implementation is encapsulated, and details of the exact
 * representation are not leaked to the caller. This allows the
 * implementation to be changed if necessary.
 */

#ifndef DNS_IPTREE_H
#define DNS_IPTREE_H 1

#include <dns/types.h>
#include <dns/result.h>
#include <stdlib.h> /* for size_t */

ISC_LANG_BEGINDECLS

/**
 * \brief Function used as callback when iterating the tree.
 *
 * This function type is used as a callback function when iterating or
 * searching the tree. It is called for non-empty nodes.
 *
 * \param data Pointer to the data stored in the node.
 * \param callback_arg User pointer that was passed to the function
 * starting the iteration.
 *
 * \return
 * * \ref ISC_TRUE True result, specific to the function using the callback.
 * * \ref ISC_FALSE False result, specific to the function using the callback.
 *
 * \par Pre-conditions
 * None.
 *
 * \par Post-conditions
 * None.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * The callback function's thread safety is undefined.
 */
typedef isc_boolean_t (*dns_iptree_callbackfunc_t)(void **data,
						   void *callback_arg);

/**
 * \brief Search for an address prefix match, optionally creating a
 * matching node.
 *
 * This function searches for a matching result for a search address
 * prefix by implementing the ECS cache lookup algorithm. Depending on
 * whether `create` is ISC_TRUE, this function can optionally create a
 * resulting entry in the tree if there was no existing match.
 *
 * The arguments accepted by the function are chosen to closely match
 * the fields in an EDNS client-subnet option.
 *
 * `search_addr`, `source_prefix_length` and `scope_prefix_length`
 * correspond to the values from the EDNS client-subnet option, whether
 * it is from a query message or from a reply message:
 *
 * * `search_addr` contains the address family and the address field.
 * * `source_prefix_length` and `scope_prefix_length` correspond to the
 *   SOURCE PREFIX-LENGTH and SCOPE PREFIX-LENGTH fields. In the case of
 *   tree lookup during queries (`create=ISC_FALSE`), SCOPE
 *   PREFIX-LENGTH should be set to 0. In the case of tree insertion,
 *   SCOPE PREFIX-LENGTH should be the value returned by the
 *   upstream server in its reply message.
 *
 * SOURCE PREFIX-LENGTH of 0 is not supported for insertion or
 * lookup. They could be stored outside this tree in a regular non-ECS
 * resolver cache, but that is not this interface's concern. Answers
 * with no address prefix information are not meant to be stored in this
 * tree.
 *
 * When a result is found in the tree (`ISC_R_SUCCESS`, `ISC_R_EXISTS`,
 * `DNS_R_PARTIALMATCH`), an opaque pointer to the node corresponding to
 * the resulting address prefix is returned in `found_node`. \ref
 * dns_iptree_get_data() can be used to get the found node's data.
 *
 * \param root Pointer to a location containing the pointer to the root
 * node of the IP tree.
 * \param mctx Memory context to use for allocations. If create is
 * false, `mctx` can be `NULL`.
 * \param search_addr Address to search for.
 * \param source_prefix_length Length of address prefix for address in
 * `addr`. Pass SOURCE PREFIX-LENGTH here.
 * \param scope_prefix_length Scope prefix length. Pass SCOPE
 * PREFIX-LENGTH here.
 * \param create Whether to insert this key if it does not exist.
 * \param match_fn A function to callback to decide whether to consider
 * an answer for matching. It can be `NULL`, in which case, every answer
 * is considered when finding the longest prefix match. `match_fn`
 * must be set to `NULL` when `create` is `ISC_TRUE`.
 * \param match_arg The user data argument to pass to the callback
 * function. It can be `NULL`.
 * \param found_node Pointer to `NULL`-initialized `dns_iptree_node_t *`
 * pointer from where a pointer to the found node can be retrieved.
 *
 * \return
 * * \ref ISC_R_SUCCESS The search was successful.
 * * \ref ISC_R_EXISTS The search was successful, but the node already
 *   exists (when `create` is \ref ISC_TRUE).
 * * \ref DNS_R_PARTIALMATCH The search was unsuccessful but a shorter
 *   address prefix length was present in the tree.
 * * \ref ISC_R_NOTFOUND The search was unsuccessful.
 * * \ref ISC_R_NOMEMORY The function ran out of memory.
 *
 * \par Pre-conditions
 * The function arguments must be valid according to the ECS
 * specification. `root` must point to a variable containing the
 * pointer to a valid root \ref dns_iptree_node_t node. if 'create' is
 * true, then `mctx` must point to a valid memory context for all tree
 * allocations. `search_addr` must point to a valid `isc_netaddr_t`
 * containing the address family and source address
 * prefix. `source_prefix_length` and `scope_prefix_length` must match
 * the corresponding address family in `search_addr` (they must not be
 * longer than the maximum allowed length for that
 * family). `source_prefix_length` MUST be non-zero. If
 * `create` is ISC_TRUE, `scope_prefix_length` must be passed as 0.
 * `found_node` must point to a valid `dns_iptree_node_t *` and
 * `*found_node` must be initialized to `NULL`. If any of the
 * pre-conditions fail, the function will abort with a `REQUIRE()`
 * assertion failure.
 *
 * \par Post-conditions
 * If a result was found (ISC_R_SUCCESS, ISC_R_EXISTS,
 * DNS_R_PARTIALMATCH), `*found_node` is assigned. If `create` was passed
 * as `ISC_TRUE` and `ISC_R_SUCCESS` is returned, the tree was modified
 * (new entry may have been created, or an existing but empty entry may
 * have been modified). If `create` was passed as `ISC_TRUE` and
 * `ISC_R_EXISTS` is returned, the tree is not modified.  If
 * `ISC_R_NOTFOUND` or `ISC_R_NOMEMORY` is returned, the tree and return
 * arguments are not modified. The caller must expect `*root` to be
 * changed when the tree is modified according to the post-conditions
 * listed here.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is not thread-safe.
 */
isc_result_t
dns_iptree_search(dns_iptree_node_t **root,
		  isc_mem_t *mctx,
		  const isc_netaddr_t *search_addr,
		  isc_uint8_t source_prefix_length,
		  isc_uint8_t scope_prefix_length,
		  isc_boolean_t create,
		  dns_iptree_callbackfunc_t match_fn,
		  void *match_arg,
		  dns_iptree_node_t **found_node);

/**
 * \brief Return data from an IP tree node.
 *
 * This function returns data from an IP tree node that was previously
 * returned by a successful call to the \ref dns_iptree_search()
 * function.
 *
 * A pointer to the data in the node is returned in `found_data` (note
 * that it is a pointer to a pointer using which this data can be also
 * set). The prefix length at which the node's data was cached is
 * returned at `found_address_prefix`. The SCOPE PREFIX-LENGTH that
 * should be returned to the client due to this cached data is returned
 * at `found_scope_prefix`. Note that the SOURCE PREFIX-LENGTH that
 * should be returned to the client must be copied from the ECS option
 * in the client's query message.
 *
 * \param found_node Pointer to a IP tree node previously returned by
 * \ref dns_iptree_search().
 * \param found_data Pointer to `NULL`-initialized `void *` pointer
 * from where a pointer to the value can be retrieved or stored.
 * \param found_address_prefix_length Pointer to `isc_uint8_t` where the
 * length of address prefix matched for address in `addr` is returned.
 * \param found_scope_prefix_length Pointer to `isc_uint8_t` where the
 * scope prefix length matched for address in `addr` is returned.
 *
 * \par Pre-conditions
 * `found_node` must point to a valid IP tree node.  `found_data` must
 * point to a valid `void *` and `*found_data` must be initialized to
 * `NULL`. `found_address_prefix_length` and `found_scope_prefix_length`
 * must point to `isc_uint8_t`s to receive the return arguments. If any
 * of the pre-conditions fail, the function will abort with a
 * `REQUIRE()` assertion failure.
 *
 * \par Post-conditions
 * `*found_data`, `*found_address_prefix_length` and
 * `*found_scope_prefix_length` are assigned with values from the node.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
void
dns_iptree_get_data(dns_iptree_node_t *found_node,
		    void **found_data,
		    isc_uint8_t *found_address_prefix_length,
		    isc_uint8_t *found_scope_prefix_length);

/**
 * \brief Set IP tree node data.
 *
 * This function sets the IP tree node's data.
 *
 * \param node Pointer to the IP tree node.
 * \param data Value to be saved in the node data pointer.
 *
 * \par Pre-conditions
 * `node` should point to a valid IP tree node.
 *
 * \par Post-conditions
 * The node's data is set to the passed pointer.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
void
dns_iptree_set_data(dns_iptree_node_t *node, void *data);

/**
 * \brief Set IP tree node's scope prefix length.
 *
 * This function sets the IP tree node's scope prefix length.
 *
 * \param node Pointer to the IP tree node.
 * \param scope_prefix_length New scope prefix length value for the node.
 *
 * \par Pre-conditions
 * `node` should point to a valid IP tree node. `scope_prefix_length`
 * should be correct for the node's address family.
 *
 * \par Post-conditions
 * The node's scope prefix length is set to the passed value.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
void
dns_iptree_set_scope(dns_iptree_node_t *node,
		     isc_uint8_t scope_prefix_length);

/**
 * \brief Return length of common address prefix.
 *
 * This function returns the length in bits of the common address prefix
 * part of `key1` and `key2`.
 *
 * This function is provided for test purposes only.
 *
 * \param key1 Pointer to isc_uint32_t[4] array containing an address.
 * \param prefix1 Number of address bits in `key1`.
 * \param key2 Pointer to isc_uint32_t[4] array containing an address.
 * \param prefix2 Number of address bits in `key2`.
 *
 * \return Number of common address prefix bits between `key1` and
 * `key2`.
 *
 * \par Pre-conditions
 * `key1` and `key2` should point to valid isc_uint32_t[4] arrays.
 *
 * \par Post-conditions
 * None.
 *
 * \par Invariants
 * None of the function arguments are modified.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
isc_uint8_t
dns_iptree_common_prefix(const isc_uint32_t *key1, isc_uint8_t prefix1,
			 const isc_uint32_t *key2, isc_uint8_t prefix2);

/**
 * \brief Iterate over all nodes with data in the tree.
 *
 * This function iterates over all nodes with data in the IP tree,
 * calling `callback_fn` on every node with data.
 *
 * \param root Pointer to the root node of the IP tree. It can be `NULL`
 * for an empty tree.
 * \param callback_fn The function to callback when iterating over the
 * tree.
 * \param callback_args The user data argument to pass to the callback
 * function. It can be `NULL`.
 *
 * \par Pre-conditions
 * A valid `callback_fn` must be passed.
 *
 * \par Post-conditions
 * The tree nodes' data may have been modified by the callback function.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
void
dns_iptree_foreach(dns_iptree_node_t *root,
		   dns_iptree_callbackfunc_t callback_fn,
		   void *callback_args);

/**
 * \brief Selectively destroy nodes in an IP tree.
 *
 * This function selectively destroys nodes in an IP tree by iterating
 * over every node in the tree with data, calling `callback_fn` on
 * them. If a node has no data or if if the `callback_fn` clears a
 * node's data, the node is a candidate for deletion or merging with
 * other nodes.
 *
 * \param root Pointer to a location containing the pointer to the root
 * node of the IP tree.
 * \param mctx Memory context to use for deallocations.
 * \param destroy_fn The function to callback when iterating over the
 * tree. It cannot be `NULL`.
 * \param destroy_args The user data argument to pass to the callback
 * function. It can be `NULL`.
 *
 * \par Pre-conditions
 * `root` must not be `NULL`, but it can point to a `NULL` node
 * pointer. Nothing happens if an empty tree is destroyed (`*root ==
 * NULL`). `mctx` must point to a valid memory context.
 *
 * \par Post-conditions
 * `*root` will be set to NULL if the tree has been destroyed. If a part
 * of the tree is selectively destroyed, what results is a valid IP tree
 * with the remaining nodes.
 *
 * \par Invariants
 * None.
 *
 * \par Thread-safety
 * This function is not thread-safe.
 */
void
dns_iptree_destroy_foreach(dns_iptree_node_t **root,
			   isc_mem_t *mctx,
			   dns_iptree_callbackfunc_t destroy_fn,
			   void *destroy_args);

/**
 * \brief Return the number of nodes in the IP tree.
 *
 * This function returns the number of empty and non-empty nodes in the
 * IP tree. It iterates over all nodes to compute the count.
 *
 * This function is provided for use in testing only.
 *
 * \param root Pointer to the root node of the IP tree. It can be `NULL`
 * for an empty tree.
 *
 * \par Pre-conditions
 * None.
 *
 * \par Post-conditions
 * None.
 *
 * \par Invariants
 * The tree is not modified by this function.
 *
 * \par Thread-safety
 * This function is thread-safe as long as the arguments do not change
 * while the function is executing.
 */
size_t
dns_iptree_get_nodecount(const dns_iptree_node_t *root);

/**
 * Print a GraphViz dot representation of the internal structure of the
 * IP tree to the passed stream.
 *
 * If show_pointers is `ISC_TRUE`, pointers are also included in the
 * generated graph.
 *
 * The address prefix stored at each node is displayed. Then the left
 * and right pointers are displayed recursively in turn. `NULL` left
 * and right pointers are silently omitted.
 */
void
dns_iptree_print_dot(const dns_iptree_node_t *root,
		     isc_boolean_t show_pointers, FILE *f);

/**
 * \brief Create an iterator over an IP tree.
 *
 * This function creates an iterator that can be used to iterate over
 * all the nodes of an IP tree. Traversal is pre-order depth first. Note
 * that during the lifetime of this iterator, a lock must be held on
 * access to the IP tree.
 *
 * \param mctx Memory context to use for allocations.
 * \param root Pointer to the root node of the IP tree. It can be `NULL`
 * for an empty tree.
 * \param iterp Pointer to `NULL`-initialized `dns_iptree_iter_t *`
 * pointer from where a pointer to the iterator can be retrieved.
 *
 * \par Pre-conditions
 * `root` must point to a valid root \ref dns_iptree_node_t node. `mctx`
 * must point to a valid memory context for allocations. `iterp` must
 * point to a valid `dns_iptree_iter_t *` and `*iterp` must be
 * initialized to `NULL`. If any of the pre-conditions fail, the
 * function will abort with a `REQUIRE()` assertion failure.
 *
 * \par Post-conditions
 * A successful result (ISC_R_SUCCESS) returns an iterator in
 * `*iterp`. In case of failure, an appropriate result indicating the
 * type of failure is returned.
 *
 * \par Invariants
 * The tree is not modified by this function.
 *
 * \par Thread-safety
 * Lock must be held on access to the IP tree.
 */
isc_result_t
dns_iptree_iter_create(isc_mem_t *mctx, dns_iptree_node_t *root,
		       dns_iptree_iter_t **iterp);

/**
 * \brief Return data from the next non-empty node of an IP tree using
 * the iterator.
 *
 * This function returns data from the next non-empty node of an IP tree
 * using the iterator passed in `iter`.
 *
 * \param iter Pointer to a non-NULL iterator created by \ref
 * dns_iptree_iter_create().
 * \param data Pointer to a `void *` to store the data from the node.
 * \param ecs Pointer to a freshly initialized `dns_ecs_t` structure
 * where the address prefix and other ECS data associated with the
 * `data` is returned.
 *
 * \par Pre-conditions
 * `iter` must point to a valid iterator created by \ref
 * dns_iptree_iter_create(). `data` must be non-NULL and point to a
 * `void *` containing NULL. `ecs` must point to a `dns_ecs_t` structure
 * freshly initialized by \ref dns_ecs_init().
 *
 * \par Post-conditions
 * A successful result (ISC_R_SUCCESS) returns data from the next node
 * in sequence from the IP tree. In case no more nodes are left to be
 * iterated, ISC_R_NOMORE is returned.
 *
 * \par Invariants
 * The tree is not modified by this function.
 *
 * \par Thread-safety
 * Lock must be held on access to the IP tree.
 */
isc_result_t
dns_iptree_iter_next(dns_iptree_iter_t *iter, void **data, dns_ecs_t *ecs);

/**
 * \brief Destroy an IP tree iterator.
 *
 * This function destroys an IP tree iterator that was created using
 * \ref dns_iptree_iter_create().
 *
 * \param iterp Pointer to `dns_iptree_iter_t *` pointer.
 *
 * \par Pre-conditions
 * `iterp` must point to a valid \ref dns_iptree_iter_t pointer that was
 * created by \ref dns_iptree_iter_create()..
 *
 * \par Post-conditions
 * The iterator is destroyed and `NULL` is returned in `*iterp`.
 *
 * \par Invariants
 * The tree is not modified by this function.
 *
 * \par Thread-safety
 * Lock must be held on access to the IP tree.
 */
void
dns_iptree_iter_destroy(dns_iptree_iter_t **iterp);


ISC_LANG_ENDDECLS

#endif /* DNS_IPTREE_H */

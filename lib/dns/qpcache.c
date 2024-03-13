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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <sys/mman.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/crc64.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/heap.h>
#include <isc/hex.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/spinlock.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/qp.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/view.h>
#include <dns/zonekey.h>

#include "db_p.h"
#include "qpcache_p.h"

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) == 0)
#define NONEXISTENT(header)                            \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NONEXISTENT) != 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_IGNORE) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NXDOMAIN) != 0)
#define STALE(header)                                  \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE) != 0)
#define STALE_WINDOW(header)                           \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STALE_WINDOW) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_OPTOUT) != 0)
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_NEGATIVE) != 0)
#define PREFETCH(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_PREFETCH) != 0)
#define ZEROTTL(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ZEROTTL) != 0)
#define ANCIENT(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_ANCIENT) != 0)
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_SLABHEADERATTR_STATCOUNT) != 0)

#define STALE_TTL(header, qpdb) \
	(NXDOMAIN(header) ? 0 : qpdb->common.serve_stale_ttl)

#define ACTIVE(header, now) \
	(((header)->ttl > (now)) || ((header)->ttl == (now) && ZEROTTL(header)))

#define EXPIREDOK(rbtiterator) \
	(((rbtiterator)->common.options & DNS_DB_EXPIREDOK) != 0)

#define STALEOK(rbtiterator) \
	(((rbtiterator)->common.options & DNS_DB_STALEOK) != 0)

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPDB_MAGIC ISC_MAGIC('Q', 'P', 'D', '4')
#define VALID_QPDB(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPDB_MAGIC)

#define HEADERNODE(h) ((qpdata_t *)((h)->node))

/*
 * Allow clients with a virtual time of up to 5 minutes in the past to see
 * records that would have otherwise have expired.
 */
/* #define QPDB_VIRTUAL 300 */
#define QPDB_VIRTUAL 0

/*
 * This defines the number of headers that we try to expire each time the
 * expire_ttl_headers() is run.  The number should be small enough, so the
 * TTL-based header expiration doesn't take too long, but it should be large
 * enough, so we expire enough headers if their TTL is clustered.
 */
#define DNS_QPDB_EXPIRE_TTL_COUNT 10

/*%
 * This is the structure that is used for each node in the qp trie of trees.
 * For now it is a copy of the dns_rbtnode structure.
 */
typedef struct qpdata qpdata_t;
typedef ISC_LIST(qpdata_t) qpdatalist_t;
struct qpdata {
	dns_name_t name;
	isc_mem_t *mctx;

	isc_refcount_t references;
	isc_refcount_t erefs;

	isc_spinlock_t spinlock;

	void *data;

	uint8_t			: 0;
	unsigned int nsec	: 2; /*%< range is 0..3 */
	unsigned int delegating : 1;
	uint8_t dirty		: 1;
	uint8_t			: 0;

	/*%
	 * Used for LRU cache.  This linked list is used to mark nodes which
	 * have no data any longer, but we cannot unlink at that exact moment
	 * because we did not or could not obtain a write lock on the tree.
	 */
	struct cds_wfcq_node deadlink;
};

typedef struct qpdb_changed {
	qpdata_t *node;
	bool dirty;
	ISC_LINK(struct qpdb_changed) link;
} qpdb_changed_t;

typedef ISC_LIST(qpdb_changed_t) qpdb_changedlist_t;

struct dns_qpdb {
	/* Unlocked. */
	dns_db_t common;

	/* Number of the internal references */
	isc_refcount_t references;

	/* Locks the data in this struct */
	isc_mutex_t lock;

	qpdata_t *origin_node;
	dns_stats_t *rrsetstats;     /* cache DB only */
	isc_stats_t *cachestats;     /* cache DB only */
	isc_stats_t *gluecachestats; /* zone DB only */
	/* Locked by lock. */
	unsigned int attributes;
	uint32_t current_serial;
	uint32_t least_serial;
	uint32_t next_serial;
	isc_loop_t *loop;
	dns_dbnode_t *soanode;
	dns_dbnode_t *nsnode;

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	/*%
	 * Temporary storage for stale cache nodes and dynamically deleted
	 * nodes that await being cleaned up.
	 */
	struct {
		struct __cds_wfcq_head head;
		uint8_t __padding[ISC_OS_CACHELINE_SIZE -
				  sizeof(struct __cds_wfcq_head)];
		struct cds_wfcq_tail tail;
		struct rcu_head rcu_head;
	} deadnodes;

	/*
	 * Heaps.  These are used for TTL based expiry in a cache,
	 * or for zone resigning in a zone DB.  hmctx is the memory
	 * context to use for the heap (which differs from the main
	 * database memory context in the case of a cache).
	 */
	isc_mem_t *hmctx;

	isc_mutex_t heaplock;
	/* isc_timer_t *heaptimer; */
	isc_heap_t *heap;

	dns_qpmulti_t *tree; /* Main QP trie for data storage */
	dns_qpmulti_t *nsec; /* NSEC nodes only */

	struct rcu_head rcu_head;
};

/*%
 * Search Context
 */
typedef struct {
	dns_qpdb_t *qpdb;
	uint32_t serial;
	unsigned int options;
	dns_qpchain_t chain;
	dns_qpiter_t iter;
	bool copy_name;
	bool need_cleanup;
	bool wild;
	qpdata_t *zonecut;
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	dns_fixedname_t zonecut_name;
	dns_qpread_t tree;
	dns_qpread_t nsec;
	dns_qpread_t nsec3;
	isc_stdtime_t now;
} qpdb_search_t;

/*%
 * Tree modification context.
 */
typedef struct {
	bool writing;
	dns_qpread_t qpr;
	dns_qp_t *tree;
	dns_qp_t *nsec;
} dbmod_t;

#ifdef DNS_DB_NODETRACE
#define qpdata_ref(ptr)	  qpdata__ref(ptr, __func__, __FILE__, __LINE__)
#define qpdata_unref(ptr) qpdata__unref(ptr, __func__, __FILE__, __LINE__)
#define qpdata_attach(ptr, ptrp) \
	qpdata__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpdata_detach(ptrp) qpdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpdata);
#else
ISC_REFCOUNT_STATIC_DECL(qpdata);
#endif

/* QP methods */
static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	qpdata_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	qpdata_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	qpdata_t *data = pval;
	return (dns_qpkey_fromname(key, &data->name));
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	UNUSED(uctx);
	snprintf(buf, size, "qpdb-lite");
}

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

typedef struct qpdb_rdatasetiter {
	dns_rdatasetiter_t common;
	dns_slabheader_t *current;
} qpdb_rdatasetiter_t;

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG);
static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy, dbiterator_first, dbiterator_last,
	dbiterator_seek,    dbiterator_prev,  dbiterator_next,
	dbiterator_current, dbiterator_pause, dbiterator_origin
};

/*
 * Note that the QP cache database uses only a single QP iterator, because
 * unlike QP zone databases, NSEC3 records are cached in the main tree.
 */
typedef struct qpdb_dbiterator {
	dns_dbiterator_t common;
	isc_result_t result;
	dns_qpsnap_t *tsnap; /* tree snapshot */
	dns_qpiter_t iter;   /* iterator */
	qpdata_t *node;
} qpdb_dbiterator_t;

static dns_dbmethods_t qpdb_cachemethods;

/*%
 * 'init_count' is used to initialize 'newheader->count' which in turn
 * is used to determine where in the cycle rrset-order cyclic starts.
 * We don't lock this as we don't care about simultaneous updates.
 */
static atomic_uint_fast16_t init_count = 0;

/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Tree Lock
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

/*
 * Locking:
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Tree Lock
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 *
 * Deleting Nodes:
 * For zone databases the node for the origin of the zone MUST NOT be deleted.
 */

/*
 * DB Routines
 */

static void
clean_stale_headers(dns_slabheader_t *top) {
	dns_slabheader_t *d = NULL, *down_next = NULL;

	for (d = top->down; d != NULL; d = down_next) {
		down_next = d->down;
		dns_slabheader_destroy(&d);
	}
	top->down = NULL;
}

static void
clean_cache_node(dns_qpdb_t *qpdb, qpdata_t *node) {
	dns_slabheader_t *current = NULL, *top_prev = NULL, *top_next = NULL;

	/*
	 * Caller must be holding the node lock.
	 */

	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;
		clean_stale_headers(current);
		/*
		 * If current is nonexistent, ancient, or stale and
		 * we are not keeping stale, we can clean it up.
		 */
		if (NONEXISTENT(current) || ANCIENT(current) ||
		    (STALE(current) && !KEEPSTALE(qpdb)))
		{
			if (top_prev != NULL) {
				top_prev->next = current->next;
			} else {
				node->data = current->next;
			}
			dns_slabheader_destroy(&current);
		} else {
			top_prev = current;
		}
	}
	node->dirty = 0;
}

static void
delete_node(qpdata_t *node, dbmod_t *modctx) {
	isc_result_t result = ISC_R_UNEXPECTED;

	INSIST(modctx->writing);

	if (isc_log_wouldlog(dns_lctx, ISC_LOG_DEBUG(1))) {
		char printname[DNS_NAME_FORMATSIZE];
		dns_name_format(&node->name, printname, sizeof(printname));
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "delete_node(): %p %s", node, printname);
	}

	switch (node->nsec) {
	case DNS_DB_NSEC_HAS_NSEC:
		/*
		 * Delete the corresponding node from the auxiliary NSEC
		 * tree before deleting from the main tree.
		 */
		result = dns_qp_deletename(modctx->nsec, &node->name, NULL,
					   NULL);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
				      "delete_node(): "
				      "dns_qp_deletename: %s",
				      isc_result_totext(result));
		}
		/* FALLTHROUGH */
	case DNS_DB_NSEC_NORMAL:
		result = dns_qp_deletename(modctx->tree, &node->name, NULL,
					   NULL);
		break;
	case DNS_DB_NSEC_NSEC:
		result = dns_qp_deletename(modctx->nsec, &node->name, NULL,
					   NULL);
		break;
	}
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
			      "delete_node(): "
			      "dns_qp_deletename: %s",
			      isc_result_totext(result));
	}
}

/*
 * Caller must be holding the node lock.
 */
static void
newref(dns_qpdb_t *qpdb, qpdata_t *node DNS__DB_FLARG) {
	uint_fast32_t refs;

	qpdata_ref(node);
	refs = isc_refcount_increment0(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#else
	UNUSED(refs);
#endif

	if (refs == 0) {
		/* this is the first external reference to the node */
		refs = isc_refcount_increment0(&qpdb->references);
#if DNS_DB_NODETRACE
		fprintf(stderr,
			"incr:nodelock:%s:%s:%u:%p:%p->references = "
			"%" PRIuFAST32 "\n",
			func, file, line, node, qpdb, refs + 1);
#else
		UNUSED(refs);
#endif
	}
}

static void
cleanup_dead_nodes(struct rcu_head *rcu_head);

/*
 * Caller must be holding the node lock; either the read or write lock.
 * Note that the lock must be held even when node references are
 * atomically modified; in that case the decrement operation itself does not
 * have to be protected, but we must avoid a race condition where multiple
 * threads are decreasing the reference to zero simultaneously and at least
 * one of them is going to free the node.
 *
 * This decrements both the internal and external node reference counters.
 * If the external reference count drops to zero, then the node lock
 * reference count is also decremented.
 *
 * This function returns true if and only if the node reference decreases
 * to zero.  (NOTE: Decrementing the reference count of a node to zero does
 * not mean it will be immediately freed.)
 */
static uint_fast32_t
decref(dns_qpdb_t *qpdb, qpdata_t *node, bool nlocked,
       dbmod_t *modctx DNS__DB_FLARG) {
	uint_fast32_t refs;

	if (!nlocked) {
		SPINLOCK(&node->spinlock);
	}

#define KEEP_NODE(n, r) ((n)->data != NULL || (n) == (r)->origin_node)

	/* Handle easy and typical case first. */
	if (!node->dirty && KEEP_NODE(node, qpdb)) {
		refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
		fprintf(stderr,
			"decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
			func, file, line, node, refs - 1);
#else
		UNUSED(refs);
#endif
		if (refs == 1) {
			refs = isc_refcount_decrement(&qpdb->references);
#if DNS_DB_NODETRACE
			fprintf(stderr,
				"decr:qpdb:%s:%s:%u:%p:%p->references = "
				"%" PRIuFAST32 "\n",
				func, file, line, node, qpdb, refs - 1);
#endif

		} else {
			refs = isc_refcount_current(&qpdb->references);
		}

		goto unlock;
	}

	refs = isc_refcount_decrement(&node->erefs);
#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif

	if (refs > 1) {
		goto unlock;
	}

	INSIST(refs == 1);

	if (node->dirty) {
		clean_cache_node(qpdb, node);
	}

	refs = isc_refcount_decrement(&qpdb->references);
#if DNS_DB_NODETRACE
	fprintf(stderr,
		"decr:qpdb:%s:%s:%u:%p:%p->references = %" PRIuFAST32 "\n",
		func, file, line, node, qpdb, refs - 1);
#else
	UNUSED(refs);
#endif

	if (KEEP_NODE(node, qpdb)) {
		goto unlock;
	}

	if (modctx != NULL && modctx->writing) {
		/* We can delete the node now. */
		delete_node(node, modctx);
	} else {
		/* We can't delete it now, but add it to deadnodes. */
		INSIST(node->data == NULL);
		cds_wfcq_node_init(&node->deadlink);

		/* The newref() will increment qpdb->references */
		newref(qpdb, node);
		refs++;
		if (!cds_wfcq_enqueue(&qpdb->deadnodes.head,
				      &qpdb->deadnodes.tail, &node->deadlink))
		{
			call_rcu(&qpdb->deadnodes.rcu_head, cleanup_dead_nodes);
		}
	}
#undef KEEP_NODE

unlock:
	if (!nlocked) {
		SPINUNLOCK(&node->spinlock);
	}

	qpdata_unref(node);

	return (refs);
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not delete them because we
 * didn't have the write transaction.
 *
 * The caller must pass a write transaction.
 */
static void
cleanup_dead_nodes(struct rcu_head *rcu_head) {
	dns_qpdb_t *qpdb = caa_container_of(rcu_head, dns_qpdb_t,
					    deadnodes.rcu_head);
	dbmod_t modctx = { .writing = true };
	struct __cds_wfcq_head head;
	struct cds_wfcq_tail tail;

	dns_qpmulti_write(qpdb->tree, &modctx.tree);
	dns_qpmulti_write(qpdb->nsec, &modctx.nsec);

	__cds_wfcq_init(&head, &tail);

	enum cds_wfcq_ret ret = __cds_wfcq_splice_blocking(
		&head, &tail, &qpdb->deadnodes.head, &qpdb->deadnodes.tail);
	INSIST(ret != CDS_WFCQ_RET_WOULDBLOCK);
	if (ret == CDS_WFCQ_RET_SRC_EMPTY) {
		/* Nothing to do, weird. */
		return;
	}

	/*
	 * FIXME: It's possible that the deadnodes list here will be non-empty
	 * but qpdb_destroy() was already called.  In such case, we need to
	 * initiate free_qpdb() from here somehow.  There's rcu_barrier() in the
	 * qpdb_destroy() now, but I don't think it's complete.
	 */
	struct cds_wfcq_node *node, *next;
	__cds_wfcq_for_each_blocking_safe(&head, &tail, node, next) {
		qpdata_t *qpnode = caa_container_of(node, qpdata_t, deadlink);

		qpdata_ref(qpnode);
		SPINLOCK(&qpnode->spinlock);
		decref(qpdb, qpnode, true, &modctx DNS__DB_FLARG_PASS);
		SPINUNLOCK(&qpnode->spinlock);
		qpdata_unref(qpnode);
	}

	dns_qp_compact(modctx.tree, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->tree, &modctx.tree);

	dns_qp_compact(modctx.nsec, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->nsec, &modctx.nsec);
}

static void
update_rrsetstats(dns_stats_t *stats, const dns_typepair_t htype,
		  const uint_least16_t hattributes, const bool increment) {
	dns_rdatastatstype_t statattributes = 0;
	dns_rdatastatstype_t base = 0;
	dns_rdatastatstype_t type;
	dns_slabheader_t *header = &(dns_slabheader_t){
		.type = htype,
		.attributes = hattributes,
	};

	if (!EXISTS(header) || !STATCOUNT(header)) {
		return;
	}

	if (NEGATIVE(header)) {
		if (NXDOMAIN(header)) {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXDOMAIN;
		} else {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXRRSET;
			base = DNS_TYPEPAIR_COVERS(header->type);
		}
	} else {
		base = DNS_TYPEPAIR_TYPE(header->type);
	}

	if (STALE(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_STALE;
	}
	if (ANCIENT(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_ANCIENT;
	}

	type = DNS_RDATASTATSTYPE_VALUE(base, statattributes);
	if (increment) {
		dns_rdatasetstats_increment(stats, type);
	} else {
		dns_rdatasetstats_decrement(stats, type);
	}
}

static void
mark(dns_slabheader_t *header, uint_least16_t flag) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;
	dns_stats_t *stats = NULL;

	/*
	 * If we are already ancient there is nothing to do.
	 */
	do {
		if ((attributes & flag) != 0) {
			return;
		}
		newattributes = attributes | flag;
	} while (!atomic_compare_exchange_weak_acq_rel(
		&header->attributes, &attributes, newattributes));

	/*
	 * Decrement and increment the stats counter for the appropriate
	 * RRtype.
	 */
	stats = dns_db_getrrsetstats(header->db);
	if (stats != NULL) {
		update_rrsetstats(stats, header->type, attributes, false);
		update_rrsetstats(stats, header->type, newattributes, true);
	}
}

static void
newttl(dns_slabheader_t *newheader) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)newheader->db;

	if (newheader) {
		return;
	}

	LOCK(&qpdb->heaplock);
	isc_heap_insert(qpdb->heap, newheader);
	UNLOCK(&qpdb->heaplock);
	newheader->heap = qpdb->heap;
}

static void
setttl(dns_slabheader_t *header, dns_ttl_t newttl) {
	dns_ttl_t oldttl = header->ttl;

	if (header) {
		return;
	}

	header->ttl = newttl;

	if (header->db == NULL || !dns_db_iscache(header->db)) {
		return;
	}

	if (header->heap == NULL || header->heap_index == 0 || newttl == oldttl)
	{
		return;
	}

	dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

	LOCK(&qpdb->heaplock);
	if (newttl < oldttl) {
		isc_heap_increased(header->heap, header->heap_index);
	} else {
		isc_heap_decreased(header->heap, header->heap_index);
	}

	if (newttl == 0) {
		isc_heap_delete(header->heap, header->heap_index);
	}

	dns_slabheader_t *top_header = isc_heap_element(qpdb->heap, 1);
	if (top_header != NULL) {
		isc_stdtime_t now = isc_stdtime_now();
		dns_ttl_t ttl = header->ttl;

		if (isc_mem_isovermem(qpdb->common.mctx)) {
			/* Only account for stale TTL if cache is not overmem */
			ttl += STALE_TTL(header, qpdb);
		}

		if (ttl >= now - QPDB_VIRTUAL) {
			isc_interval_t interval;
			isc_interval_set(&interval, ttl + QPDB_VIRTUAL - now,
					 0);
			/* isc_timer_start(qpdb->heaptimer, isc_timertype_once,
			 */
			/* 		&interval); */
		} else {
			/* isc_timer_start(qpdb->heaptimer, isc_timertype_once,
			 */
			/* 		isc_interval_zero); */
		}
	}
	UNLOCK(&qpdb->heaplock);
}

/*
 * Caller must hold the node (write) lock.
 */
static void
expireheader(dns_slabheader_t *header, dbmod_t *modctx,
	     dns_expire_t reason DNS__DB_FLARG) {
	setttl(header, 0);
	mark(header, DNS_SLABHEADERATTR_ANCIENT);
	HEADERNODE(header)->dirty = 1;

	if (isc_refcount_current(&HEADERNODE(header)->erefs) == 0) {
		dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

		/*
		 * If no one else is using the node, we can clean it up now.
		 * We first need to gain a new reference to the node to meet a
		 * requirement of decref().
		 */
		newref(qpdb, HEADERNODE(header) DNS__DB_FLARG_PASS);
		decref(qpdb, HEADERNODE(header), true,
		       modctx DNS__DB_FLARG_PASS);

		if (qpdb->cachestats == NULL) {
			return;
		}

		switch (reason) {
		case dns_expire_ttl:
			isc_stats_increment(qpdb->cachestats,
					    dns_cachestatscounter_deletettl);
			break;
		case dns_expire_lru:
			isc_stats_increment(qpdb->cachestats,
					    dns_cachestatscounter_deletelru);
			break;
		default:
			break;
		}
	}
}

static void
update_cachestats(dns_qpdb_t *qpdb, isc_result_t result) {
	if (qpdb->cachestats == NULL) {
		return;
	}

	switch (result) {
	case DNS_R_COVERINGNSEC:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_coveringnsec);
		FALLTHROUGH;
	case ISC_R_SUCCESS:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_hits);
		break;
	default:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_misses);
	}
}

static void
bindrdataset(dns_qpdb_t *qpdb, qpdata_t *node, dns_slabheader_t *header,
	     isc_stdtime_t now, dns_rdataset_t *rdataset DNS__DB_FLARG) {
	bool stale = STALE(header);
	bool ancient = ANCIENT(header);

	if (rdataset == NULL) {
		return;
	}

	newref(qpdb, node DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale or ancient if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (KEEPSTALE(qpdb) && stale_ttl > now) {
			stale = true;
		} else {
			/*
			 * We are not keeping stale, or it is outside the
			 * stale window. Mark ancient, i.e. ready for cleanup.
			 */
			ancient = true;
		}
	}

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->type);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->type);
	rdataset->ttl = header->ttl - now;
	rdataset->trust = header->trust;
	rdataset->resign = 0;

	if (NEGATIVE(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NEGATIVE;
	}
	if (NXDOMAIN(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NXDOMAIN;
	}
	if (OPTOUT(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_OPTOUT;
	}
	if (PREFETCH(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_PREFETCH;
	}

	if (stale && !ancient) {
		dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);
		if (stale_ttl > now) {
			rdataset->ttl = stale_ttl - now;
		} else {
			rdataset->ttl = 0;
		}
		if (STALE_WINDOW(header)) {
			rdataset->attributes |= DNS_RDATASETATTR_STALE_WINDOW;
		}
		rdataset->attributes |= DNS_RDATASETATTR_STALE;
	} else if (!ACTIVE(header, now)) {
		rdataset->attributes |= DNS_RDATASETATTR_ANCIENT;
		rdataset->ttl = header->ttl;
	}

	rdataset->count = atomic_fetch_add_relaxed(&header->count, 1);

	rdataset->slab.db = (dns_db_t *)qpdb;
	rdataset->slab.node = (dns_dbnode_t *)node;
	rdataset->slab.raw = dns_slabheader_raw(header);
	rdataset->slab.iter_pos = NULL;
	rdataset->slab.iter_count = 0;

	/*
	 * Add noqname proof.
	 */
	rdataset->slab.noqname = header->noqname;
	if (header->noqname != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_NOQNAME;
	}
	rdataset->slab.closest = header->closest;
	if (header->closest != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_CLOSEST;
	}
}

static isc_result_t
setup_delegation(qpdb_search_t *search, dns_dbnode_t **nodep,
		 dns_name_t *foundname, dns_rdataset_t *rdataset,
		 dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_name_t *zcname = NULL;
	dns_typepair_t type;
	qpdata_t *node = NULL;

	REQUIRE(search != NULL);
	REQUIRE(search->zonecut != NULL);
	REQUIRE(search->zonecut_header != NULL);

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	type = search->zonecut_header->type;

	/*
	 * If we have to set foundname, we do it before anything else.
	 * If we were to set foundname after we had set nodep or bound the
	 * rdataset, then we'd have to undo that work if dns_name_copy()
	 * failed.  By setting foundname first, there's nothing to undo if
	 * we have trouble.
	 */
	if (foundname != NULL && search->copy_name) {
		zcname = dns_fixedname_name(&search->zonecut_name);
		dns_name_copy(zcname, foundname);
	}
	if (nodep != NULL) {
		/*
		 * Note that we don't have to increment the node's reference
		 * count here because we're going to use the reference we
		 * already have in the search block.
		 */
		*nodep = node;
		search->need_cleanup = false;
	}
	if (rdataset != NULL) {
		qpdata_ref(node);
		SPINLOCK(&node->spinlock);
		bindrdataset(search->qpdb, node, search->zonecut_header,
			     search->now, rdataset DNS__DB_FLARG_PASS);
		if (sigrdataset != NULL && search->zonecut_sigheader != NULL) {
			bindrdataset(search->qpdb, node,
				     search->zonecut_sigheader, search->now,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
		SPINUNLOCK(&node->spinlock);
		qpdata_unref(node);
	}

	if (type == dns_rdatatype_dname) {
		return (DNS_R_DNAME);
	}
	return (DNS_R_DELEGATION);
}

static bool
check_stale_header(qpdata_t *node, dns_slabheader_t *header,
		   qpdb_search_t *search, dns_slabheader_t **header_prev) {
	if (!ACTIVE(header, search->now)) {
		dns_ttl_t stale = header->ttl + STALE_TTL(header, search->qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_STALE_WINDOW);
		if (!ZEROTTL(header) && KEEPSTALE(search->qpdb) &&
		    stale > search->now)
		{
			mark(header, DNS_SLABHEADERATTR_STALE);
			*header_prev = header;
			/*
			 * If DNS_DBFIND_STALESTART is set then it means we
			 * failed to resolve the name during recursion, in
			 * this case we mark the time in which the refresh
			 * failed.
			 */
			if ((search->options & DNS_DBFIND_STALESTART) != 0) {
				atomic_store_release(
					&header->last_refresh_fail_ts,
					search->now);
			} else if ((search->options &
				    DNS_DBFIND_STALEENABLED) != 0 &&
				   search->now <
					   (atomic_load_acquire(
						    &header->last_refresh_fail_ts) +
					    search->qpdb->serve_stale_refresh))
			{
				/*
				 * If we are within interval between last
				 * refresh failure time + 'stale-refresh-time',
				 * then don't skip this stale entry but use it
				 * instead.
				 */
				DNS_SLABHEADER_SETATTR(
					header,
					DNS_SLABHEADERATTR_STALE_WINDOW);
				return (false);
			} else if ((search->options &
				    DNS_DBFIND_STALETIMEOUT) != 0)
			{
				/*
				 * We want stale RRset due to timeout, so we
				 * don't skip it.
				 */
				return (false);
			}
			return ((search->options & DNS_DBFIND_STALEOK) == 0);
		}

		/*
		 * This rdataset is stale.  If no one else is using the
		 * node, we can clean it up right now, otherwise we mark
		 * it as ancient, and the node as dirty, so it will get
		 * cleaned up later.
		 */
		if ((header->ttl < search->now - QPDB_VIRTUAL)) {
			/*
			 * We update the node's status only when we can
			 * get write modctx; otherwise, we leave others
			 * to this work.  Periodical cleaning will
			 * eventually take the job as the last resort.
			 * We won't downgrade the lock, since other
			 * rdatasets are probably stale, too.
			 */

			if (isc_refcount_current(&node->references) == 0) {
				/*
				 * header->down can be non-NULL if the
				 * refcount has just decremented to 0
				 * but decref() has not performed
				 * clean_cache_node(), in which case we
				 * need to purge the stale headers first.
				 */
				clean_stale_headers(header);
				if (*header_prev != NULL) {
					(*header_prev)->next = header->next;
				} else {
					node->data = header->next;
				}
				dns_slabheader_destroy(&header);
			} else {
				mark(header, DNS_SLABHEADERATTR_ANCIENT);
				HEADERNODE(header)->dirty = 1;
				*header_prev = header;
			}
		} else {
			*header_prev = header;
		}
		return (true);
	}
	return (false);
}

static isc_result_t
check_zonecut(qpdata_t *node, void *arg DNS__DB_FLARG) {
	qpdb_search_t *search = arg;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *dname_header = NULL, *sigdname_header = NULL;
	isc_result_t result;

	REQUIRE(search->zonecut == NULL);

	SPINLOCK(&node->spinlock);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, search, &header_prev)) {
			/* Do nothing. */
		} else if (header->type == dns_rdatatype_dname &&
			   EXISTS(header) && !ANCIENT(header))
		{
			dname_header = header;
			header_prev = header;
		} else if (header->type == DNS_SIGTYPE(dns_rdatatype_dname) &&
			   EXISTS(header) && !ANCIENT(header))
		{
			sigdname_header = header;
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (dname_header != NULL &&
	    (!DNS_TRUST_PENDING(dname_header->trust) ||
	     (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_header will still be valid later.
		 */
		newref(search->qpdb, node DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = dname_header;
		search->zonecut_sigheader = sigdname_header;
		search->need_cleanup = true;
		result = DNS_R_PARTIALMATCH;
	} else {
		result = DNS_R_CONTINUE;
	}

	SPINUNLOCK(&node->spinlock);

	return (result);
}

static isc_result_t
find_deepest_zonecut(qpdb_search_t *search, qpdata_t *node,
		     dns_dbnode_t **nodep, dns_name_t *foundname,
		     dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_result_t result = ISC_R_NOTFOUND;

	for (int i = dns_qpchain_length(&search->chain) - 1; i >= 0; i--) {
		dns_slabheader_t *header = NULL;
		dns_slabheader_t *header_prev = NULL, *header_next = NULL;
		dns_slabheader_t *found = NULL, *foundsig = NULL;

		dns_qpchain_node(&search->chain, i, NULL, (void **)&node, NULL);

		SPINLOCK(&node->spinlock);

		/*
		 * Look for NS and RRSIG NS rdatasets.
		 */
		for (header = node->data; header != NULL; header = header_next)
		{
			header_next = header->next;
			if (check_stale_header(node, header, search,
					       &header_prev))
			{
				/* Do nothing. */
			} else if (EXISTS(header) && !ANCIENT(header)) {
				/*
				 * We've found an extant rdataset.  See if
				 * we're interested in it.
				 */
				if (header->type == dns_rdatatype_ns) {
					found = header;
					if (foundsig != NULL) {
						break;
					}
				} else if (header->type ==
					   DNS_SIGTYPE(dns_rdatatype_ns))
				{
					foundsig = header;
					if (found != NULL) {
						break;
					}
				}
				header_prev = header;
			} else {
				header_prev = header;
			}
		}

		if (found != NULL) {
			/*
			 * If we have to set foundname, we do it before
			 * anything else.
			 */
			if (foundname != NULL) {
				dns_name_copy(&node->name, foundname);
			}
			result = DNS_R_DELEGATION;
			if (nodep != NULL) {
				newref(search->qpdb, node DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			bindrdataset(search->qpdb, node, found, search->now,
				     rdataset DNS__DB_FLARG_PASS);
			if (foundsig != NULL) {
				bindrdataset(search->qpdb, node, foundsig,
					     search->now,
					     sigrdataset DNS__DB_FLARG_PASS);
			}
		}

		SPINUNLOCK(&node->spinlock);

		if (found != NULL) {
			break;
		}
	}

	return (result);
}

/*
 * Look for a potentially covering NSEC in the cache where `name`
 * is known not to exist.  This uses the auxiliary NSEC tree to find
 * the potential NSEC owner. If found, we update 'foundname', 'nodep',
 * 'rdataset' and 'sigrdataset', and return DNS_R_COVERINGNSEC.
 * Otherwise, return ISC_R_NOTFOUND.
 */
static isc_result_t
find_coveringnsec(qpdb_search_t *search, const dns_name_t *name,
		  dns_dbnode_t **nodep, isc_stdtime_t now,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_fixedname_t fpredecessor, fixed;
	dns_name_t *predecessor = NULL, *fname = NULL;
	qpdata_t *node = NULL;
	dns_qpiter_t iter;
	isc_result_t result;
	dns_typepair_t matchtype, sigmatchtype;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_next = NULL, *header_prev = NULL;

	/*
	 * Look for the node in the auxilary tree.
	 */
	result = dns_qp_lookup(&search->nsec, name, NULL, &iter, NULL,
			       (void **)&node, NULL);
	if (result != DNS_R_PARTIALMATCH) {
		return (ISC_R_NOTFOUND);
	}

	fname = dns_fixedname_initname(&fixed);
	predecessor = dns_fixedname_initname(&fpredecessor);
	matchtype = DNS_TYPEPAIR_VALUE(dns_rdatatype_nsec, 0);
	sigmatchtype = DNS_SIGTYPE(dns_rdatatype_nsec);

	/*
	 * Extract predecessor from iterator.
	 */
	result = dns_qpiter_current(&iter, predecessor, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		return (ISC_R_NOTFOUND);
	}

	/*
	 * Lookup the predecessor in the main tree.
	 */
	node = NULL;
	result = dns_qp_lookup(&search->tree, predecessor, fname, NULL, NULL,
			       (void **)&node, NULL);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_NOTFOUND);
	}

	SPINLOCK(&node->spinlock);
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, search, &header_prev)) {
			continue;
		}
		if (NONEXISTENT(header) || DNS_TYPEPAIR_TYPE(header->type) == 0)
		{
			header_prev = header;
			continue;
		}
		if (header->type == matchtype) {
			found = header;
			if (foundsig != NULL) {
				break;
			}
		} else if (header->type == sigmatchtype) {
			foundsig = header;
			if (found != NULL) {
				break;
			}
		}
		header_prev = header;
	}
	if (found != NULL) {
		bindrdataset(search->qpdb, node, found, now,
			     rdataset DNS__DB_FLARG_PASS);
		if (foundsig != NULL) {
			bindrdataset(search->qpdb, node, foundsig, now,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
		newref(search->qpdb, node DNS__DB_FLARG_PASS);

		dns_name_copy(fname, foundname);

		*nodep = node;
		result = DNS_R_COVERINGNSEC;
	} else {
		result = ISC_R_NOTFOUND;
	}
	SPINUNLOCK(&node->spinlock);

	return (result);
}

static isc_result_t
find(dns_db_t *db, const dns_name_t *name,
     dns_dbversion_t *version ISC_ATTR_UNUSED, dns_rdatatype_t type,
     unsigned int options, isc_stdtime_t now, dns_dbnode_t **nodep,
     dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpdata_t *node = NULL;
	isc_result_t result;
	qpdb_search_t search;
	bool cname_ok = true;
	bool found_noqname = false;
	bool all_negative = true;
	bool empty_node;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *nsheader = NULL;
	dns_slabheader_t *foundsig = NULL, *nssig = NULL, *cnamesig = NULL;
	dns_slabheader_t *nsecheader = NULL, *nsecsig = NULL;
	dns_typepair_t sigtype, negtype;

	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	search = (qpdb_search_t){
		.qpdb = (dns_qpdb_t *)db,
		.serial = 1,
		.options = options,
		.now = now,
	};
	dns_fixedname_init(&search.zonecut_name);

	dns_qpmulti_query(search.qpdb->tree, &search.tree);
	dns_qpmulti_query(search.qpdb->nsec, &search.nsec);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(&search.tree, name, foundname, NULL,
			       &search.chain, (void **)&node, NULL);

	/*
	 * Check the QP chain to see if there's a node above us with a
	 * active DNAME or NS rdatasets.
	 *
	 * We're only interested in nodes above QNAME, so if the result
	 * was success, then we skip the last item in the chain.
	 */
	unsigned int len = dns_qpchain_length(&search.chain);
	if (result == ISC_R_SUCCESS) {
		len--;
	}

	for (unsigned int i = 0; i < len; i++) {
		isc_result_t zcresult;
		qpdata_t *encloser = NULL;

		dns_qpchain_node(&search.chain, i, NULL, (void **)&encloser,
				 NULL);

		if (encloser->delegating) {
			zcresult = check_zonecut(
				encloser, (void *)&search DNS__DB_FLARG_PASS);
			if (zcresult != DNS_R_CONTINUE) {
				result = DNS_R_PARTIALMATCH;
				search.chain.len = i - 1;
				node = encloser;
				break;
			}
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		/*
		 * If we discovered a covering DNAME skip looking for a covering
		 * NSEC.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    (search.zonecut_header == NULL ||
		     search.zonecut_header->type != dns_rdatatype_dname))
		{
			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		if (search.zonecut != NULL) {
			result = setup_delegation(
				&search, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		} else {
		find_ns:
			result = find_deepest_zonecut(
				&search, node, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		}
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5 and RFC3007).
	 *
	 * We don't check for RRSIG, because we don't store RRSIG records
	 * directly.
	 */
	if (type == dns_rdatatype_key || type == dns_rdatatype_nsec) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	SPINLOCK(&node->spinlock);

	/*
	 * These pointers need to be reset here in case we did
	 * 'goto find_ns' from somewhere below.
	 */
	found = NULL;
	foundsig = NULL;
	sigtype = DNS_SIGTYPE(type);
	negtype = DNS_TYPEPAIR_VALUE(0, type);
	nsheader = NULL;
	nsecheader = NULL;
	nssig = NULL;
	nsecsig = NULL;
	cnamesig = NULL;
	empty_node = true;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &search, &header_prev)) {
			/* Do nothing. */
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * We now know that there is at least one active
			 * non-stale rdataset at this node.
			 */
			empty_node = false;
			if (header->noqname != NULL &&
			    header->trust == dns_trust_secure)
			{
				found_noqname = true;
			}
			if (!NEGATIVE(header)) {
				all_negative = false;
			}

			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == type ||
			    (type == dns_rdatatype_any &&
			     DNS_TYPEPAIR_TYPE(header->type) != 0) ||
			    (cname_ok && header->type == dns_rdatatype_cname))
			{
				/*
				 * We've found the answer.
				 */
				found = header;
				if (header->type == dns_rdatatype_cname &&
				    cname_ok)
				{
					/*
					 * If we've already got the
					 * CNAME RRSIG, use it.
					 */
					if (cnamesig != NULL) {
						foundsig = cnamesig;
					} else {
						sigtype = DNS_SIGTYPE(
							dns_rdatatype_cname);
					}
				}
			} else if (header->type == sigtype) {
				/*
				 * We've found the RRSIG rdataset for our
				 * target type.  Remember it.
				 */
				foundsig = header;
			} else if (header->type == RDATATYPE_NCACHEANY ||
				   header->type == negtype)
			{
				/*
				 * We've found a negative cache entry.
				 */
				found = header;
			} else if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nsheader = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_ns))
			{
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				nssig = header;
			} else if (header->type == dns_rdatatype_nsec) {
				nsecheader = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_nsec))
			{
				nsecsig = header;
			} else if (cname_ok &&
				   header->type ==
					   DNS_SIGTYPE(dns_rdatatype_cname))
			{
				/*
				 * If we get a CNAME match, we'll also need
				 * its signature.
				 */
				cnamesig = header;
			}
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		SPINUNLOCK(&node->spinlock);

		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0) {
			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		goto find_ns;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL ||
	    (DNS_TRUST_ADDITIONAL(found->trust) &&
	     ((options & DNS_DBFIND_ADDITIONALOK) == 0)) ||
	    (found->trust == dns_trust_glue &&
	     ((options & DNS_DBFIND_GLUEOK) == 0)) ||
	    (DNS_TRUST_PENDING(found->trust) &&
	     ((options & DNS_DBFIND_PENDINGOK) == 0)))
	{
		/*
		 * Return covering NODATA NSEC record.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    nsecheader != NULL)
		{
			if (nodep != NULL) {
				newref(search.qpdb, node DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			bindrdataset(search.qpdb, node, nsecheader, search.now,
				     rdataset DNS__DB_FLARG_PASS);
			if (nsecsig != NULL) {
				bindrdataset(search.qpdb, node, nsecsig,
					     search.now,
					     sigrdataset DNS__DB_FLARG_PASS);
			}
			result = DNS_R_COVERINGNSEC;
			goto node_exit;
		}

		/*
		 * This name was from a wild card.  Look for a covering NSEC.
		 */
		if (found == NULL && (found_noqname || all_negative) &&
		    (search.options & DNS_DBFIND_COVERINGNSEC) != 0)
		{
			SPINUNLOCK(&node->spinlock);

			result = find_coveringnsec(
				&search, name, nodep, now, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
			goto find_ns;
		}

		/*
		 * If there is an NS rdataset at this node, then this is the
		 * deepest zone cut.
		 */
		if (nsheader != NULL) {
			if (nodep != NULL) {
				newref(search.qpdb, node DNS__DB_FLARG_PASS);
				*nodep = node;
			}
			bindrdataset(search.qpdb, node, nsheader, search.now,
				     rdataset DNS__DB_FLARG_PASS);
			if (nssig != NULL) {
				bindrdataset(search.qpdb, node, nssig,
					     search.now,
					     sigrdataset DNS__DB_FLARG_PASS);
			}
			result = DNS_R_DELEGATION;
			goto node_exit;
		}

		/*
		 * Go find the deepest zone cut.
		 */
		SPINUNLOCK(&node->spinlock);

		goto find_ns;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		newref(search.qpdb, node DNS__DB_FLARG_PASS);
		*nodep = node;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	} else if (type != found->type && type != dns_rdatatype_any &&
		   found->type == dns_rdatatype_cname)
	{
		/*
		 * We weren't doing an ANY query and we found a CNAME instead
		 * of the type we were looking for, so we need to indicate
		 * that result to the caller.
		 */
		result = DNS_R_CNAME;
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = ISC_R_SUCCESS;
	}

	if (type != dns_rdatatype_any || result == DNS_R_NCACHENXDOMAIN ||
	    result == DNS_R_NCACHENXRRSET)
	{
		bindrdataset(search.qpdb, node, found, search.now,
			     rdataset DNS__DB_FLARG_PASS);
		if (!NEGATIVE(found) && foundsig != NULL) {
			bindrdataset(search.qpdb, node, foundsig, search.now,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

node_exit:
	SPINUNLOCK(&node->spinlock);

tree_exit:
	dns_qpread_destroy(search.qpdb->tree, &search.tree);
	dns_qpread_destroy(search.qpdb->nsec, &search.nsec);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);

		qpdata_ref(node);
		SPINLOCK(&node->spinlock);
		decref(search.qpdb, node, true, NULL DNS__DB_FLARG_PASS);
		SPINUNLOCK(&node->spinlock);
		qpdata_unref(node);
	}

	update_cachestats(search.qpdb, result);
	return (result);
}

static isc_result_t
findzonecut(dns_db_t *db, const dns_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
	    dns_name_t *dcname, dns_rdataset_t *rdataset,
	    dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpdata_t *node = NULL;
	isc_result_t result;
	qpdb_search_t search;
	dns_slabheader_t *header = NULL;
	dns_slabheader_t *header_prev = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	bool dcnull = (dcname == NULL);

	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	search = (qpdb_search_t){
		.qpdb = (dns_qpdb_t *)db,
		.serial = 1,
		.options = options,
		.now = now,
	};
	dns_fixedname_init(&search.zonecut_name);

	dns_qpmulti_query(search.qpdb->tree, &search.tree);

	if (dcnull) {
		dcname = foundname;
	}

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_qp_lookup(&search.tree, name, dcname, NULL, &search.chain,
			       (void **)&node, NULL);
	if ((options & DNS_DBFIND_NOEXACT) != 0 && result == ISC_R_SUCCESS) {
		int len = dns_qpchain_length(&search.chain);
		if (len >= 2) {
			node = NULL;
			dns_qpchain_node(&search.chain, len - 2, NULL,
					 (void **)&node, NULL);
			search.chain.len = len - 1;
			result = DNS_R_PARTIALMATCH;
		} else {
			result = ISC_R_NOTFOUND;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset,
					      sigrdataset DNS__DB_FLARG_PASS);
		goto tree_exit;
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	} else if (!dcnull) {
		dns_name_copy(dcname, foundname);
	}

	/*
	 * We now go looking for an NS rdataset at the node.
	 */

	SPINLOCK(&node->spinlock);

	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &search, &header_prev)) {
			/*
			 * The function dns_qp_lookup found us a matching
			 * node for 'name' and stored the result in 'dcname'.
			 * This is the deepest known zonecut in our database.
			 * However, this node may be stale and if serve-stale
			 * is not enabled (in other words 'stale-answer-enable'
			 * is set to no), this node may not be used as a
			 * zonecut we know about. If so, find the deepest
			 * zonecut from this node up and return that instead.
			 */
			SPINUNLOCK(&node->spinlock);
			result = find_deepest_zonecut(
				&search, node, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			dns_name_copy(foundname, dcname);
			goto tree_exit;
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				found = header;
			} else if (header->type ==
				   DNS_SIGTYPE(dns_rdatatype_ns))
			{
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				foundsig = header;
			}
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (found == NULL) {
		/*
		 * No NS records here.
		 */
		SPINUNLOCK(&node->spinlock);
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset,
					      sigrdataset DNS__DB_FLARG_PASS);
		goto tree_exit;
	}

	if (nodep != NULL) {
		newref(search.qpdb, node DNS__DB_FLARG_PASS);
		*nodep = node;
	}

	bindrdataset(search.qpdb, node, found, search.now,
		     rdataset DNS__DB_FLARG_PASS);
	if (foundsig != NULL) {
		bindrdataset(search.qpdb, node, foundsig, search.now,
			     sigrdataset DNS__DB_FLARG_PASS);
	}

	SPINUNLOCK(&node->spinlock);

tree_exit:
	dns_qpread_destroy(search.qpdb->tree, &search.tree);

	INSIST(!search.need_cleanup);

	if (result == DNS_R_DELEGATION) {
		result = ISC_R_SUCCESS;
	}

	return (result);
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *qpnode = (qpdata_t *)node;
	dns_slabheader_t *header = NULL, *header_next = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_typepair_t matchtype, sigmatchtype, negtype;
	isc_result_t result;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(type != dns_rdatatype_any);

	UNUSED(version);

	result = ISC_R_SUCCESS;

	if (now == 0) {
		now = isc_stdtime_now();
	}

	SPINLOCK(&qpnode->spinlock);

	matchtype = DNS_TYPEPAIR_VALUE(type, covers);
	negtype = DNS_TYPEPAIR_VALUE(0, type);
	if (covers == 0) {
		sigmatchtype = DNS_SIGTYPE(type);
	} else {
		sigmatchtype = 0;
	}

	for (header = qpnode->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (!ACTIVE(header, now)) {
			if ((header->ttl + STALE_TTL(header, qpdb) <
			     now - QPDB_VIRTUAL))
			{
				/*
				 * We update the node's status only when we
				 * can get write modctx.
				 *
				 * We don't check if refcurrent(qpnode) == 0
				 * and try to free like we do in find(),
				 * because refcurrent(qpnode) must be
				 * non-zero.  This is so because 'node' is an
				 * argument to the function.
				 */
				mark(header, DNS_SLABHEADERATTR_ANCIENT);
				HEADERNODE(header)->dirty = 1;
			}
		} else if (EXISTS(header) && !ANCIENT(header)) {
			if (header->type == matchtype) {
				found = header;
			} else if (header->type == RDATATYPE_NCACHEANY ||
				   header->type == negtype)
			{
				found = header;
			} else if (header->type == sigmatchtype) {
				foundsig = header;
			}
		}
	}
	if (found != NULL) {
		bindrdataset(qpdb, qpnode, found, now,
			     rdataset DNS__DB_FLARG_PASS);
		if (!NEGATIVE(found) && foundsig != NULL) {
			bindrdataset(qpdb, qpnode, foundsig, now,
				     sigrdataset DNS__DB_FLARG_PASS);
		}
	}

	SPINUNLOCK(&qpnode->spinlock);

	if (found == NULL) {
		return (ISC_R_NOTFOUND);
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	}

	update_cachestats(qpdb, result);

	return (result);
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &qpdb->cachestats);
	return (ISC_R_SUCCESS);
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	return (qpdb->rrsetstats);
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->common.serve_stale_ttl = ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*ttl = qpdb->common.serve_stale_ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->serve_stale_refresh = interval;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*interval = qpdb->serve_stale_refresh;
	return (ISC_R_SUCCESS);
}

static void
expiredata(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node, void *data) {
	qpdata_t *qpnode = (qpdata_t *)node;
	dns_slabheader_t *header = data;

	SPINLOCK(&qpnode->spinlock);
	expireheader(header, false, dns_expire_flush DNS__DB_FILELINE);
	SPINUNLOCK(&qpnode->spinlock);
}

static bool
prio_type(dns_typepair_t type) {
	switch (type) {
	case dns_rdatatype_soa:
	case DNS_SIGTYPE(dns_rdatatype_soa):
	case dns_rdatatype_a:
	case DNS_SIGTYPE(dns_rdatatype_a):
	case dns_rdatatype_aaaa:
	case DNS_SIGTYPE(dns_rdatatype_aaaa):
	case dns_rdatatype_nsec:
	case DNS_SIGTYPE(dns_rdatatype_nsec):
	case dns_rdatatype_nsec3:
	case DNS_SIGTYPE(dns_rdatatype_nsec3):
	case dns_rdatatype_ns:
	case DNS_SIGTYPE(dns_rdatatype_ns):
	case dns_rdatatype_ds:
	case DNS_SIGTYPE(dns_rdatatype_ds):
	case dns_rdatatype_cname:
	case DNS_SIGTYPE(dns_rdatatype_cname):
		return (true);
	}
	return (false);
}

/*%
 * These functions allow the heap code to rank the priority of each
 * element.  It returns true if v1 happens "sooner" than v2.
 */
static bool
ttl_sooner(void *v1, void *v2) {
	dns_slabheader_t *h1 = v1;
	dns_slabheader_t *h2 = v2;

	return (h1->ttl < h2->ttl);
}

/*%
 * This function sets the heap index into the header.
 */
static void
set_index(void *what, unsigned int idx) {
	dns_slabheader_t *h = what;

	h->heap_index = idx;
}

static void
free_qpdb_rcu(struct rcu_head *rcu_head) {
	dns_qpdb_t *qpdb = caa_container_of(rcu_head, dns_qpdb_t, rcu_head);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}

	/*
	 * Clean up heap objects.
	 */
	isc_heap_destroy(&qpdb->heap);
	isc_mutex_destroy(&qpdb->heaplock);

	if (qpdb->rrsetstats != NULL) {
		dns_stats_detach(&qpdb->rrsetstats);
	}
	if (qpdb->cachestats != NULL) {
		isc_stats_detach(&qpdb->cachestats);
	}
	if (qpdb->gluecachestats != NULL) {
		isc_stats_detach(&qpdb->gluecachestats);
	}

	isc_refcount_destroy(&qpdb->references);
	isc_refcount_destroy(&qpdb->common.references);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
		/* isc_timer_destroy(&qpdb->heaptimer); */
	}

	isc_mutex_destroy(&qpdb->lock);
	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;
	isc_mem_detach(&qpdb->hmctx);

	if (qpdb->common.update_listeners != NULL) {
		INSIST(!cds_lfht_destroy(qpdb->common.update_listeners, NULL));
	}

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb, sizeof(*qpdb));
}

static void
free_qpdb(dns_qpdb_t *qpdb, bool log) {
	char buf[DNS_NAME_FORMATSIZE];

	dns_qpmulti_destroy(&qpdb->tree);
	dns_qpmulti_destroy(&qpdb->nsec);

	if (log) {
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "done free_qpdb(%s)", buf);
	}

	call_rcu(&qpdb->rcu_head, free_qpdb_rcu);
}

static void
qpdb_destroy(dns_db_t *arg) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)arg;

	rcu_barrier();

	if (qpdb->origin_node != NULL) {
		qpdata_detach(&qpdb->origin_node);
	}

	/* XXX check for open versions here */

	if (qpdb->soanode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->soanode);
	}
	if (qpdb->nsnode != NULL) {
		dns_db_detachnode((dns_db_t *)qpdb, &qpdb->nsnode);
	}

	/*
	 * Even though there are no external direct references, there still
	 * may be nodes in use.
	 */

	if (isc_refcount_decrement(&qpdb->references) == 1) {
		char buf[DNS_NAME_FORMATSIZE];
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "calling free_qpdb(%s)", buf);
		free_qpdb(qpdb, true);
	}
}

static void
mark_ancient(dns_slabheader_t *header) {
	setttl(header, 0);
	mark(header, DNS_SLABHEADERATTR_ANCIENT);
	HEADERNODE(header)->dirty = 1;
}

/*
 * This function is assumed to be called when a node is newly referenced
 * and can be in the deadnode list.  In that case the node must be retrieved
 * from the list because it is going to be used.  In addition, if the caller
 * happens to have a write transaction, we could cleanup the dead nodes.
 *
 * Note: while a new reference is gained in multiple places, there are only very
 * few cases where the node can be in the deadnode list (only empty nodes can
 * have been added to the list).
 */
static void
reactivate_node(dns_qpdb_t *qpdb, qpdata_t *node DNS__DB_FLARG) {
	/* Reactive the node first in case it's already on the dead list */
	SPINLOCK(&node->spinlock);
	newref(qpdb, node DNS__DB_FLARG_PASS);
	SPINUNLOCK(&node->spinlock);
}

static qpdata_t *
new_qpdata(dns_qpdb_t *qpdb, const dns_name_t *name) {
	qpdata_t *newdata = isc_mem_get(qpdb->common.mctx, sizeof(*newdata));
	*newdata = (qpdata_t){
		.name = DNS_NAME_INITEMPTY,
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	isc_spinlock_init(&newdata->spinlock);

	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);
	dns_name_dupwithoffsets(name, newdata->mctx, &newdata->name);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "new_qpdata:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return (newdata);
}

static isc_result_t
findnode(dns_db_t *db, const dns_name_t *name, bool create,
	 dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *node = NULL;
	isc_result_t result;
	dns_qpread_t qpr = { 0 };
	dns_qp_t *qp = NULL;

	if (create) {
		dns_qpmulti_write(qpdb->tree, &qp);
	} else {
		dns_qpmulti_query(qpdb->tree, &qpr);
		qp = (dns_qp_t *)&qpr;
	}

	result = dns_qp_lookup(qp, name, NULL, NULL, NULL, (void **)&node,
			       NULL);
	if (result != ISC_R_SUCCESS) {
		if (!create) {
			if (result == DNS_R_PARTIALMATCH) {
				result = ISC_R_NOTFOUND;
			}
			dns_qpread_destroy(qpdb->tree, &qpr);
			return (result);
		}

		result = dns_qp_lookup(qp, name, NULL, NULL, NULL,
				       (void **)&node, NULL);
		if (result != ISC_R_SUCCESS) {
			node = new_qpdata(qpdb, name);
			result = dns_qp_insert(qp, node, 0);
			INSIST(result == ISC_R_SUCCESS);
			qpdata_unref(node);
		}
	}

	reactivate_node(qpdb, node DNS__DB_FLARG_PASS);

	if (create) {
		dns_qp_compact(qp, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &qp);
	} else {
		dns_qpread_destroy(qpdb->tree, &qpr);
	}

	*nodep = (dns_dbnode_t *)node;

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source,
	   dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(VALID_QPDB((dns_qpdb_t *)db));
	REQUIRE(targetp != NULL && *targetp == NULL);

	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *node = (qpdata_t *)source;

	newref(qpdb, node DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *node = NULL;
	uint_fast32_t refs;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (qpdata_t *)(*targetp);

	qpdata_ref(node);
	SPINLOCK(&node->spinlock);
	refs = decref(qpdb, node, true, NULL DNS__DB_FLARG_PASS);
	SPINUNLOCK(&node->spinlock);
	qpdata_unref(node);

	*targetp = NULL;

	if (refs == 1) {
		char buf[DNS_NAME_FORMATSIZE];
		if (dns_name_dynamic(&qpdb->common.origin)) {
			dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "calling free_qpdb(%s)", buf);
		free_qpdb(qpdb, true);
	}
}

static isc_result_t
createiterator(dns_db_t *db, unsigned int options ISC_ATTR_UNUSED,
	       dns_dbiterator_t **iteratorp) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdb_dbiterator_t *qpdbiter = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	qpdbiter = isc_mem_get(qpdb->common.mctx, sizeof(*qpdbiter));
	*qpdbiter = (qpdb_dbiterator_t){
		.common.methods = &dbiterator_methods,
		.common.magic = DNS_DBITERATOR_MAGIC,
	};

	dns_db_attach(db, &qpdbiter->common.db);

	dns_qpmulti_snapshot(qpdb->tree, &qpdbiter->tsnap);
	dns_qpiter_init(qpdbiter->tsnap, &qpdbiter->iter);

	*iteratorp = (dns_dbiterator_t *)qpdbiter;
	return (ISC_R_SUCCESS);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     unsigned int options, isc_stdtime_t now,
	     dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *qpnode = (qpdata_t *)node;
	qpdb_rdatasetiter_t *iterator = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	UNUSED(version);

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = NULL;
	iterator->common.options = options;
	iterator->common.now = now;
	iterator->current = NULL;

	newref(qpdb, qpnode DNS__DB_FLARG_PASS);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static isc_result_t
add(dns_qpdb_t *qpdb, qpdata_t *qpnode,
    const dns_name_t *nodename ISC_ATTR_UNUSED, dns_slabheader_t *newheader,
    unsigned int options, bool loading, dns_rdataset_t *addedrdataset,
    isc_stdtime_t now DNS__DB_FLARG) {
	qpdb_changed_t *changed = NULL;
	dns_slabheader_t *topheader = NULL, *topheader_prev = NULL;
	dns_slabheader_t *header = NULL, *sigheader = NULL;
	dns_slabheader_t *prioheader = NULL;
	bool header_nx;
	bool newheader_nx;
	dns_rdatatype_t rdtype, covers;
	dns_typepair_t negtype = 0, sigtype;
	dns_trust_t trust;

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	newheader_nx = NONEXISTENT(newheader) ? true : false;
	if (!newheader_nx) {
		rdtype = DNS_TYPEPAIR_TYPE(newheader->type);
		covers = DNS_TYPEPAIR_COVERS(newheader->type);
		sigtype = DNS_SIGTYPE(covers);
		if (NEGATIVE(newheader)) {
			/*
			 * We're adding a negative cache entry.
			 */
			if (covers == dns_rdatatype_any) {
				/*
				 * If we're adding an negative cache entry
				 * which covers all types (NXDOMAIN,
				 * NODATA(QTYPE=ANY)),
				 *
				 * We make all other data ancient so that the
				 * only rdataset that can be found at this
				 * node is the negative cache entry.
				 */
				for (topheader = qpnode->data;
				     topheader != NULL;
				     topheader = topheader->next)
				{
					mark_ancient(topheader);
				}
				goto find_header;
			}
			/*
			 * Otherwise look for any RRSIGs of the given
			 * type so they can be marked ancient later.
			 */
			for (topheader = qpnode->data; topheader != NULL;
			     topheader = topheader->next)
			{
				if (topheader->type == sigtype) {
					sigheader = topheader;
				}
			}
			negtype = DNS_TYPEPAIR_VALUE(covers, 0);
		} else {
			/*
			 * We're adding something that isn't a
			 * negative cache entry.  Look for an extant
			 * non-ancient NXDOMAIN/NODATA(QTYPE=ANY) negative
			 * cache entry.  If we're adding an RRSIG, also
			 * check for an extant non-ancient NODATA ncache
			 * entry which covers the same type as the RRSIG.
			 */
			for (topheader = qpnode->data; topheader != NULL;
			     topheader = topheader->next)
			{
				if ((topheader->type == RDATATYPE_NCACHEANY) ||
				    (newheader->type == sigtype &&
				     topheader->type ==
					     DNS_TYPEPAIR_VALUE(0, covers)))
				{
					break;
				}
			}
			if (topheader != NULL && EXISTS(topheader) &&
			    ACTIVE(topheader, now))
			{
				/*
				 * Found one.
				 */
				if (trust < topheader->trust) {
					/*
					 * The NXDOMAIN/NODATA(QTYPE=ANY)
					 * is more trusted.
					 */
					dns_slabheader_destroy(&newheader);
					if (addedrdataset != NULL) {
						bindrdataset(
							qpdb, qpnode, topheader,
							now,
							addedrdataset
								DNS__DB_FLARG_PASS);
					}
					return (DNS_R_UNCHANGED);
				}
				/*
				 * The new rdataset is better.  Expire the
				 * ncache entry.
				 */
				mark_ancient(topheader);
				topheader = NULL;
				goto find_header;
			}
			negtype = DNS_TYPEPAIR_VALUE(0, rdtype);
		}
	}

	for (topheader = qpnode->data; topheader != NULL;
	     topheader = topheader->next)
	{
		if (prio_type(topheader->type)) {
			prioheader = topheader;
		}
		if (topheader->type == newheader->type ||
		    topheader->type == negtype)
		{
			break;
		}
		topheader_prev = topheader;
	}

find_header:
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
	if (header != NULL) {
		header_nx = NONEXISTENT(header) ? true : false;

		/*
		 * Deleting an already non-existent rdataset has no effect.
		 */
		if (header_nx && newheader_nx) {
			dns_slabheader_destroy(&newheader);
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		if (trust < header->trust && (ACTIVE(header, now) || header_nx))
		{
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				bindrdataset(qpdb, qpnode, header, now,
					     addedrdataset DNS__DB_FLARG_PASS);
			}
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Don't replace existing NS, A and AAAA RRsets in the
		 * cache if they are already exist. This prevents named
		 * being locked to old servers. Don't lower trust of
		 * existing record if the update is forced. Nothing
		 * special to be done w.r.t stale data; it gets replaced
		 * normally further down.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equalx((unsigned char *)header,
					 (unsigned char *)newheader,
					 (unsigned int)(sizeof(*newheader)),
					 qpdb->common.rdclass,
					 (dns_rdatatype_t)header->type))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->ttl > newheader->ttl) {
				setttl(header, newheader->ttl);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL)
			{
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				bindrdataset(qpdb, qpnode, header, now,
					     addedrdataset DNS__DB_FLARG_PASS);
			}
			return (ISC_R_SUCCESS);
		}

		/*
		 * If we have will be replacing a NS RRset force its TTL
		 * to be no more than the current NS RRset's TTL.  This
		 * ensures the delegations that are withdrawn are honoured.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust <= newheader->trust)
		{
			if (newheader->ttl > header->ttl) {
				newheader->ttl = header->ttl;
			}
		}
		if (ACTIVE(header, now) &&
		    (options & DNS_DBADD_PREFETCH) == 0 &&
		    (header->type == dns_rdatatype_a ||
		     header->type == dns_rdatatype_aaaa ||
		     header->type == dns_rdatatype_ds ||
		     header->type == DNS_SIGTYPE(dns_rdatatype_ds)) &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equal((unsigned char *)header,
					(unsigned char *)newheader,
					(unsigned int)(sizeof(*newheader))))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->ttl > newheader->ttl) {
				setttl(header, newheader->ttl);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL)
			{
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			dns_slabheader_destroy(&newheader);
			if (addedrdataset != NULL) {
				bindrdataset(qpdb, qpnode, header, now,
					     addedrdataset DNS__DB_FLARG_PASS);
			}
			return (ISC_R_SUCCESS);
		}

		if (loading) {
			newheader->down = NULL;

			newttl(newheader);

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			dns_slabheader_destroy(&header);
		} else {
			newttl(newheader);

			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			qpnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
			mark_ancient(header);
			if (sigheader != NULL) {
				mark_ancient(sigheader);
			}
		}
	} else {
		/*
		 * No non-IGNORED rdatasets of the given type exist at
		 * this node.
		 */

		/*
		 * If we're trying to delete the type, don't bother.
		 */
		if (newheader_nx) {
			dns_slabheader_destroy(&newheader);
			return (DNS_R_UNCHANGED);
		}

		newttl(newheader);

		if (topheader != NULL) {
			/*
			 * We have an list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				qpnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			qpnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */
			INSIST(newheader->down == NULL);

			if (prio_type(newheader->type)) {
				/* This is a priority type, prepend it */
				newheader->next = qpnode->data;
				qpnode->data = newheader;
			} else if (prioheader != NULL) {
				/* Append after the priority headers */
				newheader->next = prioheader->next;
				prioheader->next = newheader;
			} else {
				/* There were no priority headers */
				newheader->next = qpnode->data;
				qpnode->data = newheader;
			}
		}
	}

	if (addedrdataset != NULL) {
		bindrdataset(qpdb, qpnode, newheader, now,
			     addedrdataset DNS__DB_FLARG_PASS);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
addnoqname(isc_mem_t *mctx, dns_slabheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *noqname = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1, r2;

	result = dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_rdataslab_fromrdataset(&neg, mctx, &r1, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r2, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	noqname = isc_mem_get(mctx, sizeof(*noqname));
	*noqname = (dns_slabheader_proof_t){
		.neg = r1.base,
		.negsig = r2.base,
		.type = neg.type,
		.name = DNS_NAME_INITEMPTY,
	};
	dns_name_dup(&name, mctx, &noqname->name);
	newheader->noqname = noqname;

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);

	return (result);
}

static isc_result_t
addclosest(isc_mem_t *mctx, dns_slabheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *closest = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1, r2;

	result = dns_rdataset_getclosest(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_rdataslab_fromrdataset(&neg, mctx, &r1, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r2, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	closest = isc_mem_get(mctx, sizeof(*closest));
	*closest = (dns_slabheader_proof_t){
		.neg = r1.base,
		.negsig = r2.base,
		.name = DNS_NAME_INITEMPTY,
		.type = neg.type,
	};
	dns_name_dup(&name, mctx, &closest->name);
	newheader->closest = closest;

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	return (result);
}

static void
expire_ttl_headers(void *arg);

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node,
	    dns_dbversion_t *version ISC_ATTR_UNUSED, isc_stdtime_t now,
	    dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *qpnode = (qpdata_t *)node;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	bool delegating = false;
	bool newnsec = false;
	bool cache_is_overmem = false;
	bool writing = false;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	dbmod_t modctx;

	REQUIRE(VALID_QPDB(qpdb));

	if (now == 0) {
		now = isc_stdtime_now();
	}

	result = dns_rdataslab_fromrdataset(rdataset, qpdb->common.mctx,
					    &region, sizeof(dns_slabheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(&qpnode->name, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (dns_slabheader_t *)region.base;
	*newheader = (dns_slabheader_t){
		.type = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers),
		.trust = rdataset->trust,
		.node = qpnode,
	};

	dns_slabheader_reset(newheader, db, node);
	setttl(newheader, rdataset->ttl + now);
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->serial = 1;
	if ((rdataset->attributes & DNS_RDATASETATTR_PREFETCH) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_PREFETCH);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NEGATIVE);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NXDOMAIN) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NXDOMAIN);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_OPTOUT) != 0) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_OPTOUT);
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_NOQNAME) != 0) {
		result = addnoqname(qpdb->common.mctx, newheader, rdataset);
		if (result != ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			return (result);
		}
	}
	if ((rdataset->attributes & DNS_RDATASETATTR_CLOSEST) != 0) {
		result = addclosest(qpdb->common.mctx, newheader, rdataset);
		if (result != ISC_R_SUCCESS) {
			dns_slabheader_destroy(&newheader);
			return (result);
		}
	}

	/*
	 * If we're adding a delegation type (which would be an NS or DNAME
	 * for a zone, but only DNAME counts for a cache), we need to set
	 * the callback bit on the node.
	 */
	if (rdataset->type == dns_rdatatype_dname) {
		delegating = true;
	}

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	if (qpnode->nsec != DNS_DB_NSEC_HAS_NSEC &&
	    rdataset->type == dns_rdatatype_nsec)
	{
		newnsec = true;
	}

	/*
	 * If we're adding a delegation type, adding to the auxiliary NSEC
	 * tree, or the DB is a cache in an overmem state, hold an
	 * exclusive lock on the tree.  In the latter case the lock does
	 * not necessarily have to be acquired but it will help purge
	 * ancient entries more effectively.
	 */
	if (isc_mem_isovermem(qpdb->common.mctx)) {
		cache_is_overmem = true;
	}
	if (delegating || newnsec || cache_is_overmem) {
		writing = true;
	}

	modctx = (dbmod_t){ .writing = writing };

	if (writing) {
		dns_qpmulti_write(qpdb->tree, &modctx.tree);
		if (newnsec) {
			dns_qpmulti_write(qpdb->nsec, &modctx.nsec);
		}
	} else {
		dns_qpmulti_query(qpdb->tree, &modctx.qpr);
		modctx.tree = (dns_qp_t *)&modctx.qpr;
	}

	SPINLOCK(&qpnode->spinlock);

	if (qpdb->rrsetstats != NULL) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->type,
				  atomic_load_acquire(&newheader->attributes),
				  true);
	}

	result = ISC_R_SUCCESS;
	if (newnsec) {
		qpdata_t *nsecnode = NULL;

		result = dns_qp_getname(modctx.nsec, name, (void **)&nsecnode,
					NULL);
		if (result == ISC_R_SUCCESS) {
			result = ISC_R_SUCCESS;
		} else {
			INSIST(nsecnode == NULL);
			nsecnode = new_qpdata(qpdb, name);
			nsecnode->nsec = DNS_DB_NSEC_NSEC;
			result = dns_qp_insert(modctx.nsec, nsecnode, 0);
			INSIST(result == ISC_R_SUCCESS);
			qpdata_detach(&nsecnode);
		}
		qpnode->nsec = DNS_DB_NSEC_HAS_NSEC;
	}

	if (result == ISC_R_SUCCESS) {
		result = add(qpdb, qpnode, name, newheader, options, false,
			     addedrdataset, now DNS__DB_FLARG_PASS);
	}
	if (result == ISC_R_SUCCESS && delegating) {
		qpnode->delegating = 1;
	}

	SPINUNLOCK(&qpnode->spinlock);

	if (writing) {
		dns_qp_compact(modctx.tree, DNS_QPGC_MAYBE);
		dns_qpmulti_commit(qpdb->tree, &modctx.tree);
		if (newnsec) {
			dns_qp_compact(modctx.nsec, DNS_QPGC_MAYBE);
			dns_qpmulti_commit(qpdb->nsec, &modctx.nsec);
		}
	} else {
		dns_qpread_destroy(qpdb->tree, &modctx.qpr);
	}

	return (result);
}

static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *qpnode = (qpdata_t *)node;
	isc_result_t result;
	dns_slabheader_t *newheader = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	if (type == dns_rdatatype_any) {
		return (ISC_R_NOTIMPLEMENTED);
	}
	if (type == dns_rdatatype_rrsig && covers == 0) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	newheader = dns_slabheader_new(db, node);
	newheader->type = DNS_TYPEPAIR_VALUE(type, covers);
	setttl(newheader, 0);
	atomic_init(&newheader->attributes, DNS_SLABHEADERATTR_NONEXISTENT);

	SPINLOCK(&qpnode->spinlock);
	result = add(qpdb, qpnode, NULL, newheader, DNS_DBADD_FORCE, false,
		     NULL, 0 DNS__DB_FLARG_PASS);
	SPINUNLOCK(&qpnode->spinlock);

	return (result);
}

static unsigned int
nodecount(dns_db_t *db, dns_dbtree_t tree) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qp_memusage_t mu;

	REQUIRE(VALID_QPDB(qpdb));

	switch (tree) {
	case dns_dbtree_main:
		mu = dns_qpmulti_memusage(qpdb->tree);
		break;
	case dns_dbtree_nsec:
		mu = dns_qpmulti_memusage(qpdb->nsec);
		break;
	default:
		UNREACHABLE();
	}

	return (mu.leaves);
}

static void
setloop(dns_db_t *db, isc_loop_t *loop) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	LOCK(&qpdb->lock);
	if (qpdb->loop != NULL) {
		isc_loop_detach(&qpdb->loop);
		/* isc_timer_async_destroy(&qpdb->heaptimer); */
	}
	if (loop != NULL) {
		isc_loop_attach(loop, &qpdb->loop);
		/* isc_timer_create(qpdb->loop, expire_ttl_headers, qpdb, */
		/* 		 &qpdb->heaptimer); */
	}
	UNLOCK(&qpdb->lock);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	qpdata_t *onode = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the modctx to origin_node doesn't require a DB lock */
	onode = (qpdata_t *)qpdb->origin_node;
	if (onode != NULL) {
		newref(qpdb, onode DNS__DB_FLARG_PASS);
		*nodep = qpdb->origin_node;
	} else {
		result = ISC_R_NOTFOUND;
	}

	return (result);
}

static void
locknode(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node,
	 isc_rwlocktype_t type ISC_ATTR_UNUSED) {
	qpdata_t *qpnode = (qpdata_t *)node;

	SPINLOCK(&qpnode->spinlock);
}

static void
unlocknode(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node,
	   isc_rwlocktype_t type ISC_ATTR_UNUSED) {
	qpdata_t *qpnode = (qpdata_t *)node;

	SPINUNLOCK(&qpnode->spinlock);
}

isc_result_t
dns__qpcache_create(isc_mem_t *mctx, const dns_name_t *origin,
		    dns_dbtype_t type, dns_rdataclass_t rdclass,
		    unsigned int argc, char *argv[],
		    void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	dns_qpdb_t *qpdb = NULL;
	isc_mem_t *hmctx = mctx;

	/* This database implementation only supports cache semantics */
	REQUIRE(type == dns_dbtype_cache);

	qpdb = isc_mem_get(mctx, sizeof(*qpdb));
	*qpdb = (dns_qpdb_t){
		.common.methods = &qpdb_cachemethods,
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.attributes = DNS_DBATTR_CACHE,
		.common.references = ISC_REFCOUNT_INITIALIZER(1),
		.current_serial = 1,
		.least_serial = 1,
		.next_serial = 2,
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	/*
	 * If argv[0] exists, it points to a memory context to use for heap
	 */
	if (argc != 0) {
		hmctx = (isc_mem_t *)argv[0];
	}

	isc_mutex_init(&qpdb->lock);

	qpdb->common.update_listeners = cds_lfht_new(16, 16, 0, 0, NULL);

	dns_rdatasetstats_create(mctx, &qpdb->rrsetstats);

	/*
	 * Create the heaps.
	 */
	isc_mutex_init(&qpdb->heaplock);
	isc_heap_create(hmctx, ttl_sooner, set_index, 0, &qpdb->heap);

	/*
	 * Create deadnode lists.
	 */
	__cds_wfcq_init(&qpdb->deadnodes.head, &qpdb->deadnodes.tail);

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &qpdb->common.mctx);
	isc_mem_attach(hmctx, &qpdb->hmctx);

	/*
	 * Make a copy of the origin name.
	 */
	dns_name_dupwithoffsets(origin, mctx, &qpdb->common.origin);

	/*
	 * Make the qp tries.
	 */
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->tree);
	dns_qpmulti_create(mctx, &qpmethods, qpdb, &qpdb->nsec);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPDB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return (ISC_R_SUCCESS);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = NULL;

	rbtiterator = (qpdb_rdatasetiter_t *)(*iteratorp);

	dns__db_detachnode(rbtiterator->common.db,
			   &rbtiterator->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(rbtiterator->common.db->mctx, rbtiterator,
		    sizeof(*rbtiterator));

	*iteratorp = NULL;
}

static bool
iterator_active(dns_qpdb_t *qpdb, qpdb_rdatasetiter_t *rbtiterator,
		dns_slabheader_t *header) {
	dns_ttl_t stale_ttl = header->ttl + STALE_TTL(header, qpdb);

	/*
	 * Is this a "this rdataset doesn't exist" record?
	 */
	if (NONEXISTENT(header)) {
		return (false);
	}

	/*
	 * If this header is still active then return it.
	 */
	if (ACTIVE(header, rbtiterator->common.now)) {
		return (true);
	}

	/*
	 * If we are not returning stale records or the rdataset is
	 * too old don't return it.
	 */
	if (!STALEOK(rbtiterator) || (rbtiterator->common.now > stale_ttl)) {
		return (false);
	}
	return (true);
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL, *top_next = NULL;

	SPINLOCK(&qpnode->spinlock);

	for (header = qpnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (EXPIREDOK(rbtiterator)) {
				if (!NONEXISTENT(header)) {
					break;
				}
				header = header->down;
			} else if (header->serial <= 1 && !IGNORE(header)) {
				if (!iterator_active(qpdb, rbtiterator, header))
				{
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			break;
		}
	}

	SPINUNLOCK(&qpnode->spinlock);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL, *top_next = NULL;
	dns_typepair_t type, negtype;
	dns_rdatatype_t rdtype, covers;
	bool expiredok = EXPIREDOK(rbtiterator);

	header = rbtiterator->current;
	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	SPINLOCK(&qpnode->spinlock);

	type = header->type;
	rdtype = DNS_TYPEPAIR_TYPE(header->type);
	if (NEGATIVE(header)) {
		covers = DNS_TYPEPAIR_COVERS(header->type);
		negtype = DNS_TYPEPAIR_VALUE(covers, 0);
	} else {
		negtype = DNS_TYPEPAIR_VALUE(0, rdtype);
	}

	/*
	 * Find the start of the header chain for the next type
	 * by walking back up the list.
	 */
	top_next = header->next;
	while (top_next != NULL &&
	       (top_next->type == type || top_next->type == negtype))
	{
		top_next = top_next->next;
	}
	if (expiredok) {
		/*
		 * Keep walking down the list if possible or
		 * start the next type.
		 */
		header = header->down != NULL ? header->down : top_next;
	} else {
		header = top_next;
	}
	for (; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (expiredok) {
				if (!NONEXISTENT(header)) {
					break;
				}
				header = header->down;
			} else if (header->serial <= 1 && !IGNORE(header)) {
				if (!iterator_active(qpdb, rbtiterator, header))
				{
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			break;
		}
		/*
		 * Find the start of the header chain for the next type
		 * by walking back up the list.
		 */
		while (top_next != NULL &&
		       (top_next->type == type || top_next->type == negtype))
		{
			top_next = top_next->next;
		}
	}

	SPINUNLOCK(&qpnode->spinlock);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpdb_rdatasetiter_t *rbtiterator = (qpdb_rdatasetiter_t *)iterator;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)(rbtiterator->common.db);
	qpdata_t *qpnode = rbtiterator->common.node;
	dns_slabheader_t *header = NULL;

	header = rbtiterator->current;
	REQUIRE(header != NULL);

	SPINLOCK(&qpnode->spinlock);
	bindrdataset(qpdb, qpnode, header, rbtiterator->common.now,
		     rdataset DNS__DB_FLARG_PASS);
	SPINUNLOCK(&qpnode->spinlock);
}

/*
 * Database Iterator Methods
 */

static void
reference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)qpdbiter->common.db;
	qpdata_t *node = qpdbiter->node;

	if (node == NULL) {
		return;
	}

	reactivate_node(qpdb, node DNS__DB_FLARG_PASS);
}

static void
dereference_iter_node(qpdb_dbiterator_t *qpdbiter DNS__DB_FLARG) {
	if (qpdbiter->node == NULL) {
		return;
	}

	detachnode(qpdbiter->common.db, (dns_dbnode_t **)qpdbiter->node);
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)(*iteratorp);
	dns_db_t *db = NULL;

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_db_attach(qpdbiter->common.db, &db);
	dns_db_detach(&qpdbiter->common.db);

	dns_qpdb_t *qpdb = (dns_qpdb_t *)db;
	dns_qpsnap_destroy(qpdb->tree, &qpdbiter->tsnap);

	isc_mem_put(db->mctx, qpdbiter, sizeof(*qpdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_qpiter_init(qpdbiter->tsnap, &qpdbiter->iter);
	result = dns_qpiter_next(&qpdbiter->iter, NULL,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE); /* The tree is empty. */
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_qpiter_init(qpdbiter->tsnap, &qpdbiter->iter);
	result = dns_qpiter_prev(&qpdbiter->iter, NULL,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE); /* The tree is empty. */
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return (result);
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return (qpdbiter->result);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qp_lookup(qpdbiter->tsnap, name, NULL, &qpdbiter->iter,
			       NULL, (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							  : result;
	return (result);
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_prev(&qpdbiter->iter, NULL,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return (result);
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_qpiter_next(&qpdbiter->iter, NULL,
				 (void **)&qpdbiter->node, NULL);

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return (result);
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	dns_qpdb_t *qpdb = (dns_qpdb_t *)iterator->db;
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;
	qpdata_t *node = qpdbiter->node;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(node != NULL);

	if (name != NULL) {
		dns_name_copy(&node->name, name);
	}

	newref(qpdb, node DNS__DB_FLARG_PASS);

	*nodep = qpdbiter->node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator ISC_ATTR_UNUSED) {
	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	qpdb_dbiterator_t *qpdbiter = (qpdb_dbiterator_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return (qpdbiter->result);
	}

	dns_name_copy(dns_rootname, name);
	return (ISC_R_SUCCESS);
}

static void
deletedata(dns_db_t *db ISC_ATTR_UNUSED, dns_dbnode_t *node ISC_ATTR_UNUSED,
	   void *data) {
	dns_slabheader_t *header = data;
	dns_qpdb_t *qpdb = (dns_qpdb_t *)header->db;

	if (header->heap != NULL && header->heap_index != 0) {
		LOCK(&qpdb->heaplock);
		isc_heap_delete(header->heap, header->heap_index);
		UNLOCK(&qpdb->heaplock);
	}

	update_rrsetstats(qpdb->rrsetstats, header->type,
			  atomic_load_acquire(&header->attributes), false);

	if (header->noqname != NULL) {
		dns_slabheader_freeproof(db->mctx, &header->noqname);
	}
	if (header->closest != NULL) {
		dns_slabheader_freeproof(db->mctx, &header->closest);
	}
}

static void __attribute__((__unused__))
expire_ttl_headers(void *arg) {
	dns_qpdb_t *qpdb = arg;
	dbmod_t modctx = {
		.writing = true,
	};
	isc_stdtime_t now = isc_stdtime_now();
	bool cache_is_overmem = isc_mem_isovermem(qpdb->common.mctx);
	dns_slabheader_t *header = NULL;

	dns_qpmulti_write(qpdb->tree, &modctx.tree);
	dns_qpmulti_write(qpdb->nsec, &modctx.nsec);

	LOCK(&qpdb->heaplock);
	while ((header = isc_heap_element(qpdb->heap, 1)) != NULL) {
		qpdata_t *node = HEADERNODE(header);
		qpdata_ref(node);
		SPINLOCK(&node->spinlock);

		dns_ttl_t ttl = header->ttl;

		if (!cache_is_overmem) {
			/* Only account for stale TTL if cache is not overmem */
			ttl += STALE_TTL(header, qpdb);
		}

		if (ttl >= now - QPDB_VIRTUAL) {
			/*
			 * The header at the top of this TTL heap is not yet
			 * eligible for expiry, so none of the other headers on
			 * the same heap can be eligible for expiry, either;
			 * exit cleaning.
			 */
			SPINUNLOCK(&node->spinlock);
			qpdata_unref(node);
			break;
		}

		expireheader(header, &modctx,
			     dns_expire_ttl DNS__DB_FLARG_PASS);
		SPINUNLOCK(&node->spinlock);
		qpdata_unref(node);
	}
	UNLOCK(&qpdb->heaplock);

	dns_qp_compact(modctx.tree, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->tree, &modctx.tree);

	dns_qp_compact(modctx.nsec, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(qpdb->nsec, &modctx.nsec);
}

static dns_dbmethods_t qpdb_cachemethods = {
	.destroy = qpdb_destroy,
	.findnode = findnode,
	.find = find,
	.findzonecut = findzonecut,
	.attachnode = attachnode,
	.detachnode = detachnode,
	.createiterator = createiterator,
	.findrdataset = findrdataset,
	.allrdatasets = allrdatasets,
	.addrdataset = addrdataset,
	.deleterdataset = deleterdataset,
	.nodecount = nodecount,
	.setloop = setloop,
	.getoriginnode = getoriginnode,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.locknode = locknode,
	.unlocknode = unlocknode,
	.expiredata = expiredata,
	.deletedata = deletedata,
};

static void
qpdata_destroy(qpdata_t *data) {
	dns_slabheader_t *current = NULL, *next = NULL;

	for (current = data->data; current != NULL; current = next) {
		dns_slabheader_t *down = current->down, *down_next = NULL;

		next = current->next;

		for (down = current->down; down != NULL; down = down_next) {
			down_next = down->down;
			dns_slabheader_destroy(&down);
		}

		dns_slabheader_destroy(&current);
	}

	isc_spinlock_destroy(&data->spinlock);
	dns_name_free(&data->name, data->mctx);
	isc_mem_putanddetach(&data->mctx, data, sizeof(qpdata_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpdata, qpdata_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpdata, qpdata_destroy);
#endif

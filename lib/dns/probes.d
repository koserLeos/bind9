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

provider libdns {
	probe qp_compact_done(void *, uint32_t, uint32_t, uint32_t, uint32_t);
	probe qp_compact_start(void *, uint32_t, uint32_t, uint32_t, uint32_t);
	probe qp_deletekey_done(void *, void *, bool);
	probe qp_deletekey_start(void *, void *);
	probe qp_deletename_done(void *, void *, void *);
	probe qp_deletename_start(void *, void *);
	probe qp_getkey_done(void *, void *, bool);
	probe qp_getkey_start(void *, void *);
	probe qp_getname_done(void *, void *, void *);
	probe qp_getname_start(void *, void *);
	probe qp_insert_done(void *, void *, uint32_t);
	probe qp_insert_start(void *, void *, uint32_t);
	probe qp_lookup_done(void *, void *, void *, void *, bool, bool);
	probe qp_lookup_start(void *, void *, void *, void *);
	probe qp_reclaim_chunks_done(void *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
	probe qp_reclaim_chunks_start(void *);
	probe qp_recycle_done(void *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
	probe qp_recycle_start(void *);

	probe qpmulti_marksweep_done(void *, void *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
	probe qpmulti_marksweep_start(void *, void *);

	probe qpmulti_txn_lockedread(void *, void *);
	probe qpmulti_txn_query(void *, void *);
	probe qpmulti_txn_snapshot(void *, void *);
	probe qpmulti_txn_update(void *, void *);
	probe qpmulti_txn_write(void *, void *);
	probe qpmulti_txn_commit_done(void *, void *);
	probe qpmulti_txn_commit_start(void *, void *);
	probe qpmulti_txn_rollback_done(void *, void *, uint32_t);
	probe qpmulti_txn_rollback_start(void *, void *);

	probe qpcache_expire_ttl_start(void *, unsigned int locknum, uint32_t);
	probe qpcache_expire_ttl_done(void *, unsigned int locknum, uint32_t, size_t expired);
	probe qpcache_expire_lru_start(void *, unsigned int locknum, size_t purgesize);
	probe qpcache_expire_lru_done(void *, unsigned int locknum, size_t purged);
	probe qpcache_overmem_done(void *, size_t purged, size_t passes);
	probe qpcache_overmem_start(void *);

	/* dns_db interface */
	probe qpcache_addrdataset_done(void *, void *, void *, bool);
	probe qpcache_addrdataset_start(void *, void *, void *);
	probe qpcache_expiredata_done(void *, void *, void *);
	probe qpcache_expiredata_start(void *, void *, void *);
	probe qpcache_find_done(void *, void * name, uint32_t now, unsigned int options, int result);
	probe qpcache_find_start(void *, void * name, uint32_t now, unsigned int options);
	probe qpcache_locknode(void *, void *, bool is_wrlock);
	probe qpcache_unlocknode(void *, void *, bool is_wrlock);

	probe xfrin_axfr_finalize_begin(void *, char *);
	probe xfrin_axfr_finalize_end(void *, char *, int);
	probe xfrin_connected(void *, char *, int);
	probe xfrin_done_callback_begin(void *, char *, int);
	probe xfrin_done_callback_end(void *, char *, int);
	probe xfrin_read(void *, char *, int);
	probe xfrin_recv_answer(void *, char *, void *);
	probe xfrin_recv_done(void *, char *, int);
	probe xfrin_recv_parsed(void *, char *, int);
	probe xfrin_recv_question(void *, char *, void *);
	probe xfrin_recv_send_request(void *, char *);
	probe xfrin_recv_start(void *, char *, int);
	probe xfrin_recv_try_axfr(void *, char *, int);
	probe xfrin_sent(void *, char *, int);
	probe xfrin_start(void *, char *);
};

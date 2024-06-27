<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

## Userland Static Defined Tracing

The probes and parameters are not stable.
In general, pointers should only be used to match `_start` and `_end` probes.

### Contents

1. [libdns](#libdns)
    * [qp](#qp)
    * [qpmulti](#qpmulti)
    * [qpcache](#qpcache)

### <a name="libdns"></a>libdns

#### <a name="qp"></a>qp

- `qp_compact_start`: Fires when compation starts. This only includes the compaction phase of `dns_qp_compact`, the recycling part is fired separately.
    - `void *` qp-trie pointer
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_compact_done`: Fires when compaction finishes. This only includes the compaction phase of `dns_qp_compact`, the recycling part is fired separately.
    - `void *` qp-trie pointer
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_deletekey_start`: Fires when a node deletion by name starts.
    - `void *` qp-trie pointer
    - `void *` key pointer

- `qp_deletekey_done`: Fires when a node deletion by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `bool` true if a leaf node is deleted

- `qp_deletename_start`: Fires when a node deletion by name starts.
    - `void *` qp-trie pointer
    - `void *` name pointer

- `qp_deletename_done`: Fires when a node deletion by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` key pointer of name

- `qp_getkey_start`: Fires when a leaf node lookup by key starts.
    - `void *` qp-trie pointer
    - `void *` key pointer

- `qp_getkey_done`: Fires when a leaf node lookup by key finishes.
    - `void *` qp-trie pointer
    - `void *` key pointer
    - `bool` true if a leaf node is found

- `qp_getname_start`: Fires when a leaf node lookup by name starts.
    - `void *` qp-trie pointer
    - `void *` name pointer

- `qp_getname_done`: Fires when a leaf node lookup by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` key pointer of name

- `qp_insert_start`: Fires when a leaf node insertion starts.
    - `void *` qp-trie pointer
    - `void *` leaf pointer
    - `uint32_t` leaf integer

- `qp_insert_done`: Fires when a leaf node insertion finishes.
    - `void *` qp-trie pointer
    - `void *` leaf pointer
    - `uint32_t` leaf integer

- `qp_lookup_start`: Fires when a leaf lookup starts.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` optional iterator pointer
    - `void *` optional chain pointer

- `qp_lookup_done`: Fires when a leaf lookup finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` optional iterator pointer
    - `void *` optional chain pointer
    - `bool` true if an leaf is matched
    - `bool` true if it was a partial match

- `qp_reclaim_chunks_start`: Fires when chunk reclamation finishes.
    - `void *` qp-trie pointer

- `qp_reclaim_chunks_done`: Fires when chunk reclamation finishes.
    - `void *` qp-trie pointer
    - `uint32_t` number of chunks reclaimed
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_recycle_start`: Fires when node recycling starts.
    - `void *` qp-trie pointer

- `qp_recycle_done`: Fires when node recycling finishes.
    - `void *` qp-trie pointer
    - `uint32_t` number of nodes recycled
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

#### <a name="qpmulti"></a>qpmulti

- `qpmulti_marksweep_start`: Fires when chunk cleanup starts.
    - `void *` qpmulti pointer
    - `void *` writer qp-trie pointer

- `qpmulti_marksweep_done`: Fires when chunk cleanup is finished.
    - `void *` qpmulti pointer
    - `void *` writer qp-trie pointer
    - `uint32_t` number of chunks freed
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qpmulti_txn_query`: Fires when a lightweight read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` read-only qp-trie pointer

- `qpmulti_txn_lockedread`: Fires when a mutex-taking read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` read-only qp-trie pointer

- `qpmulti_txn_snapshot`: Fires when a heavyweight read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` snapshot qp-trie pointer

- `qpmulti_txn_update`: Fires when a heavyweight write transaction starts.
    - `void *` qpmulti pointer
    - `void *` modifiable qp-trie pointer

- `qpmulti_txn_write`: Fires when a lightweight write transaction starts.
    - `void *` qpmulti pointer
    - `void *` modifiable qp-trie pointer

- `qpmulti_txn_commit_start`: Fires when a transaction commit starts.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_commit_done`: Fires when a transaction commit is finished.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_rollback_start`: Fires when a transaction rollback starts.
    - `void *` qpmulti_pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_rollback_done`: Fires when a transaction rollback is finished.
    - `void *` qpmulti_pointer
    - `void *` transacting qp-trie pointer
    - `uint32_t` number of reclaimed chunks

#### <a name="qpcache"></a>qpcache

- `qpcache_addrdataset_start`: Fires when `addrdataset` starts.
    - `void *` database
    - `void *` node
    - `void *` rdataset

- `qpcache_addrdataset_done`: Fires when `addrdataset` finishes.
    - `void *` database
    - `void *` node
    - `void *` rdataset
    - `bool` true if the cache is overmem

A concurrent hash set
=====================

This is a kind of hash table where the keys are derived from the items
in the set (qp-trie style). There is a method to determine when a
key matches an item.


sharded locks
-------------

There is a collection of mutexes indexed by the item's hash (mod
number of locks).

These locks prevent concurrent updates to a particular item
while allowing concurrent updates to separate items.


old and new tables
------------------

When a hash set needs to be resized, a second table is allocated and
the items are migrated incrementally.

The new hash table is sized so that any insertions and incremental
migration will complete before it fills up.

When migration is finished the old hash table is handed to qsbr for
reclamation.

A hash set needs to keep track of at most two tables. Older tables are
owned by the qsbr reclamation list(s).


table structure
---------------

A table consists of two arrays, a bit like a python dictionary.

Slots in the item array contain pointers to items, or NULL for deleted
items. New items are appended to the array. When it fills up the hash
set must be resized. Slot zero is reserved.

Elements in the search array contain a pair of a 32 bit hash and the
32 bit number of a slot in the item array. They are both zero in an
empty element; the item slot number is non-zero in an occupied element.

The ratio of the sizes of the arrays determines the hash set's maximum
load factor.

The two-array structure avoids the need for atomic ops wider than 64 bits.


single-table `put(hash, key, item)`
-----------------------------------

The `item` can be null to delete an existing item

I am not specifying the hash probe sequence in the search array

The mutex corresponding to the hash must be acquired

  * probe the search array for an element whose hash value equals the
    search hash and whose existing item matches the key

  * if we find an existing item matching the key, exchange the
    existing item with the new item, and return the existing item

    (this can't race because of the mutex)
    (the caller must hand the existing item to qsbr for reclamation)

  * if it is not found and the new item is null, return null

  * if it is not found and the search probe encountered an element
    with a matching hash value and a null item, the new item can
    replace the null, and we return null

    (no other thread will interfere with this because we hold the
    mutex for its hash value)

Otherwise we insert the new value as follows:

  * atomic increment the item array's slot counter to allocate a slot

  * store the new item pointer in the allocted slot

  * probe the search array to find an empty element,
    starting from end of initial search probe sequence

  * CAS the hash and slot number into the empty element

    this step makes the new item visible to readers

  * keep probing if the CAS failed (we can race and collide with
    differing hash values)

  * return null


double-table `put(hash, key, item)`
-----------------------------------

The mutex corresponding to the hash must be acquired

Basically, just `put()` the new item into both tables. The order does
not matter. This keeps migration simple because the tables are always
in sync.

The special case is that `put()` returns null instead of inserting
into the old table

The `put()` return values should be the same, or one is null and the
other is not

Return the non-null result if any, or null

Do some migration after dropping the mutex


to migrate an item
------------------

This uses an atomic counter to scan the item array (could re-use the
allocation counter if space is tight)

  * grab a slot using an atomic increment of the counter

  * if it's null, we're done

  * otherwise, call a method to get its hash value

  * acquire the mutex for that hash

  * search the new table for an item with the same hash value and same
    item pointer; if one is found, we're done

  * insert the item into the new table, then we're done

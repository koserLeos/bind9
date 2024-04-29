#include <inttypes.h>
#include <stdint.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/overflow.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/ttlwheel.h>
#include <isc/util.h>

#define ISC_TTLWHEEL_MAGIC ISC_MAGIC('T', 'T', 'L', 'w')

#define TTLWHEEL_BUCKET(time) (time & 0xFF)
#define TTLWHEEL_ENTRIES      256
#define TTLWHEEL_VALID(w)     ISC_MAGIC_VALID(w, ISC_TTLWHEEL_MAGIC)

typedef struct ttl_entry ttl_entry_t;
typedef ISC_LIST(ttl_entry_t) ttl_entrylist_t;

struct ttl_entry {
	isc_stdtime_t ttl;
	void *data;
	ISC_LINK(ttl_entry_t) link;
};

struct isc_ttlwheel {
	uint32_t magic;

	isc_stdtime_t epoch;

	isc_mem_t *mctx;

	ttl_entrylist_t slot[TTLWHEEL_ENTRIES];
};

void
isc_ttlwheel_create(isc_mem_t *mctx, isc_stdtime_t now,
		    isc_ttlwheel_t **wheelp) {
	isc_ttlwheel_t *wheel;

	REQUIRE(wheelp != NULL);
	REQUIRE(*wheelp == NULL);

	wheel = isc_mem_get(mctx, sizeof(*wheel));
	*wheel = (isc_ttlwheel_t){
		.magic = ISC_TTLWHEEL_MAGIC,
		.epoch = now,
	};

	for (size_t i = 0; i < TTLWHEEL_ENTRIES; i++) {
		ISC_LIST_INIT(wheel->slot[i]);
	}

	isc_mem_attach(mctx, &wheel->mctx);

	*wheelp = wheel;
}

void
isc_ttlwheel_destroy(isc_ttlwheel_t **wheelp) {
	isc_ttlwheel_t *wheel;
	ttl_entry_t *entry;

	REQUIRE(wheelp != NULL);
	REQUIRE(*wheelp != NULL);
	REQUIRE(TTLWHEEL_VALID(*wheelp));

	wheel = *wheelp;
	*wheelp = NULL;

	wheel->magic = 0;

	for (size_t i = 0; i < TTLWHEEL_ENTRIES; i++) {
		entry = ISC_LIST_HEAD(wheel->slot[i]);
		while (entry != NULL) {
			ISC_LIST_UNLINK(wheel->slot[i], entry, link);
			isc_mem_put(wheel->mctx, entry, sizeof(*entry));
			entry = ISC_LIST_HEAD(wheel->slot[i]);
		}
	}

	isc_mem_putanddetach(&wheel->mctx, wheel, sizeof(*wheel));
}

isc_stdtime_t
isc_ttlwheel_epoch(isc_ttlwheel_t *wheel) {
	REQUIRE(TTLWHEEL_VALID(wheel));

	return wheel->epoch;
}

uint64_t
isc_ttlwheel_insert(isc_ttlwheel_t *wheel, isc_stdtime_t ttl, void *data) {
	ttl_entry_t *entry;

	REQUIRE(TTLWHEEL_VALID(wheel));
	REQUIRE(data != NULL);

	if (wheel->epoch >= ttl) {
		return 0;
	}

	entry = isc_mem_get(wheel->mctx, sizeof(*entry));
	*entry = (ttl_entry_t){
		.ttl = ttl,
		.data = data,
		.link = ISC_LINK_INITIALIZER,
	};

	ISC_LIST_APPEND(wheel->slot[TTLWHEEL_BUCKET(ttl) & 0xFF], entry, link);

	STATIC_ASSERT(sizeof(uintptr_t) <= sizeof(uint64_t),
		      "pointers must fit in 64-bits");

	return (uint64_t)((uintptr_t)(entry));
}

enum isc_result
isc_ttlwheel_update(isc_ttlwheel_t *wheel, uint64_t index, isc_stdtime_t ttl) {
	ttl_entry_t *entry;

	REQUIRE(TTLWHEEL_VALID(wheel));

	entry = ((void *)((uintptr_t)index));

	INSIST(entry != NULL);
	INSIST(ISC_LINK_LINKED(entry, link));

	if (ttl < wheel->epoch) {
		return ISC_R_IGNORE;
	}

	ISC_LIST_UNLINK(wheel->slot[TTLWHEEL_BUCKET(entry->ttl)], entry, link);

	entry->ttl = ttl;

	ISC_LIST_APPEND(wheel->slot[TTLWHEEL_BUCKET(entry->ttl)], entry, link);

	return ISC_R_SUCCESS;
}

void
isc_ttlwheel_delete(isc_ttlwheel_t *wheel, uint64_t index) {
	ttl_entry_t *entry;

	REQUIRE(TTLWHEEL_VALID(wheel));

	entry = ((void *)((uintptr_t)index));

	INSIST(entry != NULL);
	INSIST(ISC_LINK_LINKED(entry, link));

	ISC_LIST_UNLINK(wheel->slot[TTLWHEEL_BUCKET(entry->ttl)], entry, link);

	isc_mem_put(wheel->mctx, entry, sizeof(*entry));
}

size_t
isc_ttlwheel_poprange(isc_ttlwheel_t *wheel, isc_stdtime_t now, size_t limit,
		      void *user, isc_ttlwheel_popaction_t action) {
	ttl_entry_t *entry, *next;
	isc_stdtime_t advance, diff;
	uint32_t i;
	size_t ctr;

	REQUIRE(TTLWHEEL_VALID(wheel));
	REQUIRE(action != NULL);

	// 0 is short for maximum possible
	if (limit == 0) {
		limit = SIZE_MAX;
	}

	if (ISC_OVERFLOW_SUB(now, wheel->epoch, &diff)) {
		return 0;
	}

	advance = 0;
	ctr = 0;

	for (i = wheel->epoch; i < wheel->epoch + ISC_MIN(diff, 255); i++) {
		entry = ISC_LIST_HEAD(wheel->slot[TTLWHEEL_BUCKET(i)]);
		while (entry != NULL) {
			next = ISC_LIST_NEXT(entry, link);

			if (entry->ttl < now) {
				ISC_LIST_UNLINK(wheel->slot[TTLWHEEL_BUCKET(i)],
						entry, link);

				action(user, entry->data);

				isc_mem_put(wheel->mctx, entry, sizeof(*entry));
			}

			advance++;

			ctr++;
			if (ctr == limit) {
				goto finish_range;
			}

			entry = next;
		}
	}

finish_range:
	wheel->epoch += advance;
	return ctr;
}

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
#include <stddef.h>

#if defined(sun) && (defined(__sparc) || defined(__sparc__))
#include <synch.h> /* for smt_pause(3c) */
#endif /* if defined(sun) && (defined(__sparc) || defined(__sparc__)) */

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#define RWLOCK_MAGIC	  ISC_MAGIC('R', 'W', 'L', 'k')
#define VALID_RWLOCK(rwl) ISC_MAGIC_VALID(rwl, RWLOCK_MAGIC)

#if defined(_MSC_VER)
#include <intrin.h>
#define isc_rwlock_pause() YieldProcessor()
#elif defined(__x86_64__)
#include <immintrin.h>
#define isc_rwlock_pause() _mm_pause()
#elif defined(__i386__)
#define isc_rwlock_pause() __asm__ __volatile__("rep; nop")
#elif defined(__ia64__)
#define isc_rwlock_pause() __asm__ __volatile__("hint @pause")
#elif defined(__arm__) && HAVE_ARM_YIELD
#define isc_rwlock_pause() __asm__ __volatile__("yield")
#elif defined(sun) && (defined(__sparc) || defined(__sparc__))
#define isc_rwlock_pause() smt_pause()
#elif (defined(__sparc) || defined(__sparc__)) && HAVE_SPARC_PAUSE
#define isc_rwlock_pause() __asm__ __volatile__("pause")
#elif defined(__ppc__) || defined(_ARCH_PPC) || defined(_ARCH_PWR) || \
	defined(_ARCH_PWR2) || defined(_POWER)
#define isc_rwlock_pause() __asm__ volatile("or 27,27,27")
#else /* if defined(_MSC_VER) */
#define isc_rwlock_pause()
#endif /* if defined(_MSC_VER) */

#ifdef ISC_RWLOCK_TRACE
#include <stdio.h> /* Required for fprintf/stderr. */

#include <isc/thread.h> /* Required for isc_thread_self(). */

static void
print_lock(const char *operation, isc__rwlock_t *rwl, isc_rwlocktype_t type) {
	fprintf(stderr,
		"rwlock %p thread %" PRIuPTR " %s(%s): "
		"write_requests=%u, write_completions=%u, "
		"cnt_and_flag=0x%x, readers_waiting=%u, "
		"write_granted=%u, write_quota=%u\n",
		rwl, isc_thread_self(), operation,
		(type == isc_rwlocktype_read ? "read" : "write"),
		atomic_load_acquire(&rwl->write_requests),
		atomic_load_acquire(&rwl->write_completions),
		atomic_load_acquire(&rwl->cnt_and_flag), rwl->readers_waiting,
		atomic_load_acquire(&rwl->write_granted), rwl->write_quota);
}
#endif /* ISC_RWLOCK_TRACE */

void
isc__rwlock_init(isc__rwlock_t *rwl, unsigned int read_quota,
		 unsigned int write_quota) {
	REQUIRE(rwl != NULL);
	UNUSED(read_quota);
	UNUSED(write_quota);

	atomic_init(&rwl->rin, 0);
	atomic_init(&rwl->rout, 0);
	atomic_init(&rwl->win, 0);
	atomic_init(&rwl->wout, 0);
	rwl->magic = RWLOCK_MAGIC;
}

void
isc__rwlock_destroy(isc__rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	REQUIRE(atomic_load_acquire(&rwl->win) ==
		atomic_load_acquire(&rwl->wout));
	REQUIRE(atomic_load_acquire(&rwl->rin) ==
		atomic_load_acquire(&rwl->rout));

	rwl->magic = 0;
}

#define ISC_RWLOCK_LSB	 0xFFFFFFF0
#define ISC_RWLOCK_RINC	 0x100 /* Reader increment value. */
#define ISC_RWLOCK_WBITS 0x3   /* Writer bits in reader. */
#define ISC_RWLOCK_PRES	 0x2   /* Writer present bit. */
#define ISC_RWLOCK_PHID	 0x1   /* Phase ID bit. */

static void
isc__rwlock_write_unlock(isc__rwlock_t *rwl) {
	/* Migrate from write phase to read phase. */
	atomic_fetch_and_release(&rwl->rin, ISC_RWLOCK_LSB);

	/* Allow other writers to continue. */
	atomic_fetch_add_release(&rwl->wout, 1);
}

static void
isc__rwlock_write_lock(isc__rwlock_t *rwl) {
	uint32_t ticket = atomic_fetch_add_release(&rwl->win, 1);

	/* Acquire ownership of write phase */
	while (atomic_load_acquire(&rwl->wout) != ticket) {
		isc_rwlock_pause();
	}

	/*
	 * Acquire ticket on read-side in order to allow them
	 * to flush. Indicates to any incoming reader that a
	 * write-phase is pending.
	 */
	ticket = atomic_fetch_add_release(
		&rwl->rin, (ticket & ISC_RWLOCK_PHID) | ISC_RWLOCK_PRES);

	/* Wait for any pending readers to flush. */
	while (atomic_load_acquire(&rwl->rout) != ticket) {
		isc_rwlock_pause();
	}
}

static void
isc__rwlock_read_unlock(isc__rwlock_t *rwl) {
	atomic_fetch_add_release(&rwl->rout, ISC_RWLOCK_RINC);
}

static void
isc__rwlock_read_lock(isc__rwlock_t *rwl) {
	uint32_t writing;

	/*
	 * If no writer is present, then the operation has completed
	 * successfully.
	 */
	writing = atomic_fetch_add_release(&rwl->rin, ISC_RWLOCK_RINC) &
		  ISC_RWLOCK_WBITS;
	if (writing == 0) {
		return;
	}

	while ((atomic_load_acquire(&rwl->rin) & ISC_RWLOCK_WBITS) == writing) {
		isc_rwlock_pause();
	}
}

void
isc__rwlock_lock(isc__rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (type) {
	case isc_rwlocktype_read:
		isc__rwlock_read_lock(rwl);
		break;
	case isc_rwlocktype_write:
		isc__rwlock_write_lock(rwl);
		break;
	default:
		UNREACHABLE();
	}
}

isc_result_t
isc__rwlock_trylock(isc__rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));
	UNUSED(type);

	return (ISC_R_LOCKBUSY);
}

isc_result_t
isc__rwlock_tryupgrade(isc__rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	return (ISC_R_LOCKBUSY);
}

void
isc__rwlock_unlock(isc__rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (type) {
	case isc_rwlocktype_read:
		isc__rwlock_read_unlock(rwl);
		break;
	case isc_rwlocktype_write:
		isc__rwlock_write_unlock(rwl);
		break;
	default:
		UNREACHABLE();
	}
}

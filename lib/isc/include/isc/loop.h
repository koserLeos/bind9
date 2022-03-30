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

#pragma once

#include <inttypes.h>
#include <uv.h>

#include <isc/barrier.h>
#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/thread.h>
#include <isc/types.h>

typedef struct isc_loopmgr isc_loopmgr_t;
typedef struct isc_loop	   isc_loop_t;
typedef struct isc_job	   isc_job_t;

typedef void (*isc_job_cb)(void *);

typedef struct isc_signal isc_signal_t;

typedef void (*isc_signal_cb)(void *, int);

#define ISC_LOOPMGR_TID_UNKNOWN UINT32_MAX

struct isc_signal {
	uv_signal_t   signal;
	isc_mem_t	  *mctx;
	isc_signal_cb cb;
	void	     *cbarg;
	int	      signum;
};

/*
 * Per-thread loop
 */
#define LOOP_MAGIC    ISC_MAGIC('L', 'O', 'O', 'P')
#define VALID_LOOP(t) ISC_MAGIC_VALID(t, LOOP_MAGIC)

struct isc_job {
	isc_mem_t *mctx;
	uv_idle_t  idle;
	isc_job_cb cb;
	void	     *cbarg;
	LINK(isc_job_t) link;
};

struct isc_loop {
	int	       magic;
	isc_refcount_t references;
	isc_thread_t   thread;

	isc_loopmgr_t *loopmgr;

	uv_loop_t loop;
	uint32_t  tid;

	isc_mem_t *mctx;

	/* states */
	bool paused;
	bool finished;
	bool shuttingdown;

	/* Pause */
	uv_async_t pause;

	/* Shutdown */
	uv_async_t shutdown;
	ISC_LIST(isc_job_t) ctors;
	ISC_LIST(isc_job_t) dtors;
};

/*
 * Loop Manager
 */
#define LOOPMGR_MAGIC	 ISC_MAGIC('L', 'o', 'o', 'M')
#define VALID_LOOPMGR(t) ISC_MAGIC_VALID(t, LOOPMGR_MAGIC)

struct isc_loopmgr {
	int	       magic;
	isc_refcount_t references;
	isc_mem_t	  *mctx;

	uint_fast32_t nloops;

	atomic_bool shuttingdown;
	atomic_bool running;
	atomic_bool paused;

	/* signal handling */
	isc_signal_t *sigint;
	isc_signal_t *sigterm;

	/* pause/resume */
	isc_barrier_t pausing;
	isc_barrier_t resuming;

	/* per-thread objects */
	isc_loop_t *loops;
};

/* FIXME: Deduplicate with netmgr-int.h */
#define UV_RUNTIME_CHECK(func, ret)                                           \
	if (ret != 0) {                                                       \
		isc_error_fatal(__FILE__, __LINE__, "%s failed: %s\n", #func, \
				uv_strerror(ret));                            \
	}

#define DEFAULT_LOOP(loopmgr) (&(loopmgr)->loops[0])
#define CURRENT_LOOP(loopmgr) (&(loopmgr)->loops[isc__loopmgr_tid_v])

ISC_LANG_BEGINDECLS

isc_loopmgr_t *
isc_loopmgr_new(isc_mem_t *mctx, uint32_t nloops);
/*%<
 * Create a loop manager supporting 'nloops' loops.
 *
 * Requires:
 *\li	'nloops' is greater than 0.
 */

void
isc_loopmgr_destroy(isc_loopmgr_t **loopmgrp);
/*%<
 * Destroy the loop manager pointed to by 'loopmgrp'.
 *
 * Requires:
 *\li	'loopmgr' points to a valid loop manager.
 */

void
isc_loopmgr_shutdown(isc_loopmgr_t *loopmgr);
/*%<
 * Request shutdown of the loop manager 'loopmgr'.
 *
 * This will stop all signal handlers and send shutdown events to
 * all active loops. As a final action on shutting down, each loop
 * will run the function (or functions) set by isc_loopmgr_schedule_dtor()
 * or isc_loop_schedule_dtor().
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 */

int
isc_loopmgr_tid(void);
/*%<
 * Returns the thread ID of the currently-running loop (or
 * ISC_LOOPMGR_TID_UNKNOWN if not running in a loop manager loop).
 */

void
isc_loopmgr_run(isc_loopmgr_t *loopmgr);
/*%<
 * Run the loops in 'loopmgr'. Each loop will start by running the
 * function (or functions) set by isc_loopmgr_schedule_ctor() or
 * isc_loop_schedule_ctor().
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 */

void
isc_loopmgr_pause(isc_loopmgr_t *loopmgr);
/*%<
 * Send pause events to all running loops in 'loopmgr' (except the
 * current one if called from one of the loops). All paused loops will
 * wait utnil isc_loopmgr_resume() is called before continuing.
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 */

void
isc_loopmgr_resume(isc_loopmgr_t *loopmgr);
/*%<
 * Send resume events to all paused loops in 'loopmgr'.
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 */

void
isc_loop_schedule_ctor(isc_loop_t *loop, isc_job_cb cb, void *cbarg);
void
isc_loop_schedule_dtor(isc_loop_t *loop, isc_job_cb cb, void *cbarg);
/*%<
 * Schedule actions to be run when starting, and when shutting down,
 * one of the loops in a loop manager.
 *
 * Requires:
 *\li	'loop' is a valid loop.
 *\li	The loop manager associated with 'loop' is paused or has not
 *	yet been started.
 */

void
isc_loopmgr_schedule_ctor(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg);
void
isc_loopmgr_schedule_dtor(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg);
/*%<
 * Schedule actions to be run when starting, and when shutting down,
 * *all* of the loops in loopmgr.
 *
 * This is the same as running isc_loop_schedule_ctor() or
 * isc_loop_schedule_dtor() on each of the loops in turn.
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 *\li	'loopmgr' is paused or has not yet been started.
 */

void
isc_loop_mem_attach(isc_loop_t *loop, isc_mem_t **mctxp);
/*%<
 * Attach to a memory context that was created for 'loop' when
 *
 * Requires:
 *\li	'loop' is a valid loop.
 *\li	'mctxp' is not NULL, and *mctxp is NULL.
 */

isc_loop_t *
isc_loopmgr_default_loop(isc_loopmgr_t *loopmgr);
/*%<
 * Returns the default loop for the 'loopmgr' (which is
 * 'loopmgr->loops[0]').
 *
 * Requires:
 *\li	'loopmgr' is a valid loop manager.
 */

ISC_LANG_ENDDECLS

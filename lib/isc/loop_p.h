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

#include <isc/barrier.h>
#include <isc/lang.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/qsbr.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/signal.h>
#include <isc/stack.h>
#include <isc/thread.h>
#include <isc/types.h>
#include <isc/uv.h>
#include <isc/work.h>

/*
 * Per-thread loop
 */
#define LOOP_MAGIC    ISC_MAGIC('L', 'O', 'O', 'P')
#define VALID_LOOP(t) ISC_MAGIC_VALID(t, LOOP_MAGIC)

typedef ISC_LIST(isc_job_t) isc_joblist_t;
typedef ISC_ASTACK(isc_job_t) isc_jobstack_t;

struct isc_loop {
	int magic;
	isc_refcount_t references;
	isc_thread_t thread;

	isc_loopmgr_t *loopmgr;

	uv_loop_t loop;
	uint32_t tid;

	isc_mem_t *mctx;

	/* states */
	bool paused;
	bool shuttingdown;

	/* Async queue */
	uv_async_t queue_trigger;
	isc_jobstack_t queue_jobs;

	/* Pause */
	uv_async_t pause_trigger;

	/* Shutdown */
	uv_async_t shutdown_trigger;
	isc_joblist_t setup_jobs;
	isc_joblist_t teardown_jobs;

	/* Destroy */
	uv_async_t destroy_trigger;

	/* safe memory reclamation */
	uv_async_t wakeup_trigger;
	uv_prepare_t quiescent;
	isc_qsbr_phase_t qsbr_phase;
};

/*
 * Loop Manager
 */
#define LOOPMGR_MAGIC	 ISC_MAGIC('L', 'o', 'o', 'M')
#define VALID_LOOPMGR(t) ISC_MAGIC_VALID(t, LOOPMGR_MAGIC)

struct isc_loopmgr {
	int magic;
	isc_mem_t *mctx;

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

	/* start/stop */
	isc_barrier_t starting;

	/* stopping */
	isc_barrier_t stopping;

	/* per-thread objects */
	isc_loop_t *loops;

	/* safe memory reclamation */
	isc_qsbr_t qsbr;
};

/*
 * Signal Handler
 */
struct isc_signal {
	uv_signal_t signal;
	isc_loop_t *loop;
	isc_signal_cb cb;
	void *cbarg;
	int signum;
};

/*
 * Job to be scheduled in an event loop
 */
#define JOB_MAGIC    ISC_MAGIC('J', 'O', 'B', ' ')
#define VALID_JOB(t) ISC_MAGIC_VALID(t, JOB_MAGIC)

struct isc_job {
	int magic;
	uv_idle_t idle;
	isc_loop_t *loop;
	isc_job_cb cb;
	void *cbarg;
	ISC_LINK(isc_job_t) link;
};

/*
 * Work to be offloaded to an external thread.
 */
struct isc_work {
	uv_work_t work;
	isc_loop_t *loop;
	isc_work_cb work_cb;
	isc_after_work_cb after_work_cb;
	void *cbarg;
};

#define DEFAULT_LOOP(loopmgr) (&(loopmgr)->loops[0])
#define CURRENT_LOOP(loopmgr) (&(loopmgr)->loops[isc_tid()])
#define LOOP(loopmgr, tid)    (&(loopmgr)->loops[tid])
#define ON_LOOP(loop)	      ((loop) == CURRENT_LOOP((loop)->loopmgr))

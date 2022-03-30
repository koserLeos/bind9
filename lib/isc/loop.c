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

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/barrier.h>
#include <isc/condition.h>
#include <isc/list.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/signal.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "loop_p.h"

/**
 * Private
 */

static thread_local uint32_t isc__loopmgr_tid_v = ISC_LOOPMGR_TID_UNKNOWN;

static void
ignore_signal(int sig, void (*handler)(int)) {
	struct sigaction sa;

	sa = (struct sigaction){ .sa_handler = handler };
	if (sigfillset(&sa.sa_mask) != 0 || sigaction(sig, &sa, NULL) < 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(errno, strbuf, sizeof(strbuf));
		isc_error_fatal(__FILE__, __LINE__, "%s() %d setup: %s",
				__func__, sig, strbuf);
	}
}

static void
isc__loopmgr_shutdown(isc_loopmgr_t *loopmgr) {
	REQUIRE(DEFAULT_LOOP(loopmgr) == CURRENT_LOOP(loopmgr));

	if (!atomic_compare_exchange_strong(&loopmgr->shuttingdown,
					    &(bool){ false }, true))
	{
		return;
	}

	/* Stop the signal handlers */
	isc_signal_stop(loopmgr->sigterm);
	isc_signal_stop(loopmgr->sigint);

	/* Free the signal handlers */
	isc_signal_free(loopmgr->sigterm);
	isc_signal_free(loopmgr->sigint);

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		uv_async_send(&loop->shutdown);
	}
}

void
isc_loopmgr_shutdown(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	/* If invoked from non-default loop, just pass the signal */
	if (DEFAULT_LOOP(loopmgr) != CURRENT_LOOP(loopmgr)) {
		kill(getpid(), SIGTERM);
		return;
	}

	isc__loopmgr_shutdown(loopmgr);
}

static void
isc__loopmgr_signal(void *arg, int signum) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		isc__loopmgr_shutdown(loopmgr);
		break;
	default:
		UNREACHABLE();
	}
}

static void
pause_loop(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;

	loop->paused = true;
	(void)isc_barrier_wait(&loopmgr->pausing);
}

static void
resume_loop(isc_loop_t *loop) {
	isc_loopmgr_t *loopmgr = loop->loopmgr;

	(void)isc_barrier_wait(&loopmgr->resuming);
	loop->paused = false;
}

static void
pauseresume_cb(uv_async_t *handle) {
	isc_loop_t *loop =
		(isc_loop_t *)uv_handle_get_data((uv_handle_t *)handle);

	pause_loop(loop);
	resume_loop(loop);
}

static void
isc__job_free(uv_handle_t *handle) {
	isc_job_t *job = uv_handle_get_data(handle);

	isc_mem_putanddetach(&job->mctx, job, sizeof(*job));
}

static void
isc__job_cb(uv_idle_t *idle) {
	isc_job_t *job = uv_handle_get_data((uv_handle_t *)idle);

	job->cb(job->cbarg);

	uv_idle_stop(idle);
	uv_close((uv_handle_t *)idle, isc__job_free);
}

static void
shutdown_cb(uv_async_t *handle) {
	isc_job_t *job = NULL;
	isc_loop_t *loop =
		(isc_loop_t *)uv_handle_get_data((uv_handle_t *)handle);

	/*
	 * The loop resources are freed only after uv_run() is finished, so we
	 * don't need to worry about freeing memory used for async callbacks.
	 */
	uv_close((uv_handle_t *)&loop->shutdown, NULL);
	uv_close((uv_handle_t *)&loop->pause, NULL);

	job = ISC_LIST_TAIL(loop->teardown_jobs);
	while (job != NULL) {
		int r;
		isc_job_t *next = ISC_LIST_NEXT(job, link);
		ISC_LIST_UNLINK(loop->teardown_jobs, job, link);

		r = uv_idle_start(&job->idle, isc__job_cb);
		UV_RUNTIME_CHECK(uv_idle_start, r);

		job = next;
	}
}

static void
loop_init(isc_loop_t *loop) {
	int r = uv_loop_init(&loop->loop);
	UV_RUNTIME_CHECK(uv_loop_init, r);

	r = uv_async_init(&loop->loop, &loop->pause, pauseresume_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data((uv_handle_t *)&loop->pause, loop);

	r = uv_async_init(&loop->loop, &loop->shutdown, shutdown_cb);
	UV_RUNTIME_CHECK(uv_async_init, r);
	uv_handle_set_data((uv_handle_t *)&loop->shutdown, loop);

	isc_mem_create(&loop->mctx);

	ISC_LIST_INIT(loop->setup_jobs);
	ISC_LIST_INIT(loop->teardown_jobs);
}

static void
loop_run(isc_loop_t *loop) {
	int r;
	isc_job_t *job;

	job = ISC_LIST_HEAD(loop->setup_jobs);
	while (job != NULL) {
		isc_job_t *next = ISC_LIST_NEXT(job, link);
		ISC_LIST_UNLINK(loop->setup_jobs, job, link);

		r = uv_idle_start(&job->idle, isc__job_cb);
		UV_RUNTIME_CHECK(uv_idle_start, r);

		job = next;
	}

	r = uv_run(&loop->loop, UV_RUN_DEFAULT);
	UV_RUNTIME_CHECK(uv_run, r);
}

static void
loop_close(isc_loop_t *loop) {
	int r = uv_loop_close(&loop->loop);
	UV_RUNTIME_CHECK(uv_loop_close, r);

	isc_mem_detach(&loop->mctx);
}

static isc_threadresult_t
loop_thread(isc_threadarg_t arg) {
	isc_loop_t *loop = (isc_loop_t *)arg;

	REQUIRE(VALID_LOOP(loop));

	/* Initialize the thread_local variable */
	isc__loopmgr_tid_v = loop->tid;

	loop_run(loop);

	return ((isc_threadresult_t)0);
}

enum {
	isc_loop_ctor,
	isc_loop_dtor,
};

static void
isc__loop_deschedule(isc_loop_t *loop, int when, isc_job_t *job) {
	switch (when) {
	case isc_loop_ctor:
		ISC_LIST_DEQUEUE(loop->setup_jobs, job, link);
		break;
	case isc_loop_dtor:
		ISC_LIST_DEQUEUE(loop->teardown_jobs, job, link);
		break;
	default:
		UNREACHABLE();
	}
}

void
isc_loop_nosetup(isc_loop_t *loop, isc_job_t *job) {
	isc__loop_deschedule(loop, isc_loop_ctor, job);
}

void
isc_loop_noteardown(isc_loop_t *loop, isc_job_t *job) {
	isc__loop_deschedule(loop, isc_loop_dtor, job);
}

static isc_job_t *
isc__loop_schedule(isc_loop_t *loop, int when, isc_job_cb cb, void *cbarg) {
	isc_job_t *job = NULL;
	isc_loopmgr_t *loopmgr;
	int r;

	REQUIRE(VALID_LOOP(loop));

	loopmgr = loop->loopmgr;

	REQUIRE(loop->tid == isc__loopmgr_tid_v ||
		!atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.cb = cb,
		.cbarg = cbarg,
	};

	ISC_LINK_INIT(job, link);

	isc_mem_attach(loop->mctx, &job->mctx);

	r = uv_idle_init(&loop->loop, &job->idle);
	UV_RUNTIME_CHECK(uv_idle_init, r);
	uv_handle_set_data((uv_handle_t *)&job->idle, job);

	/*
	 * The ISC_LIST_PREPEND is counterintuitive here, but actually, the
	 * uv_idle_start() puts the item on the HEAD of the internal list, so we
	 * want to store items here in reverse order, so on the uv_loop, they
	 * are scheduled in the correct order
	 */
	switch (when) {
	case isc_loop_ctor:
		ISC_LIST_PREPEND(loop->setup_jobs, job, link);
		break;
	case isc_loop_dtor:
		ISC_LIST_PREPEND(loop->teardown_jobs, job, link);
		break;
	default:
		UNREACHABLE();
	}
	return (job);
}

/**
 * Public
 */

int
isc_loopmgr_tid(void) {
	return (isc__loopmgr_tid_v);
}

isc_loopmgr_t *
isc_loopmgr_new(isc_mem_t *mctx, uint32_t nloops) {
	isc_loopmgr_t *loopmgr = NULL;

	REQUIRE(nloops > 0);

	loopmgr = isc_mem_get(mctx, sizeof(*loopmgr));
	*loopmgr = (isc_loopmgr_t){
		.nloops = nloops,
	};

	isc_mem_attach(mctx, &loopmgr->mctx);
	isc_refcount_init(&loopmgr->references, 1);

	isc_barrier_init(&loopmgr->pausing, loopmgr->nloops);
	isc_barrier_init(&loopmgr->resuming, loopmgr->nloops);

	loopmgr->loops = isc_mem_get(
		loopmgr->mctx, loopmgr->nloops * sizeof(loopmgr->loops[0]));
	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		*loop = (isc_loop_t){
			.tid = i,
			.loopmgr = loopmgr,
			.magic = LOOP_MAGIC,
		};

		loop_init(loop);
	}

	loopmgr->sigint = isc_signal_new(loopmgr, isc__loopmgr_signal, loopmgr,
					 SIGINT);
	loopmgr->sigterm = isc_signal_new(loopmgr, isc__loopmgr_signal, loopmgr,
					  SIGTERM);

	isc_signal_start(loopmgr->sigint);
	isc_signal_start(loopmgr->sigterm);

	loopmgr->magic = LOOPMGR_MAGIC;

	return (loopmgr);
}

isc_job_t *
isc_loop_setup(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	return (isc__loop_schedule(loop, isc_loop_ctor, cb, cbarg));
}

isc_job_t *
isc_loop_teardown(isc_loop_t *loop, isc_job_cb cb, void *cbarg) {
	return (isc__loop_schedule(loop, isc_loop_dtor, cb, cbarg));
}

static void
isc__loopmgr_schedule(isc_loopmgr_t *loopmgr, int when, isc_job_cb cb,
		      void *cbarg) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(!atomic_load(&loopmgr->running) ||
		atomic_load(&loopmgr->paused));

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];
		isc__loop_schedule(loop, when, cb, cbarg);
	}
}

void
isc_loopmgr_setup(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	isc__loopmgr_schedule(loopmgr, isc_loop_ctor, cb, cbarg);
}

void
isc_loopmgr_teardown(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	isc__loopmgr_schedule(loopmgr, isc_loop_dtor, cb, cbarg);
}

void
isc_loopmgr_runjob(isc_loopmgr_t *loopmgr, isc_job_cb cb, void *cbarg) {
	isc_loop_t *loop = NULL;
	isc_job_t *job = NULL;
	int r;

	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(isc__loopmgr_tid_v != ISC_LOOPMGR_TID_UNKNOWN);

	loop = &loopmgr->loops[isc__loopmgr_tid_v];

	job = isc_mem_get(loop->mctx, sizeof(*job));
	*job = (isc_job_t){
		.cb = cb,
		.cbarg = cbarg,
	};

	isc_mem_attach(loop->mctx, &job->mctx);

	r = uv_idle_init(&loop->loop, &job->idle);
	UV_RUNTIME_CHECK(uv_idle_init, r);
	uv_handle_set_data((uv_handle_t *)&job->idle, job);

	r = uv_idle_start(&job->idle, isc__job_cb);
	UV_RUNTIME_CHECK(uv_idle_start, r);
}

void
isc_loopmgr_run(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->running,
						     &(bool){ false }, true));

	/*
	 * Always ignore SIGPIPE.
	 */
	ignore_signal(SIGPIPE, SIG_IGN);

	/*
	 * The thread 0 is this one.
	 */
	for (size_t i = 1; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		isc_thread_create(loop_thread, loop, &loop->thread);
	}

	loop_thread(&loopmgr->loops[0]);
}

void
isc_loopmgr_pause(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(isc__loopmgr_tid_v != ISC_LOOPMGR_TID_UNKNOWN);

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		/* Skip current loop */
		if (i == isc__loopmgr_tid_v) {
			continue;
		}
		uv_async_send(&loop->pause);
	}

	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->paused,
						     &(bool){ false }, true));
	pause_loop(CURRENT_LOOP(loopmgr));
}

void
isc_loopmgr_resume(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));
	REQUIRE(isc__loopmgr_tid_v != ISC_LOOPMGR_TID_UNKNOWN);

	RUNTIME_CHECK(atomic_compare_exchange_strong(&loopmgr->paused,
						     &(bool){ true }, false));
	resume_loop(CURRENT_LOOP(loopmgr));
}

void
isc_loopmgr_destroy(isc_loopmgr_t **loopmgrp) {
	isc_loopmgr_t *loopmgr = NULL;

	REQUIRE(loopmgrp != NULL);
	REQUIRE(VALID_LOOPMGR(*loopmgrp));

	loopmgr = *loopmgrp;
	*loopmgrp = NULL;

	isc_refcount_decrement0(&loopmgr->references);
	isc_refcount_destroy(&loopmgr->references);

	loopmgr->magic = 0;

	/* FIXME: We need to split the ->running and ->paused variable */
	if (atomic_compare_exchange_strong(&loopmgr->running, &(bool){ true },
					   false)) {
		/* First wait for all loops to finish */
		for (size_t i = 1; i < loopmgr->nloops; i++) {
			isc_loop_t *loop = &loopmgr->loops[i];
			isc_thread_join(loop->thread, NULL);
		}
	}

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		loop_close(loop);
		loop->magic = 0;
	}
	isc_mem_put(loopmgr->mctx, loopmgr->loops,
		    loopmgr->nloops * sizeof(loopmgr->loops[0]));

	isc_barrier_destroy(&loopmgr->resuming);
	isc_barrier_destroy(&loopmgr->pausing);

	isc_mem_putanddetach(&loopmgr->mctx, loopmgr, sizeof(*loopmgr));
}

isc_mem_t *
isc_loop_getmctx(isc_loop_t *loop) {
	REQUIRE(VALID_LOOP(loop));

	return (loop->mctx);
}

isc_loop_t *
isc_loopmgr_mainloop(isc_loopmgr_t *loopmgr) {
	REQUIRE(VALID_LOOPMGR(loopmgr));

	return (DEFAULT_LOOP(loopmgr));
}

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

#if HAVE_CMOCKA

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/loop.h>
#include <isc/os.h>
#include <isc/result.h>
#include <isc/util.h>

#include "../loop.c"
#include "isctest.h"

static int
setup_mctx(void **state) {
	UNUSED(state);

	isc_mem_create(&test_mctx);

	return (0);
}

static int
teardown_mctx(void **state) {
	UNUSED(state);

	isc_mem_destroy(&test_mctx);

	return (0);
}

static int
setup_loopmgr(void **state) {
	isc_loopmgr_t *loopmgr = NULL;

	loopmgr = isc_loopmgr_new(test_mctx, isc_os_ncpus());
	if (loopmgr == NULL) {
		return (1);
	}

	*state = loopmgr;

	return (0);
}

static int
teardown_loopmgr(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	isc_loopmgr_destroy(&loopmgr);

	return (0);
}

static atomic_uint scheduled = 0;

static void
count(void *arg) {
	UNUSED(arg);

	atomic_fetch_add(&scheduled, 1);
}

static void
shutdown_loopmgr(void *arg) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;

	while (atomic_load(&scheduled) != loopmgr->nloops) {
		isc_thread_yield();
	}

	isc_loopmgr_shutdown(loopmgr);
}

static void
isc_loopmgr_test(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	atomic_store(&scheduled, 0);

	isc_loopmgr_setup(loopmgr, count, loopmgr);
	isc_loop_setup(DEFAULT_LOOP(loopmgr), shutdown_loopmgr, loopmgr);

	isc_loopmgr_run(loopmgr);

	assert_int_equal(atomic_load(&scheduled), loopmgr->nloops);
}

static void
count2(void *arg) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;

	atomic_fetch_add(&scheduled, 1);
	if (isc_loopmgr_tid() == 0) {
		isc_loopmgr_runjob(loopmgr, shutdown_loopmgr, loopmgr);
	}
}

static void
runjob(void *arg) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;
	isc_loopmgr_runjob(loopmgr, count2, loopmgr);
}

static void
isc_loopmgr_runjob_test(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	atomic_store(&scheduled, 0);

	isc_loopmgr_setup(loopmgr, runjob, loopmgr);

	isc_loopmgr_run(loopmgr);

	assert_int_equal(atomic_load(&scheduled), loopmgr->nloops);
}

static void
pause_loopmgr(void *arg) {
	isc_loopmgr_t *loopmgr = (isc_loopmgr_t *)arg;

	isc_loopmgr_pause(loopmgr);

	assert_true(atomic_load(&loopmgr->paused));

	for (size_t i = 0; i < loopmgr->nloops; i++) {
		isc_loop_t *loop = &loopmgr->loops[i];

		assert_true(loop->paused);
	}

	atomic_init(&scheduled, loopmgr->nloops);

	isc_loopmgr_resume(loopmgr);
}

static void
isc_loopmgr_pause_test(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	isc_loop_setup(DEFAULT_LOOP(loopmgr), pause_loopmgr, loopmgr);
	isc_loop_setup(DEFAULT_LOOP(loopmgr), shutdown_loopmgr, loopmgr);

	isc_loopmgr_run(loopmgr);
}

static void
send_sigint(void *arg) {
	UNUSED(arg);

	kill(getpid(), SIGINT);
}

static void
isc_loopmgr_sigint_test(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	isc_loop_setup(CURRENT_LOOP(loopmgr), send_sigint, loopmgr);

	isc_loopmgr_run(loopmgr);
}

static void
send_sigterm(void *arg) {
	UNUSED(arg);

	kill(getpid(), SIGINT);
}

static void
isc_loopmgr_sigterm_test(void **state) {
	isc_loopmgr_t *loopmgr = *state;

	isc_loop_setup(CURRENT_LOOP(loopmgr), send_sigterm, loopmgr);

	isc_loopmgr_run(loopmgr);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(isc_loopmgr_test, setup_loopmgr,
						teardown_loopmgr),
		cmocka_unit_test_setup_teardown(isc_loopmgr_pause_test,
						setup_loopmgr,
						teardown_loopmgr),
		cmocka_unit_test_setup_teardown(isc_loopmgr_runjob_test,
						setup_loopmgr,
						teardown_loopmgr),
		cmocka_unit_test_setup_teardown(isc_loopmgr_sigint_test,
						setup_loopmgr,
						teardown_loopmgr),
		cmocka_unit_test_setup_teardown(isc_loopmgr_sigterm_test,
						setup_loopmgr,
						teardown_loopmgr),
	};

	return (cmocka_run_group_tests(tests, setup_mctx, teardown_mctx));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */

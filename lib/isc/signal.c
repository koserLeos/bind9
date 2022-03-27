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
#include <uv.h>

#include <isc/loop.h>
#include <isc/signal.h>

isc_signal_t *
isc_signal_new(isc_loopmgr_t *loopmgr, isc_signal_cb cb, void *cbarg,
	       int signum) {
	isc_loop_t *loop = NULL;
	isc_signal_t *signal = NULL;
	isc_mem_t *mctx = NULL;

	loop = DEFAULT_LOOP(loopmgr);

	isc_loop_mem_attach(loop, &mctx);

	signal = isc_mem_get(mctx, sizeof(*signal));
	*signal = (isc_signal_t){
		.mctx = mctx,
		.cb = cb,
		.cbarg = cbarg,
		.signum = signum,
	};

	int r = uv_signal_init(&loop->loop, &signal->signal);
	UV_RUNTIME_CHECK(uv_signal_init, r);

	uv_handle_set_data((uv_handle_t *)&signal->signal, signal);

	return (signal);
}

static void
isc__signal_free(uv_handle_t *handle) {
	isc_signal_t *signal = uv_handle_get_data(handle);

	isc_mem_putanddetach(&signal->mctx, signal, sizeof(*signal));
}

void
isc_signal_free(isc_signal_t *signal) {
	uv_close((uv_handle_t *)&signal->signal, isc__signal_free);
}

void
isc_signal_stop(isc_signal_t *signal) {
	int r = uv_signal_stop(&signal->signal);
	UV_RUNTIME_CHECK(uv_signal_stop, r);
}

static void
isc__signal_cb(uv_signal_t *handle, int signum) {
	isc_signal_t *signal = uv_handle_get_data((uv_handle_t *)handle);

	REQUIRE(signum == signal->signum);

	signal->cb(signal->cbarg, signum);
}

void
isc_signal_start(isc_signal_t *signal) {
	int r = uv_signal_start(&signal->signal, isc__signal_cb,
				signal->signum);
	UV_RUNTIME_CHECK(uv_signal_start, r);
}

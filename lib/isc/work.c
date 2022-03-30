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
#include <isc/uv.h>
#include <isc/work.h>

#include "loop_p.h"

static void
isc__work_cb(uv_work_t *req) {
	isc_work_t *work = uv_req_get_data((uv_req_t *)req);

	work->work_cb(work->cbarg);
}

static void
isc__after_work_cb(uv_work_t *req, int status) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_work_t *work = uv_req_get_data((uv_req_t *)req);

	if (status != 0) {
		result = isc__nm_uverr2result(status);
	}

	work->after_work_cb(work->cbarg, result);

	isc_loop_noteardown(work->loop, work->cancel_job);

	isc_mem_put(work->loop->mctx, work, sizeof(*work));
}

static void
isc__work_cancel(void *arg) {
	isc_work_t *work = (isc_work_t *)arg;
	int r = uv_cancel((uv_req_t *)&work->work);
	UV_RUNTIME_CHECK(uv_cancel, r);
}

void
isc_queue_work(isc_loop_t *loop, isc_work_cb work_cb,
	       isc_after_work_cb after_work_cb, void *cbarg) {
	isc_work_t *work = NULL;
	int r;

	REQUIRE(VALID_LOOP(loop));
	REQUIRE(work_cb != NULL);
	REQUIRE(after_work_cb != NULL);

	work = isc_mem_get(loop->mctx, sizeof(*work));
	*work = (isc_work_t){
		.loop = loop,
		.work_cb = work_cb,
		.after_work_cb = after_work_cb,
		.cbarg = cbarg,
	};

	uv_req_set_data((uv_req_t *)&work->work, work);

	r = uv_queue_work(&loop->loop, &work->work, isc__work_cb,
			  isc__after_work_cb);
	UV_RUNTIME_CHECK(uv_queue_work, r);

	work->cancel_job = isc_loop_teardown(loop, isc__work_cancel, work);
}

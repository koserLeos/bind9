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

#include <isc/iterated_hash.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/tls.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>
#include <isc/xml.h>

#include "config.h"
#include "mem_p.h"
#include "mutex_p.h"
#include "os_p.h"

#ifndef ISC_CONSTRUCTOR
#error Either __attribute__((constructor|destructor))__ or DllMain support needed to compile BIND 9.
#endif

/***
 *** Functions
 ***/

void
isc__initialize(void) ISC_CONSTRUCTOR;
void
isc__shutdown(void) ISC_DESTRUCTOR;

#include <openssl/err.h>

static void
detect_uncleared_libcrypto_error(const char *xfile, int xline) {
       const char *file, *func, *data;
       int line, flags;
       long err;
       bool leak = false;
       while ((err = ERR_get_error_all(&file, &line, &func, &data, &flags)) !=
              0L)
       {
               fprintf(stderr,
                       "# Uncleared libcrypto error: %s:%d %s:%d %s %s %ld "
                       "%x\n",
                       xfile, xline, file, line, func, data, err, flags);
               leak = true;
       }
       INSIST(!leak);
}

void
isc__initialize(void) {
	isc__os_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__mutex_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__mem_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__tls_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__uv_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__xml_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__md_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	isc__iterated_hash_initialize();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	(void)isc_os_ncpus();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
	rcu_register_thread();
	detect_uncleared_libcrypto_error(__FILE__, __LINE__);
}

void
isc__shutdown(void) {
	isc__iterated_hash_shutdown();
	isc__md_shutdown();
	isc__xml_shutdown();
	isc__uv_shutdown();
	isc__tls_shutdown();
	isc__mem_shutdown();
	isc__mutex_shutdown();
	isc__os_shutdown();
	/* should be after isc__mem_shutdown() which calls rcu_barrier() */
	rcu_unregister_thread();
}

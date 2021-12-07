/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <string.h>
#include <uv.h>

#include <openssl/crypto.h>

#include <isc/bind9.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/util.h>

#include "mem_p.h"
#include "mutex_p.h"
#include "result_p.h"
#include "tls_p.h"
#include "trampoline_p.h"

#ifndef ISC_CONSTRUCTOR
#error Either __attribute__((constructor|destructor))__ or DllMain support needed to compile BIND 9.
#endif

/***
 *** Functions
 ***/

static isc_mem_t *uv_mem = NULL;
static isc_mem_t *openssl_mem = NULL;

static void *
uv_malloc(size_t size) {
	return (isc_mem_allocate(uv_mem, size));
}

static void *
uv_realloc(void *ptr, size_t size) {
	return (isc_mem_reallocate(uv_mem, ptr, size));
}

static void *
uv_calloc(size_t count, size_t size) {
	/* FIXME: Check for overflow */
	void *ptr = isc_mem_allocate(uv_mem, count * size);
	memset(ptr, 0, count * size);

	return (ptr);
}

static void
uv_free(void *ptr) {
	if (ptr == 0) {
		return;
	}
	isc_mem_free(uv_mem, ptr);
}

static void
isc__uv_initialize(void) {
	isc_mem_create(&uv_mem);

	RUNTIME_CHECK(uv_replace_allocator(uv_malloc, uv_realloc, uv_calloc,
					   uv_free) == 0);
}

static void
isc__uv_shutdown(void) {
	uv_library_shutdown();
	isc_mem_destroy(&uv_mem);
}

static void *
openssl_malloc(size_t size, const char *file, int line) {
#if ISC_MEM_TRACKLINES
	return (isc__mem_allocate(openssl_mem, size, file, line));
#else
	UNUSED(file);
	UNUSED(line);

	return (isc_mem_allocate(openssl_mem, size));
#endif
}

static void *
openssl_realloc(void *ptr, size_t size, const char *file, int line) {
#if ISC_MEM_TRACKLINES
	return (isc__mem_reallocate(openssl_mem, ptr, size, file, line));
#else
	UNUSED(file);
	UNUSED(line);
	return (isc_mem_reallocate(openssl_mem, ptr, size));
#endif
}

static void
openssl_free(void *ptr, const char *file, int line) {
	if (ptr == 0) {
		return;
	}
#if ISC_MEM_TRACKLINES
	isc__mem_free(openssl_mem, ptr, file, line);
#else
	UNUSED(file);
	UNUSED(line);
	isc_mem_free(openssl_mem, ptr);
#endif
}

static void
isc__openssl_initialize(void) {
	isc_mem_create(&openssl_mem);

	RUNTIME_CHECK(CRYPTO_set_mem_functions(openssl_malloc, openssl_realloc,
					       openssl_free) == 1);
}

static void
isc__openssl_shutdown(void) {
	isc_mem_destroy(&openssl_mem);
}

void
isc_lib_register(void) {
	isc_bind9 = false;
}

#ifdef WIN32
int
isc_lib_ntservice(int(WINAPI *mainfunc)(int argc, char *argv[]), int argc,
		  char *argv[]) {
	isc__trampoline_t *trampoline = isc__trampoline_get(NULL, NULL);
	int r;

	isc__trampoline_attach(trampoline);

	r = mainfunc(argc, argv);

	isc__trampoline_detach(trampoline);

	return (r);
}
#endif /* ifdef WIN32 */

void
isc__initialize(void) ISC_CONSTRUCTOR;
void
isc__shutdown(void) ISC_DESTRUCTOR;

void
isc__initialize(void) {
	isc__mutex_initialize();
	isc__mem_initialize();
	isc__uv_initialize();
	isc__openssl_initialize();
	isc__tls_initialize();
	isc__trampoline_initialize();
	isc__result_initialize();
}

void
isc__shutdown(void) {
	isc__result_shutdown();
	isc__trampoline_shutdown();
	isc__tls_shutdown();
	isc__openssl_shutdown();
	isc__uv_shutdown();
	isc__mem_shutdown();
	isc__mutex_shutdown();
}

/*
 * This is a workaround for situation when libisc is statically linked.  Under
 * normal situation, the linker throws out all symbols from compilation unit
 * when no symbols are used in the final binary.  This empty function must be
 * called at least once from different compilation unit (mem.c in this case).
 */
void
isc_enable_constructors() {
	/* do nothing */
}

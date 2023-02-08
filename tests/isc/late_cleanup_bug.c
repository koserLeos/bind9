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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/utsname.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if !defined(LIBRESSL_VERSION_NUMBER)
static bool done = false;

static void *
malloc_ex(size_t size, const char *file __attribute__((unused)),
	  int line __attribute__((unused))) {
	/* fprintf(stderr, "%s:%s:%u\n", __func__, file, line); */
	return (malloc(size));
}

static void *
realloc_ex(void *ptr, size_t size, const char *file __attribute__((unused)),
	   int line __attribute__((unused))) {
	/* fprintf(stderr, "%s:%s:%u\n", __func__, file, line); */
	return (realloc(ptr, size));
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void
free_ex(void *ptr, const char *file __attribute__((unused)),
	int line __attribute__((unused))) {
	/* fprintf(stderr, "%s:%s:%u\n", __func__, file, line); */
	if (ptr == NULL) {
		return;
	}
	if (done) {
		fprintf(stderr, "%s:%s:%u\n", __func__, file, line);
	}
	assert(!done);
	free(ptr);
}
#else
static void
free_ex(void *ptr) {
	if (ptr == NULL) {
		return;
	}
	if (done) {
		fprintf("%s\n", __func__);
		assert(!done);
	}
	free(ptr);
}
#endif
#endif

static void
ATEXIT(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_cleanup();
#else
	CONF_modules_unload(1);
	OBJ_cleanup();
	EVP_cleanup();
#if !defined(OPENSSL_NO_ENGINE)
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	RAND_cleanup();
	ERR_free_strings();
#endif
#if !defined(LIBRESSL_VERSION_NUMBER)
	done = true;
	fprintf(stderr, "done = true\n");
#endif
}

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
	struct utsname utsname;

	uname(&utsname);

	fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n", utsname.sysname,
		utsname.nodename, utsname.release, utsname.version,
		utsname.machine);
	fprintf(stderr, "compiled with OpenSSL version: %s\n",
		OPENSSL_VERSION_TEXT);
#if !defined(LIBRESSL_VERSION_NUMBER) && \
	OPENSSL_VERSION_NUMBER >= 0x10100000L /* 1.1.0 or higher */
	fprintf(stderr, "linked to OpenSSL version: %s\n",
		OpenSSL_version(OPENSSL_VERSION));

#else  /* if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= \
	* 0x10100000L */
	fprintf(stderr, "linked to OpenSSL version: %s\n",
		SSLeay_version(SSLEAY_VERSION));
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

#if !defined(LIBRESSL_VERSION_NUMBER)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	CRYPTO_set_mem_functions(malloc_ex, realloc_ex, free_ex);
#else
	CRYPTO_set_mem_ex_functions(malloc_ex, realloc_ex, free_ex);
#endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	uint64_t opts = OPENSSL_INIT_ENGINE_ALL_BUILTIN |
#ifdef OPENSSL_INIT_NO_ATEXIT
			OPENSSL_INIT_NO_ATEXIT |
#endif
			OPENSSL_INIT_LOAD_CONFIG;
	OPENSSL_init_ssl(opts, NULL);
#else
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
#if !defined(OPENSSL_NO_ENGINE)
	ENGINE_load_builtin_engines();
#endif
	OpenSSL_add_all_algorithms();
	OPENSSL_load_builtin_modules();

	CONF_modules_load_file(NULL, NULL,
			       CONF_MFLAGS_DEFAULT_SECTION |
				       CONF_MFLAGS_IGNORE_MISSING_FILE);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_default_properties_enable_fips(NULL, 1);
	OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
	fprintf(stderr, "FIPS PROVIDER %s\n", fips ? "FOUND" : "NOT AVAILABLE");
	if (fips != NULL) {
		OSSL_PROVIDER_unload(fips);
	}
#endif
	ATEXIT();
}

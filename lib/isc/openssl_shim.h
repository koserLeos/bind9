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

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#if !HAVE_EVP_MD_CTX_GET0_MD
#define EVP_MD_CTX_get0_md EVP_MD_CTX_md
#endif /* if !HAVE_EVP_MD_CTX_GET0_MD */

#if !HAVE_BIO_READ_EX
int
BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
#endif

#if !HAVE_BIO_WRITE_EX
int
BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
#endif

#if !HAVE_OPENSSL_INIT_CRYPTO

#define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
#define OPENSSL_INIT_ADD_ALL_CIPHERS	    0x00000004L
#define OPENSSL_INIT_ADD_ALL_DIGESTS	    0x00000008L
#define OPENSSL_INIT_NO_ADD_ALL_CIPHERS	    0x00000010L
#define OPENSSL_INIT_NO_ADD_ALL_DIGESTS	    0x00000020L

int
OPENSSL_init_crypto(uint64_t opts, const void *settings);
#endif

#if !HAVE_OPENSSL_INIT_SSL
#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS 0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS	 0x00200000L

int
OPENSSL_init_ssl(uint64_t opts, const void *settings);

#endif

#if !HAVE_OPENSSL_CLEANUP
void
OPENSSL_cleanup(void);
#endif

#if !HAVE_X509_STORE_UP_REF
int
X509_STORE_up_ref(X509_STORE *v);
#endif /* !HAVE_OPENSSL_CLEANUP */

#if !HAVE_SSL_CTX_SET1_CERT_STORE
void
SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store);
#endif /* !HAVE_SSL_CTX_SET1_CERT_STORE */

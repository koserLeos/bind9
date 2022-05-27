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

/* ! \file */

#if HAVE_CMOCKA

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(FORCE_FIPS)
#define ISC_FIPS_MODE() true
#elif defined(HAVE_EVP_DEFAULT_PROPERTIES_ENABLE_FIPS)
#include <openssl/evp.h>
#define ISC_FIPS_MODE() EVP_default_properties_is_fips_enabled(NULL)
#elif defined(HAVE_FIPS_MODE)
#include <openssl/crypto.h>
#define ISC_FIPS_MODE() FIPS_mode()
#endif

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/hex.h>
#include <isc/hmac.h>
#include <isc/region.h>
#include <isc/result.h>

#include "../hmac.c"

#define TEST_INPUT(x) (x), sizeof(x) - 1

static int
_setup(void **state) {
	isc_hmac_t *hmac = isc_hmac_new();
	if (hmac == NULL) {
		return (-1);
	}
	*state = hmac;
	return (0);
}

static int
_teardown(void **state) {
	if (*state == NULL) {
		return (-1);
	}
	isc_hmac_free(*state);
	return (0);
}

static int
_reset(void **state) {
	if (*state == NULL) {
		return (-1);
	}
	if (isc_hmac_reset(*state) != ISC_R_SUCCESS) {
		return (-1);
	}
	return (0);
}

static void
isc_hmac_new_test(void **state) {
	UNUSED(state);

	isc_hmac_t *hmac = isc_hmac_new();
	assert_non_null(hmac);
	isc_hmac_free(hmac); /* Cleanup */
}

static void
isc_hmac_free_test(void **state) {
	UNUSED(state);

	isc_hmac_t *hmac = isc_hmac_new();
	assert_non_null(hmac);
	isc_hmac_free(hmac); /* Test freeing valid message digest context */
	isc_hmac_free(NULL); /* Test freeing NULL argument */
}

static void
isc_hmac_test(isc_hmac_t *hmac, const void *key, size_t keylen,
	      const isc_md_type_t *type, const char *buf, size_t buflen,
	      const char *result, const int repeats) {
	assert_non_null(hmac);
	assert_int_equal(isc_hmac_init(hmac, key, keylen, type), ISC_R_SUCCESS);

	int i;

	for (i = 0; i < repeats; i++) {
		assert_int_equal(isc_hmac_update(hmac,
						 (const unsigned char *)buf,
						 buflen),
				 ISC_R_SUCCESS);
	}

	unsigned char digest[ISC_MAX_MD_SIZE];
	unsigned int digestlen = sizeof(digest);
	assert_int_equal(isc_hmac_final(hmac, digest, &digestlen),
			 ISC_R_SUCCESS);

	char hexdigest[ISC_MAX_MD_SIZE * 2 + 3];
	isc_region_t r = { .base = digest, .length = digestlen };
	isc_buffer_t b;
	isc_buffer_init(&b, hexdigest, sizeof(hexdigest));

	assert_return_code(isc_hex_totext(&r, 0, "", &b), ISC_R_SUCCESS);

	assert_memory_equal(hexdigest, result, (result ? strlen(result) : 0));
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);
}

static void
isc_hmac_init_test(void **state) {
	isc_hmac_t *hmac = *state;
	assert_non_null(hmac);

	assert_int_equal(isc_hmac_init(hmac, "", 0, NULL),
			 ISC_R_NOTIMPLEMENTED);

#ifdef ISC_FIPS_MODE
	if (!ISC_FIPS_MODE())
#endif /* ifdef ISC_FIPS_MODE */
	{
		expect_assert_failure(isc_hmac_init(NULL, "", 0, ISC_MD_MD5));

		expect_assert_failure(isc_hmac_init(hmac, NULL, 0, ISC_MD_MD5));

		assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_MD5),
				 ISC_R_SUCCESS);
		assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);
	}

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA1),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA224),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA256),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA384),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA512),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);
}

static void
isc_hmac_update_test(void **state) {
	isc_hmac_t *hmac = *state;
	assert_non_null(hmac);

	/* Uses message digest context initialized in isc_hmac_init_test() */
	expect_assert_failure(isc_hmac_update(NULL, NULL, 0));

	assert_int_equal(isc_hmac_update(hmac, NULL, 100), ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_update(hmac, (const unsigned char *)"", 0),
			 ISC_R_SUCCESS);
}

static void
isc_hmac_reset_test(void **state) {
	isc_hmac_t *hmac = *state;
#if 0
	unsigned char digest[ISC_MAX_MD_SIZE] __attribute((unused));
	unsigned int digestlen __attribute((unused));
#endif /* if 0 */

	assert_non_null(hmac);

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA512),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_update(hmac, (const unsigned char *)"a", 1),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_hmac_update(hmac, (const unsigned char *)"b", 1),
			 ISC_R_SUCCESS);

	assert_int_equal(isc_hmac_reset(hmac), ISC_R_SUCCESS);

#if 0
	/*
	 * This test would require OpenSSL compiled with mock_assert(),
	 * so this could be only manually checked that the test will
	 * segfault when called by hand
	 */
	expect_assert_failure(isc_hmac_final(hmac,digest,&digestlen));
#endif /* if 0 */
}

static void
isc_hmac_final_test(void **state) {
	isc_hmac_t *hmac = *state;
	assert_non_null(hmac);

	unsigned char digest[ISC_MAX_MD_SIZE];
	unsigned int digestlen = sizeof(digest);

	/* Fail when message digest context is empty */
	expect_assert_failure(isc_hmac_final(NULL, digest, &digestlen));
	/* Fail when output buffer is empty */
	expect_assert_failure(isc_hmac_final(hmac, NULL, &digestlen));

	assert_int_equal(isc_hmac_init(hmac, "", 0, ISC_MD_SHA512),
			 ISC_R_SUCCESS);
	/* Fail when the digest length pointer is empty */
	expect_assert_failure(isc_hmac_final(hmac, digest, NULL));
}

static void
isc_hmac_md5_test(void **state) {
	isc_hmac_t *hmac = *state;

#ifdef ISC_FIPS_MODE
	if (ISC_FIPS_MODE()) {
		skip();
		return;
	}
#endif

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_MD5, TEST_INPUT(""),
		      "74E6F7298A9C2D168935F58C001BAD88", 1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_MD5,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "9294727A3638BB1C13F48EF8158BFC9D", 1);

	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_MD5,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79"
				 "\x61\x20\x77\x61\x6e\x74\x20\x66\x6f"
				 "\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "750C783E6AB0B503EAA86E310A5DB738", 1);

	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_MD5,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "56BE34521D144C88DBB8C733F0E8B3F6", 1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_MD5,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "697EAF0ACA3A3AEA3A75164746FFAA79", 1);
#if 0
	/* Test 5 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_MD5,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
	/* Test 6 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_MD5,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "AA4AE5E15272D00E95705637CE8A3B55ED402112",
		      1);
	/* Test 7 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_MD5,
		      TEST_INPUT("Test Using Larger Than Block-Size Key and "
				 "Larger Than One Block-Size Data"),
		      "E8E99D0F45237D786D6BBAA7965C7808BBFF1A91",
		      1);
#endif /* if 0 */
}

static void
isc_hmac_sha1_test(void **state) {
	isc_hmac_t *hmac = *state;

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_SHA1, TEST_INPUT(""),
		      "FBDB1D1B18AA6C08324B7D64B71FB76370690E1D", 1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_SHA1,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "B617318655057264E28BC0B6FB378C8EF146BE00", 1);
	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_SHA1,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				 "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79", 1);
	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA1,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "125D7342B9AC11CD91A39AF48AA17B4F63F175D3", 1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_SHA1,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "4C9007F4026250C6BC8414F9BF50C86C2D7235DA", 1);
#if 0
	/* Test 5 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_SHA1,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
#endif /* if 0 */
	/* Test 6 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA1,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "AA4AE5E15272D00E95705637CE8A3B55ED402112", 1);
	/* Test 7 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA1,
		      TEST_INPUT("Test Using Larger Than Block-Size Key and "
				 "Larger Than One Block-Size Data"),
		      "E8E99D0F45237D786D6BBAA7965C7808BBFF1A91", 1);
}

static void
isc_hmac_sha224_test(void **state) {
	isc_hmac_t *hmac = *state;

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_SHA224, TEST_INPUT(""),
		      "5CE14F72894662213E2748D2A6BA234B74263910CEDDE2F5"
		      "A9271524",
		      1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_SHA224,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "896FB1128ABBDF196832107CD49DF33F47B4B1169912BA"
		      "4F53684B22",
		      1);
	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_SHA224,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				 "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E61480"
		      "08FD05E44",
		      1);
	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA224,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "7FB3CB3588C6C1F6FFA9694D7D6AD2649365B0C1F65D69"
		      "D1EC8333EA",
		      1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_SHA224,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "6C11506874013CAC6A2ABC1BB382627CEC6A90D86EFC01"
		      "2DE7AFEC5A",
		      1);
#if 0
	/* Test 5 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_SHA224,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
#endif /* if 0 */
	/* Test 6 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA224,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "95E9A0DB962095ADAEBE9B2D6F0DBCE2D499F112F2D2B7"
		      "273FA6870E",
		      1);
	/* Test 7 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA224,
		      TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				 "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				 "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				 "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				 "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				 "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				 "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				 "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				 "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				 "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				 "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				 "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				 "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				 "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				 "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				 "\x6d\x2e"),
		      "3A854166AC5D9F023F54D517D0B39DBD946770DB9C2B95"
		      "C9F6F565D1",
		      1);
}

static void
isc_hmac_sha256_test(void **state) {
	isc_hmac_t *hmac = *state;

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_SHA256, TEST_INPUT(""),
		      "B613679A0814D9EC772F95D778C35FC5FF1697C493715653"
		      "C6C712144292C5AD",
		      1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_SHA256,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833D"
		      "A726E9376C2E32CFF7",
		      1);
	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_SHA256,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				 "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "5BDCC146BF60754E6A042426089575C75A003F089D2739"
		      "839DEC58B964EC3843",
		      1);
	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA256,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "773EA91E36800E46854DB8EBD09181A72959098B3EF8C1"
		      "22D9635514CED565FE",
		      1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_SHA256,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8"
		      "077A2E3FF46729665B",
		      1);
#if 0
	/* Test 5 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_SHA256,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
#endif /* if 0 */
	/* Test 6 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA256,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5"
		      "140546040F0EE37F54",
		      1);
	/* Test 7 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA256,
		      TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				 "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				 "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				 "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				 "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				 "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				 "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				 "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				 "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				 "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				 "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				 "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				 "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				 "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				 "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				 "\x6d\x2e"),
		      "9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713"
		      "938A7F51535C3A35E2",
		      1);
}

static void
isc_hmac_sha384_test(void **state) {
	isc_hmac_t *hmac = *state;

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_SHA384, TEST_INPUT(""),
		      "6C1F2EE938FAD2E24BD91298474382CA218C75DB3D83E114"
		      "B3D4367776D14D3551289E75E8209CD4B792302840234ADC",
		      1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_SHA384,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "AFD03944D84895626B0825F4AB46907F15F9DADBE4101E"
		      "C682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152"
		      "E8B2FA9CB6",
		      1);
	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_SHA384,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				 "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B"
		      "47E42EC3736322445E8E2240CA5E69E2C78B3239"
		      "ECFAB21649",
		      1);
	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA384,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9F"
		      "EBE83EF4E55966144B2A5AB39DC13814B94E3AB6"
		      "E101A34F27",
		      1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_SHA384,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "3E8A69B7783C25851933AB6290AF6CA77A998148085000"
		      "9CC5577C6E1F573B4E6801DD23C4A7D679CCF8A3"
		      "86C674CFFB",
		      1);
#if 0
	/* Test 5 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_SHA384,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
#endif /* if 0 */
	/* Test 6 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA384,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B58"
		      "8F3CD11F05033AC4C60C2EF6AB4030FE8296248D"
		      "F163F44952",
		      1);
	/* Test 7 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA384,
		      TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				 "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				 "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				 "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				 "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				 "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				 "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				 "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				 "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				 "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				 "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				 "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				 "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				 "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				 "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				 "\x6d\x2e"),
		      "6617178E941F020D351E2F254E8FD32C602420FEB0B8FB"
		      "9ADCCEBB82461E99C5A678CC31E799176D3860E6"
		      "110C46523E",
		      1);
}

static void
isc_hmac_sha512_test(void **state) {
	isc_hmac_t *hmac = *state;

	/* Test 0 */
	isc_hmac_test(hmac, TEST_INPUT(""), ISC_MD_SHA512, TEST_INPUT(""),
		      "B936CEE86C9F87AA5D3C6F2E84CB5A4239A5FE50480A6EC6"
		      "6B70AB5B1F4AC6730C6C515421B327EC1D69402E53DFB49A"
		      "D7381EB067B338FD7B0CB22247225D47",
		      1);

	/* Test 1 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		      ISC_MD_SHA512,
		      TEST_INPUT("\x48\x69\x20\x54\x68\x65\x72\x65"),
		      "87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2"
		      "787AD0B30545E17CDEDAA833B7D6B8A702038B27"
		      "4EAEA3F4E4BE9D914EEB61F1702E696C203A126854",
		      1);
	/* Test 2 */
	isc_hmac_test(hmac, TEST_INPUT("Jefe"), ISC_MD_SHA512,
		      TEST_INPUT("\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61"
				 "\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
				 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f"),
		      "164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831F"
		      "D610270CD7EA2505549758BF75C05A994A6D034F"
		      "65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737",
		      1);
	/* Test 3 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"),
		      ISC_MD_SHA512,
		      TEST_INPUT("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
				 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"),
		      "FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A"
		      "3655F83E33B2279D39BF3E848279A722C806B485"
		      "A47E67C807B946A337BEE8942674278859E13292FB",
		      1);
	/* Test 4 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
				 "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
				 "\x15\x16\x17\x18\x19"),
		      ISC_MD_SHA512,
		      TEST_INPUT("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
				 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"),
		      "B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B87"
		      "2DE76F8050361EE3DBA91CA5C11AA25EB4D67927"
		      "5CC5788063A5F19741120C4F2DE2ADEBEB10A298DD",
		      1);
#if 0
	/* Test 5 -- unimplemented optional functionality */
	isc_hmac_test(hmac,
		      TEST_INPUT("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				 "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"),
		      ISC_MD_SHA512,
		      TEST_INPUT("Test With Truncation"),
		      "4C1A03424B55E07FE7F27BE1",
		      1);
#endif /* if 0 */
	/* Test 6 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA512,
		      TEST_INPUT("Test Using Larger Than Block-Size Key - "
				 "Hash Key First"),
		      "80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEE"
		      "C1121B013783F8F3526B56D037E05F2598BD0FD2"
		      "215D6A1E5295E64F73F63F0AEC8B915A985D786598",
		      1);
	/* Test 7 */
	isc_hmac_test(hmac,
		      TEST_INPUT("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				 "\xaa"),
		      ISC_MD_SHA512,
		      TEST_INPUT("\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20"
				 "\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67"
				 "\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20"
				 "\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b"
				 "\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20"
				 "\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67"
				 "\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c"
				 "\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"
				 "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
				 "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74"
				 "\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65"
				 "\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62"
				 "\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20"
				 "\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41"
				 "\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68"
				 "\x6d\x2e"),
		      "E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289"
		      "865DF5A32D20CDC944B6022CAC3C4982B10D5EEB"
		      "55C3E4DE15134676FB6DE0446065C97440FA8C6A58",
		      1);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		/* isc_hmac_new() */
		cmocka_unit_test(isc_hmac_new_test),

		/* isc_hmac_init() */
		cmocka_unit_test_setup_teardown(isc_hmac_init_test, _reset,
						_reset),

		/* isc_hmac_reset() */
		cmocka_unit_test_setup_teardown(isc_hmac_reset_test, _reset,
						_reset),

		/* isc_hmac_init() -> isc_hmac_update() -> isc_hmac_final() */
		cmocka_unit_test(isc_hmac_md5_test),
		cmocka_unit_test(isc_hmac_sha1_test),
		cmocka_unit_test(isc_hmac_sha224_test),
		cmocka_unit_test(isc_hmac_sha256_test),
		cmocka_unit_test(isc_hmac_sha384_test),
		cmocka_unit_test(isc_hmac_sha512_test),

		cmocka_unit_test_setup_teardown(isc_hmac_update_test, _reset,
						_reset),
		cmocka_unit_test_setup_teardown(isc_hmac_final_test, _reset,
						_reset),

		cmocka_unit_test(isc_hmac_free_test),
	};

	return (cmocka_run_group_tests(tests, _setup, _teardown));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */

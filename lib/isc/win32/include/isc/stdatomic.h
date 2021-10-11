/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0.  If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <intrin.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uchar.h>
#include <windows.h>

#pragma warning(disable : 4133)
#pragma warning(disable : 4090)

#define InterlockedExchangeAdd8	    _InterlockedExchangeAdd8
#define InterlockedCompareExchange8 _InterlockedCompareExchange8

#pragma intrinsic(_InterlockedCompareExchange8, _InterlockedExchangeAdd8)

#include <isc/util.h>

#ifndef __ATOMIC_RELAXED
#define __ATOMIC_RELAXED 0
#endif /* ifndef __ATOMIC_RELAXED */
#ifndef __ATOMIC_CONSUME
#define __ATOMIC_CONSUME 1
#endif /* ifndef __ATOMIC_CONSUME */
#ifndef __ATOMIC_ACQUIRE
#define __ATOMIC_ACQUIRE 2
#endif /* ifndef __ATOMIC_ACQUIRE */
#ifndef __ATOMIC_RELEASE
#define __ATOMIC_RELEASE 3
#endif /* ifndef __ATOMIC_RELEASE */
#ifndef __ATOMIC_ACQ_REL
#define __ATOMIC_ACQ_REL 4
#endif /* ifndef __ATOMIC_ACQ_REL */
#ifndef __ATOMIC_SEQ_CST
#define __ATOMIC_SEQ_CST 5
#endif /* ifndef __ATOMIC_SEQ_CST */

enum memory_order {
	memory_order_relaxed = __ATOMIC_RELAXED,
	memory_order_consume = __ATOMIC_CONSUME,
	memory_order_acquire = __ATOMIC_ACQUIRE,
	memory_order_release = __ATOMIC_RELEASE,
	memory_order_acq_rel = __ATOMIC_ACQ_REL,
	memory_order_seq_cst = __ATOMIC_SEQ_CST
};

typedef enum memory_order memory_order;

/*
 * If you add a type with different sizeof() length,
 * you need to implement atomic_<foo>_explicitNN macros.
 */

typedef bool volatile atomic_bool;
typedef char volatile atomic_char;
typedef signed char volatile atomic_schar;
typedef unsigned char volatile atomic_uchar;
typedef short volatile atomic_short;
typedef unsigned short volatile atomic_ushort;
typedef int volatile atomic_int;
typedef unsigned int volatile atomic_uint;
typedef long volatile atomic_long;
typedef unsigned long volatile atomic_ulong;
typedef long long volatile atomic_llong;
typedef unsigned long long volatile atomic_ullong;
typedef char16_t volatile atomic_char16_t;
typedef char32_t volatile atomic_char32_t;
typedef wchar_t volatile atomic_wchar_t;
typedef int_least8_t volatile atomic_int_least8_t;
typedef uint_least8_t volatile atomic_uint_least8_t;
typedef int_least16_t volatile atomic_int_least16_t;
typedef uint_least16_t volatile atomic_uint_least16_t;
typedef int_least32_t volatile atomic_int_least32_t;
typedef uint_least32_t volatile atomic_uint_least32_t;
typedef int_least64_t volatile atomic_int_least64_t;
typedef uint_least64_t volatile atomic_uint_least64_t;
typedef int_fast8_t volatile atomic_int_fast8_t;
typedef uint_fast8_t volatile atomic_uint_fast8_t;
typedef int_fast16_t volatile atomic_int_fast16_t;
typedef uint_fast16_t volatile atomic_uint_fast16_t;
typedef int_fast32_t volatile atomic_int_fast32_t;
typedef uint_fast32_t volatile atomic_uint_fast32_t;
typedef int_fast64_t volatile atomic_int_fast64_t;
typedef uint_fast64_t volatile atomic_uint_fast64_t;
typedef intptr_t volatile atomic_intptr_t;
typedef uintptr_t volatile atomic_uintptr_t;
typedef size_t volatile atomic_size_t;
typedef ptrdiff_t volatile atomic_ptrdiff_t;
typedef intmax_t volatile atomic_intmax_t;
typedef uintmax_t volatile atomic_uintmax_t;

#define atomic_init(obj, desired) (*(obj) = (desired))

#define atomic_store_explicit8(obj, desired, order) \
	(void)InterlockedExchange8((atomic_int_fast8_t *)obj, desired)

#define atomic_store_explicit16(obj, desired, order)                           \
	(order == memory_order_relaxed                                         \
		 ? (void)InterlockedExchangeNoFence16((atomic_short *)obj,     \
						      desired)                 \
		 : (order == memory_order_acquire                              \
			    ? (void)InterlockedExchangeAcquire16(              \
				      (atomic_short *)obj, desired)            \
			    : (void)InterlockedExchange16((atomic_short *)obj, \
							  desired)))

#define atomic_store_explicit32(obj, desired, order)                       \
	(order == memory_order_relaxed                                     \
		 ? (void)InterlockedExchangeNoFence(                       \
			   (atomic_int_fast32_t *)obj, desired)            \
		 : (order == memory_order_acquire                          \
			    ? (void)InterlockedExchangeAcquire(            \
				      (atomic_int_fast32_t *)obj, desired) \
			    : (void)InterlockedExchange(                   \
				      (atomic_int_fast32_t *)obj, desired)))

#ifdef _WIN64
#define atomic_store_explicit64(obj, desired, order)                       \
	(order == memory_order_relaxed                                     \
		 ? (void)InterlockedExchangeNoFence64(                     \
			   (atomic_int_fast64_t *)obj, desired)            \
		 : (order == memory_order_acquire                          \
			    ? (void)InterlockedExchangeAcquire64(          \
				      (atomic_int_fast64_t *)obj, desired) \
			    : (void)InterlockedExchange64(                 \
				      (atomic_int_fast64_t *)obj, desired)))
#else /* ifdef _WIN64 */
#define atomic_store_explicit64(obj, desired, order) \
	(void)InterlockedExchange64((atomic_int_fast64_t *)obj, desired)
#endif /* ifdef _WIN64 */

static inline void
atomic_store_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_store_explicit(obj, desired, order)                             \
	(sizeof(*(obj)) == 8                                                   \
		 ? atomic_store_explicit64(obj, desired, order)                \
		 : (sizeof(*(obj)) == 4                                        \
			    ? atomic_store_explicit32(obj, desired, order)     \
			    : (sizeof(*(obj)) == 2                             \
				       ? atomic_store_explicit16(obj, desired, \
								 order)        \
				       : (sizeof(*(obj)) == 1                  \
						  ? atomic_store_explicit8(    \
							    obj, desired,      \
							    order)             \
						  : atomic_store_abort()))))

#define atomic_store(obj, desired) \
	atomic_store_explicit(obj, desired, memory_order_seq_cst)

#define atomic_load_explicit8(obj, order) \
	(int8_t) InterlockedOr8((atomic_int_fast8_t *)obj, 0)

#define atomic_load_explicit16(obj, order) \
	(short)InterlockedOr16((atomic_short *)obj, 0)

#define atomic_load_explicit32(obj, order)                                      \
	(order == memory_order_relaxed                                          \
		 ? (int32_t)InterlockedOrNoFence((atomic_int_fast32_t *)obj,    \
						 0)                             \
		 : (order == memory_order_acquire                               \
			    ? (int32_t)InterlockedOrAcquire(                    \
				      (atomic_int_fast32_t *)obj, 0)            \
			    : (order == memory_order_release                    \
				       ? (int32_t)InterlockedOrRelease(         \
						 (atomic_int_fast32_t *)obj, 0) \
				       : (int32_t)InterlockedOr(                \
						 (atomic_int_fast32_t *)obj,    \
						 0))))

#ifdef _WIN64
#define atomic_load_explicit64(obj, order)                                      \
	(order == memory_order_relaxed                                          \
		 ? InterlockedOr64NoFence((atomic_int_fast64_t *)obj, 0)        \
		 : (order == memory_order_acquire                               \
			    ? InterlockedOr64Acquire(                           \
				      (atomic_int_fast64_t *)obj, 0)            \
			    : (order == memory_order_release                    \
				       ? InterlockedOr64Release(                \
						 (atomic_int_fast64_t *)obj, 0) \
				       : InterlockedOr64(                       \
						 (atomic_int_fast64_t *)obj,    \
						 0))))
#else /* ifdef _WIN64 */
#define atomic_load_explicit64(obj, order) \
	InterlockedOr64((atomic_int_fast64_t *)obj, 0)
#endif /* ifdef _WIN64 */

static inline int8_t
atomic_load_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_load_explicit(obj, order)                                       \
	(((sizeof(*(obj)) == 8)                                                \
		  ? atomic_load_explicit64(obj, order)                         \
		  : ((sizeof(*(obj)) == 4)                                     \
			     ? atomic_load_explicit32(obj, order)              \
			     : ((sizeof(*(obj)) == 2)                          \
					? atomic_load_explicit16(obj, order)   \
					: ((sizeof(*(obj)) == 1)               \
						   ? atomic_load_explicit8(    \
							     obj, order)       \
						   : atomic_load_abort())))) & \
	 ((sizeof(*(obj)) == 8)                                                \
		  ? 0xffffffffffffffffULL                                      \
		  : ((sizeof(*(obj)) == 4)                                     \
			     ? 0xffffffffULL                                   \
			     : ((sizeof(*(obj)) == 2)                          \
					? 0xffffULL                            \
					: ((sizeof(*(obj)) == 1)               \
						   ? 0xffULL                   \
						   : atomic_load_abort())))))

#define atomic_load(obj) atomic_load_explicit(obj, memory_order_seq_cst)

#define atomic_fetch_add_explicit8(obj, arg, order) \
	InterlockedExchangeAdd8((atomic_int_fast8_t *)obj, arg)

#define atomic_fetch_add_explicit16(obj, arg, order) \
	InterlockedExchangeAdd16((atomic_short *)obj, arg)

#define atomic_fetch_add_explicit32(obj, arg, order)                         \
	(order == memory_order_relaxed                                       \
		 ? InterlockedExchangeAddNoFence((atomic_int_fast32_t *)obj, \
						 arg)                        \
		 : (order == memory_order_acquire                            \
			    ? InterlockedExchangeAddAcquire(                 \
				      (atomic_int_fast32_t *)obj, arg)       \
			    : (order == memory_order_release                 \
				       ? InterlockedExchangeAddRelease(      \
						 (atomic_int_fast32_t *)obj, \
						 arg)                        \
				       : InterlockedExchangeAdd(             \
						 (atomic_int_fast32_t *)obj, \
						 arg))))

#ifdef _WIN64
#define atomic_fetch_add_explicit64(obj, arg, order)                           \
	(order == memory_order_relaxed                                         \
		 ? InterlockedExchangeAddNoFence64((atomic_int_fast64_t *)obj, \
						   arg)                        \
		 : (order == memory_order_acquire                              \
			    ? InterlockedExchangeAddAcquire64(                 \
				      (atomic_int_fast64_t *)obj, arg)         \
			    : (order == memory_order_release                   \
				       ? InterlockedExchangeAddRelease64(      \
						 (atomic_int_fast64_t *)obj,   \
						 arg)                          \
				       : InterlockedExchangeAdd64(             \
						 (atomic_int_fast64_t *)obj,   \
						 arg))))
#else /* ifdef _WIN64 */
#define atomic_fetch_add_explicit64(obj, arg, order) \
	InterlockedExchangeAdd64((atomic_int_fast64_t *)obj, arg)
#endif /* ifdef _WIN64 */

static inline int8_t
atomic_add_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_fetch_add_explicit(obj, arg, order)                              \
	(sizeof(*(obj)) == 8                                                    \
		 ? atomic_fetch_add_explicit64(obj, arg, order)                 \
		 : (sizeof(*(obj)) == 4                                         \
			    ? atomic_fetch_add_explicit32(obj, arg, order)      \
			    : (sizeof(*(obj)) == 2                              \
				       ? atomic_fetch_add_explicit16(obj, arg,  \
								     order)     \
				       : (sizeof(*(obj)) == 1                   \
						  ? atomic_fetch_add_explicit8( \
							    obj, arg, order)    \
						  : atomic_add_abort()))))

#define atomic_fetch_add(obj, arg) \
	atomic_fetch_add_explicit(obj, arg, memory_order_seq_cst)

#define atomic_fetch_sub_explicit(obj, arg, order) \
	atomic_fetch_add_explicit(obj, -arg, order)

#define atomic_fetch_sub(obj, arg) \
	atomic_fetch_sub_explicit(obj, arg, memory_order_seq_cst)

#define atomic_fetch_and_explicit8(obj, arg, order) \
	InterlockedAnd8((atomic_int_fast8_t *)obj, arg)

#define atomic_fetch_and_explicit16(obj, arg, order) \
	InterlockedAnd16((atomic_short *)obj, arg)

#define atomic_fetch_and_explicit32(obj, arg, order)                         \
	(order == memory_order_relaxed                                       \
		 ? InterlockedAndNoFence((atomic_int_fast32_t *)obj, arg)    \
		 : (order == memory_order_acquire                            \
			    ? InterlockedAndAcquire(                         \
				      (atomic_int_fast32_t *)obj, arg)       \
			    : (order == memory_order_release                 \
				       ? InterlockedAndRelease(              \
						 (atomic_int_fast32_t *)obj, \
						 arg)                        \
				       : InterlockedAnd(                     \
						 (atomic_int_fast32_t *)obj, \
						 arg))))

#ifdef _WIN64
#define atomic_fetch_and_explicit64(obj, arg, order)                         \
	(order == memory_order_relaxed                                       \
		 ? InterlockedAnd64NoFence((atomic_int_fast64_t *)obj, arg)  \
		 : (order == memory_order_acquire                            \
			    ? InterlockedAnd64Acquire(                       \
				      (atomic_int_fast64_t *)obj, arg)       \
			    : (order == memory_order_release                 \
				       ? InterlockedAnd64Release(            \
						 (atomic_int_fast64_t *)obj, \
						 arg)                        \
				       : InterlockedAnd64(                   \
						 (atomic_int_fast64_t *)obj, \
						 arg))))
#else /* ifdef _WIN64 */
#define atomic_fetch_and_explicit64(obj, arg, order) \
	InterlockedAnd64((atomic_int_fast64_t *)obj, arg)
#endif /* ifdef _WIN64 */

static inline int8_t
atomic_and_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_fetch_and_explicit(obj, arg, order)                              \
	(sizeof(*(obj)) == 8                                                    \
		 ? atomic_fetch_and_explicit64(obj, arg, order)                 \
		 : (sizeof(*(obj)) == 4                                         \
			    ? atomic_fetch_and_explicit32(obj, arg, order)      \
			    : (sizeof(*(obj)) == 2                              \
				       ? atomic_fetch_and_explicit16(obj, arg,  \
								     order)     \
				       : (sizeof(*(obj)) == 1                   \
						  ? atomic_fetch_and_explicit8( \
							    obj, arg, order)    \
						  : atomic_and_abort()))))

#define atomic_fetch_and(obj, arg) \
	atomic_fetch_and_explicit(obj, arg, memory_order_seq_cst)

#define atomic_fetch_or_explicit8(obj, arg, order) \
	InterlockedOr8((atomic_int_fast8_t *)obj, arg)

#define atomic_fetch_or_explicit16(obj, arg, order) \
	InterlockedOr16((atomic_short *)obj, arg)

#define atomic_fetch_or_explicit32(obj, arg, order)                            \
	(order == memory_order_relaxed                                         \
		 ? InterlockedOrNoFence((atomic_int_fast32_t *)obj, arg)       \
		 : (order == memory_order_acquire                              \
			    ? InterlockedOrAcquire((atomic_int_fast32_t *)obj, \
						   arg)                        \
			    : (order == memory_order_release                   \
				       ? InterlockedOrRelease(                 \
						 (atomic_int_fast32_t *)obj,   \
						 arg)                          \
				       : InterlockedOr(                        \
						 (atomic_int_fast32_t *)obj,   \
						 arg))))

#ifdef _WIN64
#define atomic_fetch_or_explicit64(obj, arg, order)                          \
	(order == memory_order_relaxed                                       \
		 ? InterlockedOr64NoFence((atomic_int_fast64_t *)obj, arg)   \
		 : (order == memory_order_acquire                            \
			    ? InterlockedOr64Acquire(                        \
				      (atomic_int_fast64_t *)obj, arg)       \
			    : (order == memory_order_release                 \
				       ? InterlockedOr64Release(             \
						 (atomic_int_fast64_t *)obj, \
						 arg)                        \
				       : InterlockedOr64(                    \
						 (atomic_int_fast64_t *)obj, \
						 arg))))
#else /* ifdef _WIN64 */
#define atomic_fetch_or_explicit64(obj, arg, order) \
	InterlockedOr64((atomic_int_fast64_t *)obj, arg)
#endif /* ifdef _WIN64 */

static inline int8_t
atomic_or_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_fetch_or_explicit(obj, arg, order)                              \
	(sizeof(*(obj)) == 8                                                   \
		 ? atomic_fetch_or_explicit64(obj, arg, order)                 \
		 : (sizeof(*(obj)) == 4                                        \
			    ? atomic_fetch_or_explicit32(obj, arg, order)      \
			    : (sizeof(*(obj)) == 2                             \
				       ? atomic_fetch_or_explicit16(obj, arg,  \
								    order)     \
				       : (sizeof(*(obj)) == 1                  \
						  ? atomic_fetch_or_explicit8( \
							    obj, arg, order)   \
						  : atomic_or_abort()))))

#define atomic_fetch_or(obj, arg) \
	atomic_fetch_or_explicit(obj, arg, memory_order_seq_cst)

static inline bool
atomic_compare_exchange_strong_explicit8(atomic_int_fast8_t *obj,
					 int8_t *expected, int8_t desired,
					 memory_order succ, memory_order fail) {
	bool   __r;
	int8_t __v;

	UNUSED(succ);
	UNUSED(fail);

	__v = InterlockedCompareExchange8((atomic_int_fast8_t *)obj, desired,
					  *expected);
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

static inline bool
atomic_compare_exchange_strong_explicit16(atomic_short *obj, short *expected,
					  short desired, memory_order succ,
					  memory_order fail) {
	bool  __r;
	short __v;

	UNUSED(succ);
	UNUSED(fail);

	__v = InterlockedCompareExchange16((atomic_short *)obj, desired,
					   *expected);
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

static inline bool
atomic_compare_exchange_strong_explicit32(atomic_int_fast32_t *obj,
					  int32_t *expected, int32_t desired,
					  memory_order succ,
					  memory_order fail) {
	bool	__r;
	int32_t __v;

	UNUSED(succ);
	UNUSED(fail);

	switch (succ) {
	case memory_order_relaxed:
		__v = InterlockedCompareExchangeNoFence(
			(atomic_int_fast32_t *)obj, desired, *expected);
		break;
	case memory_order_acquire:
		__v = InterlockedCompareExchangeAcquire(
			(atomic_int_fast32_t *)obj, desired, *expected);
		break;
	case memory_order_release:
		__v = InterlockedCompareExchangeRelease(
			(atomic_int_fast32_t *)obj, desired, *expected);
		break;
	default:
		__v = InterlockedCompareExchange((atomic_int_fast32_t *)obj,
						 desired, *expected);
		break;
	}
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

static inline bool
atomic_compare_exchange_strong_explicit64(atomic_int_fast64_t *obj,
					  int64_t *expected, int64_t desired,
					  memory_order succ,
					  memory_order fail) {
	bool	__r;
	int64_t __v;

	UNUSED(succ);
	UNUSED(fail);

#ifdef _WIN64
	switch (succ) {
	case memory_order_relaxed:
		__v = InterlockedCompareExchangeNoFence64(
			(atomic_int_fast64_t *)obj, desired, *expected);
		break;
	case memory_order_acquire:
		__v = InterlockedCompareExchangeAcquire64(
			(atomic_int_fast64_t *)obj, desired, *expected);
		break;
	case memory_order_release:
		__v = InterlockedCompareExchangeRelease64(
			(atomic_int_fast64_t *)obj, desired, *expected);
		break;
	default:
		__v = InterlockedCompareExchange64((atomic_int_fast64_t *)obj,
						   desired, *expected);
		break;
	}
#else  /* ifdef _WIN64 */
	__v = InterlockedCompareExchange64((atomic_int_fast64_t *)obj, desired,
					   *expected);
#endif /* ifdef _WIN64 */
	__r = (*(expected) == __v);
	if (!__r) {
		*(expected) = __v;
	}
	return (__r);
}

static inline bool
atomic_compare_exchange_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ,                 \
						fail)                                         \
	(sizeof(*(obj)) == 8                                                                  \
		 ? atomic_compare_exchange_strong_explicit64(                                 \
			   obj, expected, desired, succ, fail)                                \
		 : (sizeof(*(obj)) == 4                                                       \
			    ? atomic_compare_exchange_strong_explicit32(                      \
				      obj, expected, desired, succ, fail)                     \
			    : (sizeof(*(obj)) == 2                                            \
				       ? atomic_compare_exchange_strong_explicit16(           \
						 obj, expected, desired, succ,                \
						 fail)                                        \
				       : (sizeof(*(obj)) == 1                                 \
						  ? atomic_compare_exchange_strong_explicit8( \
							    obj, expected,                    \
							    desired, succ,                    \
							    fail)                             \
						  : atomic_compare_exchange_abort()))))

#define atomic_compare_exchange_strong(obj, expected, desired)          \
	atomic_compare_exchange_strong_explicit(obj, expected, desired, \
						memory_order_seq_cst,   \
						memory_order_seq_cst)

#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ,   \
					      fail)                           \
	atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, \
						fail)

#define atomic_compare_exchange_weak(obj, expected, desired)          \
	atomic_compare_exchange_weak_explicit(obj, expected, desired, \
					      memory_order_seq_cst,   \
					      memory_order_seq_cst)

static inline bool
atomic_exchange_abort() {
	UNREACHABLE();
	ISC_UNREACHABLE();
}

#define atomic_exchange_explicit(obj, desired, order)                        \
	(sizeof(*(obj)) == 8                                                 \
		 ? InterlockedExchange64(obj, desired)                       \
		 : (sizeof(*(obj)) == 4                                      \
			    ? InterlockedExchange(obj, desired)              \
			    : (sizeof(*(obj)) == 2                           \
				       ? InterlockedExchange16(obj, desired) \
				       : (sizeof(*(obj)) == 1                \
						  ? InterlockedExchange8(    \
							    obj, desired)    \
						  : atomic_exchange_abort()))))

#define atomic_exchange(obj, desired) \
	atomic_exchange_explicit(obj, desired, memory_order_seq_cst)

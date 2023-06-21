#!/bin/sh
export CLANG_VERSION="16"
export CLANG="clang-${CLANG_VERSION}"
export SCAN_BUILD="scan-build-${CLANG_VERSION}"
export LLVM_SYMBOLIZER="/usr/lib/llvm-${CLANG_VERSION}/bin/llvm-symbolizer"
export ASAN_SYMBOLIZER_PATH="/usr/lib/llvm-${CLANG_VERSION}/bin/llvm-symbolizer"
export CLANG_FORMAT="clang-format-${CLANG_VERSION}"

export CFLAGS_COMMON="-fno-omit-frame-pointer -fno-optimize-sibling-calls -O1 -g -Wall -Wextra"

# Pass run-time flags to AddressSanitizer to get core dumps on error.
export ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:unmap_shadow_on_exit=1"

export TSAN_OPTIONS_COMMON="disable_coredump=0 second_deadlock_stack=1 atexit_sleep_ms=1000 history_size=7 log_exe_name=true log_path=tsan"
export TSAN_SUPPRESSIONS="suppressions=${PWD}/.tsan-suppress"
export TSAN_OPTIONS_DEBIAN="${TSAN_OPTIONS_COMMON} ${TSAN_SUPPRESSIONS} external_symbolizer_path=${LLVM_SYMBOLIZER}"
export TSAN_OPTIONS_FEDORA="${TSAN_OPTIONS_COMMON} ${TSAN_SUPPRESSIONS} external_symbolizer_path=/usr/bin/llvm-symbolizer"
export TSAN_OPTIONS="${TSAN_OPTIONS_DEBIAN}"

export CC="${CLANG}"
export CFLAGS="${CFLAGS_COMMON} -fsanitize=thread"
export LDFLAGS="-fsanitize=thread"


autoreconf -fi
./configure --disable-maintainer-mode --enable-developer --enable-option-checking=fatal --enable-dnstap --with-cmocka --with-libxml2 --with-json-c --with-libidn2 --enable-pthread-rwlock --without-jemalloc
make -k all


cd bin/tests/system
sh ifconfig.sh up

pytest-3 -n auto

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="-p ${PORT}"

status=0
n=1

echo_i "check PROTOSS option is logged correctly ($n)"
ret=0
nextpart ns2/named.run > /dev/null
$PYTHON protoss.py ${PORT} > /dev/null
nextpart ns2/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 8 ] || ret=1
grep "ipv4:10.0.0.4/org:1816793" protoss.out > /dev/null || ret=1
grep "ipv4:10.0.0.4/org:1816793/dev:deadbeef" protoss.out > /dev/null || ret=1
grep "ipv6:fe0f::1/org:1816793/dev:deadbeef" protoss.out > /dev/null || ret=1
grep "ipv4:10.0.0.4/org:1816793/va:30280231" protoss.out > /dev/null || ret=1
grep '(F)' protoss.out > /dev/null || ret=1
grep '(N)' protoss.out > /dev/null || ret=1
grep '(FN)' protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check PROTOSS option with duplicate identify field is logged as hex ($n)"
nextpart ns2/named.run > /dev/null
$DIG $DIGOPTS +ednsopt=protoss:4f444e53010000080000000200080000000100100a000004 @10.53.0.2 -b 10.53.0.4 a.example > dig.out.ns2.test$n || ret=1
nextpart ns2/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 1 ] || ret=1
grep "4f 44 4e 53" protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check PROTOSS option with bad magic number is logged as hex ($n)"
nextpart ns2/named.run > /dev/null
$DIG $DIGOPTS +ednsopt=protoss:44444444010000080000000100100a000004 @10.53.0.2 -b 10.53.0.4 a.example > dig.out.ns2.test$n || ret=1
nextpart ns2/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 1 ] || ret=1
grep "44 44 44 44" protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1

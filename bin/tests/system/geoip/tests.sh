#!/bin/sh
#
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

status=0
n=0

rm -f dig.out.*

DIGOPTS="+tcp +short -p ${PORT} @10.53.0.2"
DIGOPTS6="+tcp +short -p ${PORT} @fd92:7065:b8e:ffff::2"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

n=`expr $n + 1`
echo_i "checking GeoIP country database by code ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP country database by code (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking response scope using client subnet ($n)"
ret=0
$DIG +tcp -p ${PORT} @10.53.0.2 txt example -b 127.0.0.1 +subnet="10.53.0.1/32" > dig.out.ns2.test$n.1 || ret=1
grep 'CLIENT-SUBNET.*10.53.0.1/32/32' dig.out.ns2.test$n.1 > /dev/null || ret=1
$DIG +tcp -p ${PORT} @10.53.0.2 txt example -b 127.0.0.1 +subnet="192.0.2.64/32" > dig.out.ns2.test$n.2 || ret=1
grep 'CLIENT-SUBNET.*192.0.2.64/32/24' dig.out.ns2.test$n.2 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named2.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP country database by three-letter code ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named3.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP country database by name ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named4.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP region code, no specified database ($n)"
ret=0
lret=0
# skipping 2 on purpose here; it has the same region code as 1
for i in 1 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named5.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP region database by region name and country code ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP region database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`


echo_i "reloading server"
copy_setports ns2/named6.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

if $TESTSOCK6 fd92:7065:b8e:ffff::3
then
  n=`expr $n + 1`
  echo_i "checking GeoIP city database by city name using IPv6 ($n)"
  ret=0
  $DIG +tcp +short -p ${PORT} @fd92:7065:b8e:ffff::1 -6 txt example -b fd92:7065:b8e:ffff::2 > dig.out.ns2.test$n || ret=1
  [ $ret -eq 0 ] || echo_i "failed"
  status=`expr $status + $ret`
else
  echo_i "IPv6 unavailable; skipping"
fi

n=`expr $n + 1`
echo_i "checking GeoIP city database by city name ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP city database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named7.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP isp database ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP isp database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named8.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP org database ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP org database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named9.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP asnum database ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP asnum database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named10.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP asnum database - ASNNNN only ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP asnum database - ASNNNN only (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named11.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP domain database ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP domain database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named12.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP netspeed database ($n)"
ret=0
lret=0
for i in 1 2 3 4; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP netspeed database (using client subnet) ($n)"
ret=0
lret=0
for i in 1 2 3 4; do
    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named13.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP blackhole ACL ($n)"
ret=0
$DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n || ret=1
$RNDCCMD 10.53.0.2 status 2>&1 > rndc.out.ns2.test$n || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named14.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking GeoIP country database by code (using nested ACLs) ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "reloading server"
copy_setports ns2/named14.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3

n=`expr $n + 1`
echo_i "checking geoip-use-ecs ($n)"
ret=0
lret=0
for i in 1 2 3 4 5 6 7; do
    $DIG $DIGOPTS txt example -b 10.53.0.$i > dig.out.ns2.test$n.$i || lret=1
    j=`cat dig.out.ns2.test$n.$i | tr -d '"'`
    [ "$i" = "$j" ] || lret=1
    [ $lret -eq 1 ] && break

    $DIG $DIGOPTS txt example -b 127.0.0.1 +subnet="10.53.0.$i/32" > dig.out.ns2.test$n.ecs.$i || lret=1
    j=`cat dig.out.ns2.test$n.ecs.$i | tr -d '"'`
    [ "$j" = "bogus" ] || lret=1
    [ $lret -eq 1 ] && break
done
[ $lret -eq 1 ] && ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "reloading server with different geoip-directory ($n)"
copy_setports ns2/named15.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 3
awk '/using "..\/data2" as GeoIP directory/ {m=1} ; { if (m>0) { print } }' ns2/named.run | grep "GeoIP City .* DB not available" > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking GeoIP v4/v6 when only IPv6 database is available ($n)"
ret=0
$DIG $DIGOPTS -4 txt example -b 10.53.0.2 > dig.out.ns2.test$n.1 || ret=1
j=`cat dig.out.ns2.test$n.1 | tr -d '"'`
[ "$j" = "bogus" ] || ret=1
if $TESTSOCK6 fd92:7065:b8e:ffff::2; then
    $DIG $DIGOPTS6 txt example -b fd92:7065:b8e:ffff::2 > dig.out.ns2.test$n.2 || ret=1
    j=`cat dig.out.ns2.test$n.2 | tr -d '"'`
    [ "$j" = "2" ] || ret=1
fi
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking other GeoIP options are parsed correctly ($n)"
ret=0
$CHECKCONF options.conf || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

# ECS auth and resolver tests start here.
#
# NOTE: that some of the following tests are redundant, testing
# functionality already addressed above, but they use a different
# geoip database: one that has addresses in the 10.53.1/24 and 10.53.2/24
# net blocks, so that they can be used for ECS testing.

# ECS auth tests
echo_i "check auth server using ECS options with various source prefixes"

n=`expr $n + 1`
ret=0
echo_i "check /16 source prefix length matches geoip db ($n)"
$DIG +tcp -p ${PORT} @10.53.0.3 txt www.test.example -b 127.0.0.1 +subnet=10.53.2.99/16 > dig.out.ns3.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.0.0/16/32' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns3.test$n.1 > /dev/null || ret=1
# 10.53.2.99/16 is really 10.53.0.0
grep "www.test.example..*This is the IS Iceland zone" dig.out.ns3.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "check /32 source prefix length matches geoip db ($n)"
$DIG +tcp -p ${PORT} @10.53.0.3 txt www.test.example -b 127.0.0.1 +subnet=10.53.2.99/32 > dig.out.ns3.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.2.99/32/24' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the DE Germany zone" dig.out.ns3.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "check /32 source prefix length is not clamped by auth server"
echo_i "and matches geoip db ($n)"
$DIG +tcp -p ${PORT} @10.53.0.3 txt www.test.example -b 127.0.0.1 +subnet=10.53.0.5/32 > dig.out.ns3.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.0.5/32/24' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the CA Canada zone" dig.out.ns3.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "check /8 source prefix length will not match custom geoip db ($n)"
$DIG +tcp -p ${PORT} @10.53.0.3 txt www.test.example -b 127.0.0.1 +subnet=10.53.0.5/8 > dig.out.ns3.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.0.0.0/8/0' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns3.test$n.1 > /dev/null || ret=1
# the custom geoip db, doesn't have 10.0.0.0, so fall back to last view
grep "www.test.example..*This is the non-matching zone" dig.out.ns3.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "check that a match-clients ACL using an 'ecs' keyword can be "
echo_i "used to bypass the geoip db ($n)"
$DIG +tcp -p ${PORT} @10.53.0.3 txt www.test.example -b 127.0.0.1 +subnet=10.53.0.7/32 > dig.out.ns3.test$n.1 || ret=1
# 10.53.0.7 is US in DB, but views has it match CA first using "ecs" keyword
grep 'CLIENT-SUBNET: 10.53.0.7/32/24' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns3.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the CA Canada zone" dig.out.ns3.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

# ECS resolver tests
echo_i "check resolver with synthesized or forwarded ECS options"

# "ecs-forward" configured, no "ecs-zones" (@10.53.0.4 ns4)
echo_i "'ecs-forward' defined, no 'ecs-zones':"

n=`expr $n + 1`
ret=0
# TTL 1, so a sleep should clear the cache
sleep 2
echo_i "check when source length is not 0, no ECS option is sent ($n)"
$DIG +tcp -p ${PORT} @10.53.0.4 txt www.test.example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns4.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.0.0/24/0' dig.out.ns4.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns4.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the non-matching zone" dig.out.ns4.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

# "ecs-forward" and "ecs-zones" configured (@10.53.0.5 ns5)
echo_i "'ecs-zones' and 'ecs-forward' both defined"

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check REFUSED if name is whitelisted but client not allowed ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 127.0.0.1 +subnet="10.53.1.4/24" > dig.out.ns5.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.1.0/24/0' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: REFUSED' dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check success if name is whitelisted and client address is allowed ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 10.53.0.1 +subnet="10.53.1.4/24" > dig.out.ns5.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.1.0/24/0' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns5.test$n.1 > /dev/null || ret=1
# NOTE: not checking for specific result here, just want to make sure
# received anything.
# Note that 10.53.1.4 is United States, but 10.53.1.0/24/0 doesn't
# match geoip so is the auth server's none view.
grep "www.test.example..*This is the" dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check ECS forwarding with source length /16 matches a.b.0.0 ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 10.53.0.1 +subnet="10.53.2.8/16" > dig.out.ns5.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.0.0/16/32' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the IS Iceland zone" dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check ECS forwarding with source length /8 will not match ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 10.53.0.1 +subnet="10.53.2.8/8" > dig.out.ns5.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.0.0.0/8/0' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the non-matching zone" dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check source length /32 is clamped and does not match database ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 10.53.0.1 +subnet="10.53.1.2/32" > dig.out.ns5.test$n.1 || ret=1
# 10.53.1.2 is JP Japan, but becomes 10.53.1.0/24 which is not in db
grep 'CLIENT-SUBNET: 10.53.1.2/32/0' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the non-matching zone" dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check source length /32 is clamped and does match database ($n)"
$DIG +tcp -p ${PORT} @10.53.0.5 txt www.test.example -b 10.53.0.1 +subnet="10.53.2.2/32" > dig.out.ns5.test$n.1 || ret=1
# 10.53.2.2 is n DE Germany and becomes 10.53.2.0/24 which also is DE
grep 'CLIENT-SUBNET: 10.53.2.2/32/24' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns5.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the DE Germany zone" dig.out.ns5.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

# "ecs-zones" only (@10.53.0.6 ns6)
echo_i "'ecs-zones' defined, 'ecs-forward' not enabled"

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check REFUSED on nonzero source prefix length and whitelisted name ($n)"
$DIG +tcp -p ${PORT} @10.53.0.6 txt www.test.example -b 127.0.0.1 +subnet="10.53.1.4/24" > dig.out.ns6.test$n.1 || ret=1
grep 'CLIENT-SUBNET: 10.53.1.0/24/0' dig.out.ns6.test$n.1 > /dev/null || ret=1
grep 'status: REFUSED' dig.out.ns6.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check success on zero prefix length and whitelisted name ($n)"
$DIG +tcp -p ${PORT} @10.53.0.6 txt www.test.example -b 127.0.0.1 +subnet="10.53.1.4/0" > dig.out.ns6.test$n.1 || ret=1
# this is the same as +subnet=0.0.0.0/0
# the  +subnet="10.53.1.4/0" is 0.0.0.0/0/0
grep 'CLIENT-SUBNET: 0.0.0.0/0/0' dig.out.ns6.test$n.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns6.test$n.1 > /dev/null || ret=1
grep "www.test.example..*This is the non-matching zone" dig.out.ns6.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check for synthesized ECS for a TCP query for a whitelisted name ($n)"
# +nosubnet is the default
$DIG +tcp -p ${PORT} -b 10.53.2.1 @10.53.0.6 txt www.test.example +nosubnet > dig.out.ns6.test$n.1 || ret=1
# should not have CLIENT-SUBNET
grep 'CLIENT-SUBNET:' dig.out.ns6.test$n.1 > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns6.test$n.1 > /dev/null || ret=1
# Expect that 10.53.2.7 will become synthesized 10.53.2.0/24
# which should match this geoip database for 10.53.2.0 for DE.
grep "www.test.example..*This is the DE Germany zone" dig.out.ns6.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
sleep 2
echo_i "check for synthesized ECS for a UDP query for a whitelisted name ($n)"
# +nosubnet is the default, +notcp is the default (udp)
$DIG +notcp -p ${PORT} -b 10.53.2.1 @10.53.0.6 txt www.test.example +nosubnet > dig.out.ns6.test$n.1 || ret=1
# should not have CLIENT-SUBNET
grep 'CLIENT-SUBNET:' dig.out.ns6.test$n.1 > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns6.test$n.1 > /dev/null || ret=1
# The 10.53.2.7 will become synthesized 10.53.2.0/24
# which will match in geoip database for 10.53.2.0 for DE.
grep "www.test.example..*This is the DE Germany zone" dig.out.ns6.test$n.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1

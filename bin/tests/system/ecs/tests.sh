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
SEND="$PERL $SYSTEMTESTTOP/send.pl 10.53.0.8 ${EXTRAPORT1}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

# print the first line in file $2 which matches $1, and up to two
# lines following it which start with semicolon or whitespace.
# (XXX: this needs further work; what we want is to parse out the
# explicit cache records that we're interested in for a given name,
# whether cached with ECS or globally, and discard anything related
# to any other name)
group () {
   awk '/'"$1"'/ { print; x = NR+2 }
        (NR<=x && /^[; \t]/)  {print}
        END      { if (x == "") exit 1 }' $2
}

# perform rndc dumpdb -ecscache, waiting for the dump to complete.
dumpdb() {
    rm -f ns7/named_dump.db
    $RNDCCMD 10.53.0.7 dumpdb -ecscache default
    for try in 1 2 3 4 5 6 7 8 9 0; do
	tmp=0
	grep "Dump complete" ns7/named_dump.db > /dev/null || tmp=1
	[ $tmp -eq 0 ] && break
	sleep 1
    done
    if [ $tmp -eq 1 ] ; then echo_i "rndc dumpdb -escache didn't complete"; fi
    return $tmp
}

# grep in named_dump.db for a name, then in the lines immediately
# following it, for an rdatatype. loop for ten seconds before
# giving up, to allow for rndc dumpdb being slow.
dumpdb_grep () {
    for try in 1 2 3 4 5 6 7 8 9 0; do
        ret=0
        group "$1" ns7/named_dump.db | grep '[ 	]'"$2"'[ 	]' > /dev/null 2>&1 || ret=1
        [ $ret -eq 0 ] && break
        sleep 1
    done
    return $ret
}

status=0
n=0

n=`expr $n + 1`
echo_i "checking that named-checkconf handles ecs options ($n)"
ret=0
$CHECKCONF named1.conf > /dev/null 2>&1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that named handles ecs options ($n)"
ret=0
$NAMED -c named1.conf -d 99 -g > named1.run 2>&1 &
sleep 2
grep "exiting (due to fatal error)" named1.run > /dev/null && ret=1
[ -s named1.pid ] && kill -15 `cat named1.pid` > /dev/null 2>&1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that invalid ecs-types are rejected by named ($n)"
ret=0
$NAMED -c named2.conf -d 99 -g > named2.run 2>&1 &
sleep 2
grep "unknown class/type" named2.run > /dev/null || ret=1
grep "exiting (due to fatal error)" named2.run > /dev/null || ret=1
[ -s named2.pid ] && kill -15 `cat named2.pid` > /dev/null 2>&1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that public suffix ecs-zones are warned by named ($n)"
ret=0
$NAMED -c named3.conf -d 99 -g > named3.run 2>&1 &
sleep 2
grep "WARNING: 'org' is a public suffix" named3.run > /dev/null 2>&1 || ret=1
grep "WARNING: 'ip6.arpa' is a reverse zone" named3.run > /dev/null 2>&1 || ret=1
grep "WARNING: 'in-addr.arpa' is a reverse zone" named3.run > /dev/null 2>&1 || ret=1
grep "WARNING: '10.ip6.arpa' is a public suffix" named3.run > /dev/null 2>&1 && ret=1
grep "WARNING: '10.ip6.arpa' is a reverse zone" named3.run > /dev/null 2>&1 || ret=1
grep "WARNING: '10.in-addr.arpa' is a public suffix" named3.run > /dev/null 2>&1 && ret=1
grep "WARNING: '10.in-addr.arpa' is a reverse zone" named3.run > /dev/null 2>&1 || ret=1
grep "WARNING: 'example.com' is a public suffix" named3.run > /dev/null 2>&1 && ret=1
[ -s named3.pid ] && kill -15 `cat named3.pid` > /dev/null 2>&1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that invalid ecs-zones are rejected by named ($n)"
ret=0
#TODO: split this out into several tests once the checks are in
$NAMED -c named4.conf -d 99 -g > named4.run 2>&1 &
sleep 2
grep "invalid element type" named4.run > /dev/null || ret=1
grep "exiting (due to fatal error)" named4.run > /dev/null || ret=1
[ -s named4.pid ] && kill -15 `cat named4.pid` > /dev/null 2>&1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that invalid ecs-forward values are rejected by named ($n)"
ret=0
$NAMED -c named5.conf -d 99 -g > named5.run 2>&1 &
sleep 2
grep "invalid prefix length '42'" named5.run > /dev/null || ret=1
grep "exiting (due to fatal error)" named5.run > /dev/null || ret=1
[ -s named5.pid ] && kill -15 `cat named5.pid` > /dev/null 2>&1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "Start of tests from Recursive ECS Requirements Document."
echo_i "1.4      Start named with a basic named.conf that enables recursion"
echo_i "         and does not include any ECS options"

n=`expr $n + 1`
echo_i "1.4.1    Check that IPv4 queries do not result in upstream queries"
echo_i "         containing an ECS option ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.6 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "1.4.2    Check that IPv6 queries do not result in upstream queries"
echo_i "         containing an ECS option ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "2.1      Test that when ECS is enabled for a domain (by placing the"
echo_i "         domain in the white list), a query for that domain results"
echo_i "         in outgoing queries from the server that include an ECS"
echo_i "         option."

n=`expr $n + 1`
echo_i "2.1.1.1  When the original query includes an ECS option (UDP) ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 8' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.1.1.2  When the original query includes an ECS option (TCP) ($n)"
ret=0
$DIG $DIGOPTS +tcp @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 8' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.1.2.1  When the original query does not include ECS (UDP) ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.1.2.2  When the original query does not include ECS (TCP) ($n)"
ret=0
$DIG $DIGOPTS +tcp @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "         Test that when ECS is disabled, an ECS option is not"
echo_i "         added to outgoing queries from a recursive server:"

n=`expr $n + 1`
echo_i "2.1.3    When the original query includes an ECS option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.6 -b 10.53.0.1 +subnet=127/0 test${n}.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.1.4    When the original query does not include an ECS option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.6 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "2.3      Configure named for ECS forwarding"

n=`expr $n + 1`
echo_i "2.3.2.1  Check that IPv4 UDP queries that do not specify ECS"
echo_i "         get the server-specified default ECS options ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.3.2.2  Check that IPv4 TCP queries that do not specify ECS"
echo_i "         get the server-specified default ECS options ($n)"
ret=0
$DIG $DIGOPTS +tcp @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.3.3.1  Check that IPv6 UDP queries that do not specify"
echo_i "         ECS get the server-specified default ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "2.3.3.2  Check that IPv6 TCP queries that do not specify"
echo_i "         ECS get the server-specified default ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS +tcp @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "2.3.4    Check that IPv4 queries that specify ECS use the"
echo_i "         specified ECS ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127.0.0.1/20 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 20' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.3.5    Check that IPv6 queries that specify ECS use the"
echo_i "         specified ECS ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=127.0.0.1/20 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 20' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "2.3.6    Check that when client specifies a source prefix"
echo_i "         length of 0, ECS is not used ($n)"
ret=0
# no need for -b here because subnet=0 is always allowed
$DIG $DIGOPTS @10.53.0.7 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "2.4      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) without setting a prefix length. Check that:"

n=`expr $n + 1`
echo_i "2.4.1    Outgoing IPv4 queries include an ECS option with a"
echo_i "         prefix length of /24 ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.4.2    Outgoing IPv6 queries include an ECS option with a"
echo_i "         prefix length of /56 ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and set an IPv4 prefix length of /16 and an"
echo_i "         IPv6 prefix length of /48. Check that:"

n=`expr $n + 1`
echo_i "2.4.3    Outgoing IPv4 queries include an ECS option with a"
echo_i "         prefix length of /16 ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.short.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 16' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.4.4    Outgoing IPv6 queries include an ECS option with a"
echo_i "         prefix length of /48 ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.short.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e::, 48' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "2.8.1    The 2.8.1 requirements cover both whitelisting and"
echo_i "         blacklisting by using exclusion. Configure a"
echo_i "         whitelist of domains. Check that:"

n=`expr $n + 1`
echo_i "2.8.1.1  Queries for domains in the whitelist include an ECS"
echo_i "         option in the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.8.1.2  Queries for domains not in the whitelist do not include"
echo_i "         an ECS option in the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.outside.whitelist > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "         Exclude a subdomain of a domain in the whitelist"
echo_i "         (whitelist test.example; add !exclude.test.example)."
echo_i "         Check that:"

n=`expr $n + 1`
echo_i "2.8.1.3  Queries for test.example include an ECS option in"
echo_i "         the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test.example. > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.8.1.4  Queries for exclude.test.example do not include an ECS"
echo_i "         option in the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 exclude.test.example. > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.8.1.5  Queries for subdomains of exclude.test.example do not"
echo_i "         include an ECS option in the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.exclude.test.example. > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.8.1.6  Queries for baz.foo.com still include an ECS option"
echo_i "         in the outgoing query. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example. > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "2.9      Configure a resolver with ECS, but put the target"
echo_i "         server in a server blacklist"

n=`expr $n + 1`
echo_i "2.9.1    Check that IPv4 queries do not result in upstream queries"
echo_i "         containing ECS options. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.9.2    Check that IPv6 queries do not result in upstream queries"
echo_i "         containing ECS options. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::5 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "2.10     Configure a resolver with ECS and a query-type whitelist"
copy_setports ns5/named2.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig 2>&1 | sed 's/^/I:ns5 /'
sleep 3

n=`expr $n + 1`
echo_i "2.10.1   Check that IPv4 queries for types outside the whitelist"
echo_i "         do not result in upstream queries with ECS options ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 test${n}.test.example -t txt > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.10.2   Check that IPv6 queries for types outside the whitelist"
echo_i "         do not result in upstream queries with ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 test${n}.test.example -t txt > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "2.10.3   Check that IPv4 queries for types in the whitelist"
echo_i "         do result in upstream queries with ECS options ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 test${n}.test.example -t aaaa > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.10.4   Check that IPv6 queries for types in the whitelist"
echo_i "         do result in upstream queries with ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::5 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 test${n}.test.example -t aaaa > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Configure a resolver with ECS and no query-type whitelist"

n=`expr $n + 1`
echo_i "2.10.5   Check that IPv4 queries for non-DNS infrastructure types"
echo_i "         do result in upstream queries with ECS options ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example -t txt > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.10.6   Check that IPv6 queries for non-DNS infrastructure types"
echo_i "         do result in upstream queries with ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example -t txt > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "2.10.7   Check that IPv4 queries for DNS infrastructure types"
echo_i "         do not result in upstream queries with ECS options ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example -t soa > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "2.10.8   Check that IPv6 queries for DNS infrastructure types"
echo_i "         do not result in upstream queries with ECS options ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example -t soa > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep ClientSubnetOption > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "3.1      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and set up a whitelist of domains."
echo_i "         Send queries to the server and check:"

n=`expr $n + 1`
echo_i "3.1.1    An IPv4 query for a domain not in the whitelist and"
echo_i "         without ECS options in the query does not result in"
echo_i "         ECS option sent upstream. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.outside.whitelist > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "3.1.2    An IPv4 query for a domain not in the whitelist and"
echo_i "         with an ECS option in the query does not result in"
echo_i "         ECS option sent upstream. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.outside.whitelist > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "3.1.3    An IPv4 query for a domain in the whitelist and"
echo_i "         without ECS options in the query results in ECS option"
echo_i "         sent upstream. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "3.1.4    An IPv4 query for a domain in the whitelist and with"
echo_i "         an ECS option in the query results in the appropriate"
echo_i "         ECS option sent upstream. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 8,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "3.1.5    Test removed from plan"

n=`expr $n + 1`
echo_i "3.1.6    An IPv6 query for a domain not in the whitelist and"
echo_i "         without ECS options in the query does not result in"
echo_i "         ECS option sent upstream. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.outside.whitelist > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "3.1.7    An IPv6 query for a domain not in the whitelist and"
echo_i "         with an ECS option in the query does not result in"
echo_i "         ECS option sent upstream. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=127/8 test${n}.outside.whitelist > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "3.1.8    An IPv6 query for a domain in the whitelist and"
echo_i "         without ECS options in the query results in ECS option"
echo_i "         sent upstream. ($n)"
ret=0

if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "3.1.9    An IPv6 query for a domain in the whitelist and"
echo_i "         with an ECS option in the query results in the"
echo_i "         appropriate ECS option sent upstream. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 8,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "3.1.10   Test removed from plan"

echo_i "3.3      Configure ans.py to act as an authoritative server"
echo_i "         but to log queries and not respond."

n=`expr $n + 1`
echo_i "3.3.1    Execute several queries for the same tuple (where"
echo_i "         tuple is name/class/type/clientsubnet) and check"
echo_i "         that only one query is logged by the program. ($n)"
ret=0
# skip all of ns7/named.run prior to this
nextpart ns7/named.run > /dev/null
for m in 0 1 2 3 4; do
    $DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.drop.test.example > /dev/null
done
$RNDCCMD 10.53.0.7 -c ../common/rndc.conf recursing 2>&1 | sed 's/^/I:ns7 /'
sleep 1
grep "^test.example.: 1 active" ns7/named.recursing > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "4.1      Validate the format of an IPv4 outbound ECS query"
echo_i "         by checking for the presence of a properly-formatted"
echo_i "         ECS option, in particular:"

n=`expr $n + 1`
echo_i "4.1.1    Family ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
capture4_1_1=`nextpart ans8/ans.run`
echo "$capture4_1_1" | grep 'CS F:1 ' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "4.1.2    Source prefix-length is that set for the resolver. ($n)"
ret=0
echo "$capture4_1_1" | grep 'CS .* SOURCE:24 ' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "4.1.3    Scope prefix length is zero ($n)"
ret=0
echo "$capture4_1_1" | grep 'CS .* SCOPE:0$' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "4.1.4    Address is the client-supplied network address,"
echo_i "         truncated to the number of bits specified in the"
echo_i "         source prefix length and only using as many octets"
echo_i "         as required. ($n)"
ret=0
echo "$capture4_1_1" | grep 'CS .* ADDR:a350000 ' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "         Validate the format of an IPv6 outbound ECS query"
echo_i "         by checking for the presence of a properly-formatted"
echo_i "         ECS option, in particular:"

n=`expr $n + 1`
echo_i "4.1.5    Family ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    capture4_1_5=`nextpart ans8/ans.run`
    echo "$capture4_1_5" | grep 'CS F:2 ' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "4.1.6    Source prefix-length is that set for the resolver. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    echo "$capture4_1_5" | grep 'CS .* SOURCE:56 ' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "4.1.7    Scope prefix length is zero ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    echo "$capture4_1_5" | grep 'CS .* SCOPE:0$' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "4.1.8    Address is the client-supplied network address,"
echo_i "         truncated to the number of bits specified in the"
echo_i "         source prefix length and only using as many octets"
echo_i "         as required. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 2> /dev/null
then
    echo "$capture4_1_5" | grep 'CS .* ADDR:fd9270650b8eff000000000000000000' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "5.1      Send a query to a named configured for recursive"
echo_i "         ECS that will recurse to an ans.py that is configured"
echo_i "         to reply without an ECS option in the reply."

n=`expr $n + 1`
echo_i "5.1.1    When no ECS option is received in the authoritative"
echo_i "         answer, test that it is processed as if it had an ECS"
echo_i "         option with Scope Netmask set to 0. In particular,"
echo_i "         examine the cache and check that it is stored in the"
echo_i "         same way. ($n)"
ret=0
# we send queries with 1-second delays from different subnets. if the
# TTLs decrease, then the first answer must have been cached globally.
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test${n}.noecs.test.example > dig.out.$n.1 || ret=1
ttl1=`awk '{print $2}' dig.out.$n.1`
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.1.1 test${n}.noecs.test.example > dig.out.$n.2 || ret=1
ttl2=`awk '{print $2}' dig.out.$n.2`
[ "$ttl1" -gt "$ttl2" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.2.1 test${n}.noecs.test.example > dig.out.$n.3 || ret=1
ttl3=`awk '{print $2}' dig.out.$n.3`
[ "$ttl2" -gt "$ttl3" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 127.0.0.1 test${n}.noecs.test.example > dig.out.$n.4 || ret=1
ttl4=`awk '{print $2}' dig.out.$n.4`
[ "$ttl3" -gt "$ttl4" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "5.2      Check that a response is dropped if, in the ECS option"
echo_i "         in the response:"

n=`expr $n + 1`
echo_i "5.2.1    Address family does not match that in the upstream query. ($n)"
ret=0
# set up ans to return an ECS option with the wrong family
echo "test${n}.test.example./10.53.0.0/24|1.2.3.4, 000210000a35" | $SEND
$DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n.1 || ret=1
grep "status: NOERROR" dig.out.$n.1 > /dev/null && ret=1
# now set up ans to return a good ECS option
echo "test${n}.test.example./10.53.0.0/24|4.3.2.1, 000118000a3500" | $SEND
for try in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    $DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n.2
    grep "status: NOERROR" dig.out.$n.2 > /dev/null && break
done
grep "4.3.2.1" dig.out.$n.2 > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "5.2.2    Source prefix does not match that in the upstream query. ($n)"
ret=0
# set up ans to return an ECS option with the wrong source prefix
echo "test${n}.test.example./10.53.0.0/24|1.2.3.4, 000218000a35ff" | $SEND
$DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null && ret=1
# now set up ans to return a good ECS option
echo "test${n}.test.example./10.53.0.0/24|4.3.2.1, 000118000a3500" | $SEND
for try in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    $DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n
    grep "status: NOERROR" dig.out.$n > /dev/null && break
done
grep "4.3.2.1" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "5.2.3    Source prefix length does not match that in the upstream"
echo_i "         query. ($n)"
ret=0
# set up ans to return an ECS option with the wrong source prefix length
echo "test${n}.test.example./10.53.0.0/24|1.2.3.4, 000219000a3500" | $SEND
$DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null && ret=1
# now set up ans to return a good ECS option
echo "test${n}.test.example./10.53.0.0/24|4.3.2.1, 000118000a3500" | $SEND
for try in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    $DIG $DIGOPTS +tries=1 +time=1 @10.53.0.7 test${n}.test.example > dig.out.$n
    grep "status: NOERROR" dig.out.$n > /dev/null && break
done
grep "4.3.2.1" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "5.2.4    Check that a response with a valid ECS leads to the"
echo_i "         ECS information being cached (as well as the RR). ($n)"
ret=0
# we send queries with 1-second delays from the same subnet. if the
# TTL decreases, then the first answer must have been cached. we then
# examine the ECS information to confirm that both were the same.
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.0.1 test${n}.noecs.test.example > dig.out.$n.1 || ret=1
ttl1=`awk '/test.*noecs.test.example/ {print $2}' dig.out.$n.1`
ecs1=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n.1`
sleep 1
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.1.1 test${n}.noecs.test.example > dig.out.$n.2 || ret=1
ttl2=`awk '/test.*noecs.test.example/ {print $2}' dig.out.$n.2`
ecs2=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n.2`
[ "$ttl1" -gt "$ttl2" ] || ret=1
[ "$ecs1" = "$ecs2" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "5.2.5    Check that if the upstream server returns REFUSED,"
echo_i "         the resolver re-queries without ECS. ($n)"
ret=0
echo "test${n}.refuse.test.example./127.0.0.0/8|1.2.3.4, 127.0.0.0, 8, 24" | $SEND
$DIG $DIGOPTS @10.53.0.7 test${n}.refuse.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
grep "1.2.3.4" dig.out.$n > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "6.1      Disable ECS"

n=`expr $n + 1`
echo_i "6.1.1    Check that an IPv4 query to the resolver without an"
echo_i "         ECS option results in a response that also has no"
echo_i "         ECS option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.6 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.1.2    Check that an IPv6 query to the resolver without"
echo_i "         an ECS option results in a response that also has no"
echo_i "         ECS option. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list)"

n=`expr $n + 1`
echo_i "6.1.3    Check that an IPv4 query to the resolver without an"
echo_i "         ECS option results in a response that also has no ECS"
echo_i "         option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.1.4    Check that an IPv6 query to the resolver without an"
echo_i "         ECS option results in a response that also has no ECS"
echo_i "         option. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "6.2      Disable ECS"

n=`expr $n + 1`
echo_i "6.2.1    Check that an IPv4 query without an ECS option results"
echo_i "         in a response without an ECS option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.6 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.2.2    Check that an IPv4 query containing an ECS option"
echo_i "         results in a response with an scope 0($n)"
$DIG $DIGOPTS @10.53.0.6 -b 10.53.0.1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.2.3    Check that an IPv6 query without an ECS option results"
echo_i "         in a response without an ECS option. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "6.2.4    Check that an IPv6 query containing an ECS option"
echo_i "         results in a response with an scope 0($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "6.3      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "6.3.1    Send an IPv4 query containing an ECS option with a"
echo_i "         source prefix length of 0. The response should contain"
echo_i "         an ECS option with a matching address and family and"
echo_i "         a scope prefix-length of 0. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET: 0.0.0.0/0/0" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.3.2    Send an IPv6 query containing an ECS option with a"
echo_i "         source prefix length of 0. The response should contain"
echo_i "         an ECS option with a matching address and family and"
echo_i "         a scope prefix-length of 0. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::1 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET: ::/0/0" dig.out.$n > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) but disable ECS forwarding"

n=`expr $n + 1`
echo_i "6.3.3    Send an IPv4 query containing an ECS option with a"
echo_i "         source prefix length of 0. The response should contain"
echo_i "         an ECS option with a matching address and family and"
echo_i "         a scope prefix-length of 0. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET: 0.0.0.0/0/0" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.3.4    Send an IPv6 query containing an ECS option with a"
echo_i "         source prefix length of 0. The response should contain"
echo_i "         an ECS option with a matching address and family and"
echo_i "         a scope prefix-length of 0. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 fd92:7065:b8e:ffff::2 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::2 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET: ::/0/0" dig.out.$n > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "6.4      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS Forwarding"

n=`expr $n + 1`
echo_i "6.4.1    Send an IPv4 query with a non-zero source-prefix-length"
echo_i "         for a name served by an ECS enabled authoritative server,"
echo_i "         and ensure that the response contains an ECS option. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.4.2    Send an IPv4 query with a non-zero source-prefix-length"
echo_i "         for a name served by an non-ECS enabled authoritative"
echo_i "         server, and ensure that the response still contains ECS"
echo_i "         (with scope prefix length set to 0). ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 test${n}.noecs.test.example > dig.out.$n || ret=1
grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.4.3    Send an IPv6 query with a non-zero source-prefix-length"
echo_i "         for a name served by an ECS enabled authoritative server,"
echo_i "         and ensure that the response contains an ECS option. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::1 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "6.4.4    Send an IPv6 query with a non-zero source-prefix-length"
echo_i "         for a name served by a non-ECS enabled authoritative"
echo_i "         server, and ensure that the response still contains ECS"
echo_i "         (with scope prefix length set to 0). ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::1 +subnet=127/8 test${n}.noecs.test.example > dig.out.$n || ret=1
    grep "CLIENT-SUBNET: 127.0.0.0/8/0" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "6.5      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) but disable ECS forwarding"

n=`expr $n + 1`
echo_i "6.5.1    Send an IPv4 query containing an ECS option with a"
echo_i "         non-zero source prefix length. The response should be"
echo_i "         a REFUSED status. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
grep "status: REFUSED" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.5.2    Send an IPv4 query containing an ECS option with a non-zero"
echo_i "         source prefix length, for a name which is not whitelisted for"
echo_i "         ECS. The response should be a REFUSED status. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=127/8 test${n}.exclude.test.example > dig.out.$n || ret=1
grep "status: REFUSED" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "6.5.3    Send an IPv6 query containing an ECS option with a"
echo_i "         non-zero source prefix length. The response should be"
echo_i "         a REFUSED status. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::6 -b fd92:7065:b8e:ffff::2 +subnet=127/8 test${n}.test.example > dig.out.$n || ret=1
    grep "status: REFUSED" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "6.5.4    Send an IPv6 query containing an ECS option with a non-zero"
echo_i "         source prefix length, for a name which is not whitelisted for"
echo_i "         ECS. The response should be a REFUSED status. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=127/8 test${n}.exclude.test.example > dig.out.$n || ret=1
grep "status: REFUSED" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "7.1      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list)"

n=`expr $n + 1`
echo_i "7.1.1    Send a set of IPv4 queries with no ECS options or with"
echo_i "         a source prefix-length set to 0. Check that the cache"
echo_i "         contains responses cached with a scope prefix-length"
echo_i "         of 0. ($n)"
ret=0
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.0.1 test${n}.exclude.test.example > dig.out.$n || ret=1
ttl1=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
sleep 1
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.1.1 test${n}.exclude.test.example > dig.out.$n || ret=1
ttl2=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
[ "$ttl1" -gt "$ttl2" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer +comments +subnet=0 @10.53.0.7 -b 10.53.2.1 test${n}.exclude.test.example > dig.out.$n || ret=1
ttl3=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
[ "$ttl2" -gt "$ttl3" ] || ret=1
[ "$ecs3" = "0.0.0.0/0/0" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.1.2    Send a set of IPv6 queries with no ECS options or with"
echo_i "         a source prefix-length set to 0. Check that the cache"
echo_i "         contains responses cached with a scope prefix-length"
echo_i "         of 0. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::7 fd92:7065:b8e:ffff::1 fd92:7065:b8e:00ff::1 fd92:7065:b8e:99ff::1 2> /dev/null
then
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 test${n}.exclude.test.example > dig.out.$n || ret=1
    ttl1=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:00ff::1 test${n}.exclude.test.example > dig.out.$n || ret=1
    ttl2=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
    [ "$ttl1" -gt "$ttl2" ] || ret=1
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments +subnet=0 @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:99ff::1 test${n}.exclude.test.example > dig.out.$n || ret=1
    ttl3=`awk '/test.*exclude.test.example/ {print $2}' dig.out.$n`
    ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
    [ "$ttl2" -gt "$ttl3" ] || ret=1
    [ "$ecs3" = "0.0.0.0/0/0" ] || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "7.1.3    Send a set of IPv4 queries with a source prefix-length set"
echo_i "         to something greater than 0. Check that the cache contains"
echo_i "         responses cached with a matching scope prefix-length. ($n)"
ret=0
# discard prior ans.run logging
echo "test${n}.short.example./10.53.0.0/16|1.2.3.4, 10.53.0.0, 16, 8" | $SEND
nextpart ans8/ans.run > /dev/null
# because short.example uses length 16, all queries from 10.53/16 should match
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.1.1 test${n}.short.example > dig.out.$n || ret=1
ttl1=`awk '/test.*short.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 16,' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.2.1 test${n}.short.example > dig.out.$n || ret=1
ttl2=`awk '/test.*short.example/ {print $2}' dig.out.$n`
[ "$ttl1" -gt "$ttl2" ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 16,' > /dev/null && ret=1
sleep 1
$DIG $DIGOPTS +noall +answer +comments +subnet=10.53/16 @10.53.0.7 -b 10.53.0.1 test${n}.short.example > dig.out.$n || ret=1
ttl3=`awk '/test.*short.example/ {print $2}' dig.out.$n`
ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
[ "$ttl2" -gt "$ttl3" ] || ret=1
[ "$ecs3" = "10.53.0.0/16/8" ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 16,' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.1.4    Send a set of IPv6 queries with a source prefix-length set"
echo_i "         to something greater than 0. Check that the cache contains"
echo_i "         responses cached with a matching scope prefix-length. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::7 fd92:7065:b8e:ff::1 fd92:7065:b8e:99ff::1  2> /dev/null
then
# because short.example uses length 48, all queries from fd92:7065:b8e::/48 should match
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ff::1 test${n}.short.example > dig.out.$n || ret=1
    ttl1=`awk '/test.*short.example/ {print $2}' dig.out.$n`
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e::, 48,' > /dev/null || ret=1
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:99ff::1 test${n}.short.example > dig.out.$n || ret=1
    ttl2=`awk '/test.*short.example/ {print $2}' dig.out.$n`
    [ "$ttl1" -gt "$ttl2" ] || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e::, 48,' > /dev/null && ret=1
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments +subnet=fd92:7065:b8e:ffff::/48 @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 test${n}.short.example > dig.out.$n || ret=1
    ttl3=`awk '/test.*short.example/ {print $2}' dig.out.$n`
    ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
    [ "$ttl2" -gt "$ttl3" ] || ret=1
    [ "$ecs3" = "fd92:7065:b8e::/48/0" ] || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e::, 48,' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "7.2      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "7.2.1    Send a set of IPv4 queries with and without ECS"
echo_i "         information. Check that the answers in the cache are"
echo_i "         cached with the appropriate ECS data intact. ($n)"
ret=0
echo "test${n}.test.example./10.53.1.0/24|5.6.7.8, 10.53.2.0, 24, 24" | $SEND
echo "test${n}.test.example./10.53.2.0/24|4.3.2.1, 10.53.1.0, 24, 16" | $SEND
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.1.1 test${n}.test.example > dig.out.$n || ret=1
ttl1=`awk '/test.*test.example/ {print $2}' dig.out.$n`
answer1=`awk '/test.*test.example/ {print $5}' dig.out.$n`
[ "$answer1" = "5.6.7.8" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.2.1 test${n}.test.example > dig.out.$n || ret=1
ttl2=`awk '/test.*test.example/ {print $2}' dig.out.$n`
answer2=`awk '/test.*test.example/ {print $5}' dig.out.$n`
[ "$ttl1" -eq "$ttl2" ] || ret=1
[ "$answer2" = "4.3.2.1" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.0.1 +subnet=10.53.1/24 test${n}.test.example > dig.out.$n || ret=1
ttl3=`awk '/test.*test.example/ {print $2}' dig.out.$n`
answer3=`awk '/test.*test.example/ {print $5}' dig.out.$n`
ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
[ "$answer3" = "5.6.7.8" ] || ret=1
[ "$ttl3" -lt "$ttl1" ] || ret=1
[ "$ecs3" = "10.53.1.0/24/24" ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer +comments @10.53.0.7 -b 10.53.0.1 +subnet=10.53.3/24 test${n}.test.example > dig.out.$n || ret=1
ttl4=`awk '/test.*test.example/ {print $2}' dig.out.$n`
answer4=`awk '/test.*test.example/ {print $5}' dig.out.$n`
ecs4=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
[ "$answer4" = "4.3.2.1" ] || ret=1
[ "$ttl4" -lt "$ttl2" ] || ret=1
[ "$ecs4" = "10.53.3.0/24/16" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.2.2    Send a set of IPv6 queries with and without ECS"
echo_i "         information. Check that the answers in the cache are"
echo_i "         cached with the appropriate ECS data intact. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 fd92:7065:b8e:ff::1 fd92:7065:b8e:99ff::1 fd92:7065:b8e:ffff::1 2> /dev/null
then
    echo "test${n}.test.example./fd92:7065:b8e::/56|5.6.7.8, fd92:7065:b8e:99ff::, 56, 56" | $SEND
    echo "test${n}.test.example./fd92:7065:b8e:9900::/56|4.3.2.1, fd92:7065:b8e::, 56, 48" | $SEND
    $DIG $DIGOPTS +noall +answer @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ff::1 test${n}.test.example > dig.out.$n || ret=1
    ttl1=`awk '/test.*test.example/ {print $2}' dig.out.$n`
    answer1=`awk '/test.*test.example/ {print $5}' dig.out.$n`
    [ "$answer1" = "5.6.7.8" ] || { ret=1; echo_i "fail1 $answer1"; }
    sleep 1
    $DIG $DIGOPTS +noall +answer @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:99ff::1 test${n}.test.example > dig.out.$n || ret=1
    ttl2=`awk '/test.*test.example/ {print $2}' dig.out.$n`
    answer2=`awk '/test.*test.example/ {print $5}' dig.out.$n`
    [ "$ttl1" -eq "$ttl2" ] || { ret=1; echo_i "fail2"; }
    [ "$answer2" = "4.3.2.1" ] || { ret=1; echo_i "fail3"; }
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e::/56 test${n}.test.example > dig.out.$n || ret=1
    ttl3=`awk '/test.*test.example/ {print $2}' dig.out.$n`
    answer3=`awk '/test.*test.example/ {print $5}' dig.out.$n`
    ecs3=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
    [ "$answer3" = "5.6.7.8" ] || { ret=1; echo_i "fail4"; }
    [ "$ttl3" -lt "$ttl1" ] || { ret=1; echo_i "fail5"; }
    [ "$ecs3" = "fd92:7065:b8e::/56/56" ] || { ret=1; echo_i "fail6 $ecs3"; }
    sleep 1
    $DIG $DIGOPTS +noall +answer +comments @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:99ff::/48 test${n}.test.example > dig.out.$n || ret=1
    ttl4=`awk '/test.*test.example/ {print $2}' dig.out.$n`
    answer4=`awk '/test.*test.example/ {print $5}' dig.out.$n`
    ecs4=`awk '/CLIENT-SUBNET/ {print $3}' dig.out.$n`
    [ "$answer4" = "4.3.2.1" ] || { ret=1 ; echo "fail7 $answer4"; }
    [ "$ttl4" -lt "$ttl2" ] || { ret=1 ; echo "fail8 $ttl4"; }
    [ "$ecs4" = "fd92:7065:b8e::/48/48" ] || { ret=1 ; echo "fail9 $ecs4"; }
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "7.3      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "7.3.1    Send a set of IPv4 queries with and without ECS"
echo_i "         information for RRs that will give NODATA. Check that"
echo_i "         the answers in the cache are cached with the appropriate"
echo_i "         ECS data intact with a global scope. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.1.1 mx test${n}.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.2.1 mx test${n}.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.3/24 mx test${n}.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.3.2    Send a set of IPv6 queries with and without ECS"
echo_i "         information for RRs that will give NODATA. Check that"
echo_i "         the answers in the cache are cached with the appropriate"
echo_i "         ECS data intact with a global scope. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::7 fd92:7065:b8e:ff::1 fd92:7065:b8e:99ff::1 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ff::1 mx test${n}.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
    sleep 1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:99ff::1 mx test${n}.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    sleep 1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=10.53.3/24 mx test${n}.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "7.3.3    Send a set of IPv4 queries with and without ECS"
echo_i "         information for RRs that will give NXDOMAIN. Check that"
echo_i "         the answers in the cache are cached with the appropriate"
echo_i "         ECS data intact with a global scope. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.1.1 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.2.1 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.3/24 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.3.4    Send a set of IPv6 queries with and without ECS"
echo_i "         information for RRs that will give NXDOMAIN. Check that"
echo_i "         the answers in the cache are cached with the appropriate"
echo_i "         ECS data intact with a global scope. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::7 fd92:7065:b8e:ff::1 fd92:7065:b8e:99ff::1 fd92:7065:b8e:ffff::1 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ff::1 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
    sleep 1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:99ff::1 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    sleep 1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=10.53.3/24 mx test${n}.nxdomain.test.example > dig.out.$n || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "7.4      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list)"

n=`expr $n + 1`
echo_i "7.4.1    Send an IPv4 query and ensure that RRs in the additional"
echo_i "         and authority sections of the answer are cached with a"
echo_i "         global scope. ($n)"
ret=0
# flush cache
$RNDCCMD 10.53.0.7 flush 2>&1 | sed 's/^/I:ns7 /'
sleep 1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10/8 ns test.example > dig.out.$n || ret=1
# ns1, ns2, and ns3.test.example/A should have been cached from
# the additional section now.
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10/8 ns1.test.example > dig.out.$n || ret=1
dumpdb || ret=1
dumpdb_grep "^ns1\.test\.example" "A" || { ret=1; echo_i "not cached 1"; }
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=20/8 ns1.test.example > dig.out.$n || ret=1
dumpdb || ret=1
dumpdb_grep "^ns2\.test\.example" "A" || { ret=1; echo_i "not cached 2"; }
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=127/8 ns1.test.example > dig.out.$n || ret=1
dumpdb || ret=1
dumpdb_grep "^ns3\.test\.example" "A" || { ret=1; echo_i "not cached 3"; }
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.4.2    Send an IPv6 query and ensure that RRs in the additional"
echo_i "         and authority sections of the answer are cached with a"
echo_i "         global scope. ($n)"
ret=0
# flush cache
$RNDCCMD 10.53.0.7 flush 2>&1 | sed 's/^/I:ns7 /'
sleep 1
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=10/8 ns test.example > dig.out.$n || ret=1
    # ns1, ns2, and ns3.test.example/A should have been cached from
    # the additional section now.
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=10/8 ns1.test.example > dig.out.$n || ret=1
    dumpdb || ret=1
    dumpdb_grep "^ns1\.test\.example" "AAAA" || { ret=1; echo_i "not cached 1"; }
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=20/8 ns1.test.example > dig.out.$n || ret=1
    dumpdb || ret=1
    dumpdb_grep "^ns2\.test\.example" "AAAA" || { ret=1; echo_i "not cached 2"; }
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=127/8 ns1.test.example > dig.out.$n || ret=1
    dumpdb || ret=1
    dumpdb_grep "^ns3\.test\.example" "AAAA" || { ret=1; echo_i "not cached 3"; }
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "7.5      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list)"

n=`expr $n + 1`
echo_i "7.5.1    Send an IPv4 query to an ECS enabled server that will"
echo_i "         return an answer without ECS, ensure that it is cached"
echo_i "         globally. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10/8 test$n.noecs.test.example > dig.out.$n || ret=1
dumpdb || ret=1
dumpdb_grep "^test${n}\.noecs\.test\.example" "A" || { ret=1; echo_i "not cached 1"; }
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.5.2    Send an IPv4 query to a non-ECS enabled server, ensure"
echo_i "         that it is cached globally. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 test$n.exclude.test.example > dig.out.$n || ret=1
dumpdb || ret=1
dumpdb_grep "test${n}\.exclude\.test\.example" "A" || { ret=1; echo_i "not cached 1"; }
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "7.5.3    Send an IPv6 query to an ECS enabled server that will"
echo_i "         return an answer without ECS, ensure that it is cached"
echo_i "         globally. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 AAAA test$n.noecs.test.example > dig.out.$n || ret=1
    dumpdb || ret=1
    dumpdb_grep "^test${n}\.noecs\.test\.example" "AAAA" || { ret=1; echo_i "not cached 1"; }
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "7.5.4    Send an IPv6 query to a non-ECS enabled server, ensure"
echo_i "         that it is cached globally. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 AAAA test$n.exclude.test.example > dig.out.$n || ret=1
    dumpdb || ret=1
    dumpdb_grep "^test${n}\.exclude\.test\.example" "AAAA" || { ret=1; echo_i "not cached 1"; }
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "8.1      Configure a recursive resolver with ECS, and put"
echo_i "         several records in the cache with ECS options specifying"
echo_i "         several different networks"

n=`expr $n + 1`
# set up auth and preload cache (v4)
echo "test${n}.test.example./10.0.0.0/8|1.0.0.0, 10.0.0.0, 8, 16" | $SEND
echo "test${n}.test.example./10.53.0.0/16|2.0.0.0, 10.53.0.0, 16, 16" | $SEND
echo "test${n}.test.example./10.53.1.0/24|4.0.0.0, 10.53.1.0, 24, 24" | $SEND
echo "test${n}.test.example./10.53.2.0/24|5.0.0.0, 10.53.2.0, 24, 24" | $SEND
# note: query the longest subnets first. if the shorter subnets are
# already cached, then we wouldn't recurse for them and so they won't
# be cached.
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.1/24 test$n.test.example > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.2/24 test$n.test.example > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53/16 test$n.test.example > /dev/null

echo_i "8.1.1    Send an IPv4 query with an ECS option that exactly"
echo_i "         matches an entry in the cache, and ensure that the"
echo_i "         cache entry is used for the response. ($n) (1/3)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
answer=`$DIG $DIGOPTS +short @10.53.0.7 -b 10.53.0.1 +subnet=10.53/16 test$n.test.example`
[ "$answer" = "2.0.0.0" ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "8.1.2    Send an IPv4 query that doesnt exactly match, and"
echo_i "         ensure that the answer with the longest prefix length"
echo_i "         in the cache is used for the response. ($n) (2/3)"
ret=0
answer=`$DIG $DIGOPTS +short @10.53.0.7 -b 10.53.0.1 +subnet=10.53.10/20 test$n.test.example`
[ "$answer" = "2.0.0.0" ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "8.1.3    Send an IPv4 query that doesnt match any network"
echo_i "         already in cache, and ensure that named performs"
echo_i "         resolution as usual. ($n) (3/3)"
ret=0
answer=`$DIG $DIGOPTS +short @10.53.0.7 -b 10.53.0.1 +subnet=99.99.99/24 test$n.test.example`
[ "$answer" = "10.53.0.8" ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(99.99.99.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
# set up auth and preload cache (v6)
echo "test${n}.test.example./fd92:7065::/32|1.0.0.0, fd92:7065::, 32, 48" | $SEND
echo "test${n}.test.example./fd92:7065:b8e::/48|2.0.0.0, fd92:7065:b8e::, 48, 48" | $SEND
echo "test${n}.test.example./fd92:7065:b8e:ff00::/56|3.0.0.0, fd92:7065:b8e:ff00::, 56, 56" | $SEND
echo "test${n}.test.example./fd92:7065:b8e:ee00::/56|4.0.0.0, fd92:7065:b8e:ee00::, 56, 56" | $SEND
# note: query the longest subnets first. if the shorter subnets are
# already cached, then we wouldn't recurse for them and so they won't
# be cached.
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:ff00::/56 test$n.test.example > /dev/null
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:ee00::/56 test$n.test.example > /dev/null
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e::/48 test$n.test.example > /dev/null
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065::/32 test$n.test.example > /dev/null
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "8.1.4    Send an IPv6 query with an ECS option that exactly"
echo_i "         matches an entry in the cache, and ensure that the"
echo_i "         cache entry is used for the response. ($n) (1/3)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    answer=`$DIG $DIGOPTS +short @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065::/32 test$n.test.example`
    [ "$answer" = "1.0.0.0" ] || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "8.1.5    Send an IPv6 query that doesnt exactly match, and"
echo_i "         ensure that the answer with the longest prefix length"
echo_i "         in the cache is used for the response. ($n) (2/3)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    answer=`$DIG $DIGOPTS +short @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:0111::/50 test$n.test.example`
    [ "$answer" = "2.0.0.0" ] || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "8.1.6    Send an IPv6 query that doesnt match any network"
echo_i "         already in cache, and ensure that named performs"
echo_i "         resolution as usual. ($n) (3/3)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    answer=`$DIG $DIGOPTS +short @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=dead:beef::/32 test$n.test.example`
    [ "$answer" = "10.53.0.8" ] || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(dead:beef::, 32' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "8.3      Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "8.3.1    Send IPv4 query with an ECS option indicating a"
echo_i "         short prefix-length (shorter than the configured"
echo_i "         prefix-length). Check that the resolver queries for"
echo_i "         the requested prefix length. Close to the expiration"
echo_i "         of the RR, send another query with an ECS option."
echo_i "         Check that the resolver refreshes the cache with a"
echo_i "         query for the requested prefix length. This is regarding"
echo_i "         prefetch. ($n)"
ret=0
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.1.0/24 txt test${n}.short-ttl.test.example > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.1.0, 24,' > /dev/null || ret=1
ttl1=`awk '/"Some text here"/ { print $2 - 2 }' dig.out.${n}.1`
# sleep so we are in prefetch range
sleep ${ttl1:-0}
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
# trigger prefetch
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.2.0/24 txt test${n}.short-ttl.test.example > dig.out.${n}.2 || ret=1
ttl2=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.2`
sleep 1
# check that prefetch occured
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.2.0, 24,' > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.3.0/24 txt test${n}.short-ttl.test.example > dig.out.${n}.3 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
ttl=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.3`
test ${ttl:-0} -gt ${ttl2:-1} || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "8.3.2    Send IPv6 query with an ECS option indicating a short"
echo_i "         prefix-length (shorter than the configured prefix-length)."
echo_i "         Check that the resolver queries for the requested"
echo_i "         prefix length. Close to the expiration of the RR,"
echo_i "         send another query with an ECS option. Check that"
echo_i "         the resolver refreshes the cache with a query for the"
echo_i "         requested prefix length. This is regarding prefetch. ($n)"
ret=0
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:ff00::/56 txt test${n}.short-ttl.test.example > dig.out.${n}.1 || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56,' > /dev/null || ret=1
    ttl1=`awk '/"Some text here"/ { print $2 - 2 }' dig.out.${n}.1`
    # sleep so we are in prefetch range
    sleep ${ttl1:-0}
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    # trigger prefetch
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:fe00::/56 txt test${n}.short-ttl.test.example > dig.out.${n}.2 || ret=1
    ttl2=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.2`
    sleep 1
    # check that prefetch occured
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:fe00::, 56,' > /dev/null || ret=1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=fd92:7065:b8e:fb00::/56 txt test${n}.short-ttl.test.example > dig.out.${n}.3 || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    ttl=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.3`
    test ${ttl:-0} -gt ${ttl2:-1} || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "8.3.3    Send IPv4 query without an ECS option. Check that the"
echo_i "         resolver queries for the default prefix length. Close to"
echo_i "         the expiration of the RR, send another query without an"
echo_i "         ECS option. Check that the resolver refreshes the cache"
echo_i "         with a query for the default prefix length. This is"
echo_i "         regarding prefetch. ($n)"
ret=0
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 txt test${n}.short-ttl.test.example > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24,' > /dev/null || ret=1
ttl1=`awk '/"Some text here"/ { print $2 - 2 }' dig.out.${n}.1`
# sleep so we are in prefetch range
sleep ${ttl1:-0}
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
# trigger prefetch
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 txt test${n}.short-ttl.test.example > dig.out.${n}.2 || ret=1
ttl2=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.2`
sleep 1
# check that prefetch occured
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24,' > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 txt test${n}.short-ttl.test.example > dig.out.${n}.3 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
ttl=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.3`
test ${ttl:-0} -gt ${ttl2:-1} || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "8.3.4    Send IPv6 query without an ECS option. Check that the"
echo_i "         resolver queries for the default prefix length. Close to"
echo_i "         the expiration of the RR, send another query without an"
echo_i "         ECS option. Check that the resolver refreshes the cache"
echo_i "         with a query for the default prefix length. This is"
echo_i "         regarding prefetch. ($n)"
ret=0
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 txt test${n}.short-ttl.test.example > dig.out.${n}.1 || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56,' > /dev/null || ret=1
    ttl1=`awk '/"Some text here"/ { print $2 - 2 }' dig.out.${n}.1`
    # sleep so we are in prefetch range
    sleep ${ttl1:-0}
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    # trigger prefetch
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 txt test${n}.short-ttl.test.example > dig.out.${n}.2 || ret=1
    ttl2=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.2`
    sleep 1
    # check that prefetch occured
    nextpart ans8/ans.run | grep 'ClientSubnetOption(fd92:7065:b8e:ff00::, 56,' > /dev/null || ret=1
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 txt test${n}.short-ttl.test.example > dig.out.${n}.3 || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
    ttl=`awk '/"Some text here"/ { print $2 }' dig.out.${n}.3`
    test ${ttl:-0} -gt ${ttl2:-1} || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "10.1     Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "10.1.1   Send an IPv4 query with source prefix-length set to 0."
echo_i "         Check that upstream queries contain an ECS option with"
echo_i "         a source prefix-length of 0. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "10.1.2   Send an IPv6 query with source prefix-length set to 0."
echo_i "         Check that upstream queries contain an ECS option with"
echo_i "         a source prefix-length of 0. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and disable ECS forwarding"

n=`expr $n + 1`
echo_i "10.1.3   Send an IPv4 query with source prefix-length set to 0."
echo_i "         Check that upstream queries contain an ECS option with"
echo_i "         a source prefix-length of 0. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.2 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "10.1.4   Send an IPv6 query with source prefix-length set to 0."
echo_i "         Check that upstream queries contain an ECS option with"
echo_i "         a source prefix-length of 0. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=0 test${n}.test.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "10.2     Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "10.2.1   Send an IPv4 query with source prefix-length set to"
echo_i "         less than the default source prefix-length setting in"
echo_i "         the resolver. Check that upstream query contains an"
echo_i "         ECS option with the specified source prefix-length. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10/8 test${n}.short.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.0.0.0, 8' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "10.2.2   Send an IPv4 query with source prefix-length set equal"
echo_i "         to the default source prefix-length setting in the"
echo_i "         resolver. Check that upstream query contains an"
echo_i "         ECS option with the specified source prefix-length. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=11.22/16 test${n}.short.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(11.22.0.0, 16' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "10.2.3   Send an IPv4 query with source prefix-length set"
echo_i "         greater to the default source prefix-length setting"
echo_i "         in the resolver. Check that upstream query contains"
echo_i "         an ECS option with the default source prefix-length. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=11.22.33.44/32 test${n}.short.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(11.22.0.0, 16' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "10.2.4   Send an IPv6 query with source prefix-length set"
echo_i "         to less than the default source prefix-length setting"
echo_i "         in the resolver. Check that upstream query contains"
echo_i "         an ECS option with the specified source prefix-length. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS -b fd92:7065:b8e:ffff::1 @fd92:7065:b8e:ffff::7 +subnet=1111::/16 test${n}.short.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(1111::, 16,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "10.2.5   Send an IPv6 query with source prefix-length set"
echo_i "         equal to the default source prefix-length setting in"
echo_i "         the resolver. Check that upstream query contains"
echo_i "         an ECS option with the specified source prefix-length. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS -b fd92:7065:b8e:ffff::1 @fd92:7065:b8e:ffff::7 +subnet=1111:2222:3333::/48 test${n}.short.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(1111:2222:3333::, 48,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "10.2.6   Send an IPv6 query with source prefix-length set"
echo_i "         greater to the default source prefix-length setting"
echo_i "         in the resolver. Check that upstream query contains"
echo_i "         an ECS option with the default source prefix-length. ($n)"
ret=0
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 -b fd92:7065:b8e:ffff::1 +subnet=1111:2222:3333:4444::/64 test${n}.short.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(1111:2222:3333::, 48' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "12.2     Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding, ensure that each of the"
echo_i "         following receive a FORMERR response"

echo_i "12.2.1   (Test deleted)"

echo_i "12.2.2   (Test deleted)"

n=`expr $n + 1`
echo_i "12.2.3   Send an IPv4 query with an invalid family specified ($n)"
ret=0
# FAMILY set to 4097
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:100110000a35 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.4   Send an IPv6 query with an invalid family specified ($n)"
ret=0
# FAMILY set to 4097
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:100110000a35 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "12.2.5   Send an IPv4 query with -5 source prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to -5 (0xfb)
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:1001fb000a35 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.6   Send an IPv6 query with -5 source prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to -5 (0xfb)
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:1001fb000a35 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "12.2.7   Send an IPv4 query with maximum source prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to maximum (0xff)
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:1001ff000a35 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.8   Send an IPv6 query with maximum source prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to maximum (0xff)
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:1001ff000a35 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "12.2.9   Send an IPv4 query with -5 scope prefix length ($n)"
ret=0
# SCOPE-PREFIX-LENGTH set to -5 (0xfb)
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:100100fb0a35 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.10  Send an IPv6 query with -5 scope prefix length ($n)"
ret=0
# SCOPE-PREFIX-LENGTH set to -5 (0xfb)
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:100100fb0a35 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "12.2.11  Send an IPv4 query with maximum scope prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to maximum (0xff)
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:100100ff0a35 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.12  Send an IPv6 query with maximum scope prefix length ($n)"
ret=0
# SOURCE-PREFIX-LENGTH set to maximum (0xff)
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:100100ff0a35 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

n=`expr $n + 1`
echo_i "12.2.13  Send an IPv4 query with an invalid address specified ($n)"
ret=0
# ADDRESS set too long for source prefix length
$DIG $DIGOPTS @10.53.0.7 +ednsopt=8:100110000a350000 test${n}.test.example > dig.out.$n || ret=1
grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "12.2.14  Send an IPv6 query with an invalid address specified ($n)"
ret=0
# ADDRESS set too long for source prefix length
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +ednsopt=8:100110000a350000 test${n}.test.example > dig.out.$n || ret=1
    grep "status: FORMERR" dig.out.$n > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "13.4     Enable ECS (for a specific domain by adding that domain to"
echo_i "         the white list) and ECS forwarding"

n=`expr $n + 1`
echo_i "13.4.1   Send a number of queries to fill the cache with"
echo_i "         various names and check that rndc flushname removes"
echo_i "         a single domain from the cache, along with its ECS"
echo_i "         information. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
# all of these should recurse
$DIG $DIGOPTS @10.53.0.7 test${n}-1.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl1=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
# flush the third one
$RNDCCMD 10.53.0.7 flushname test${n}-3.test.example 2>&1 | sed 's/^/I:ns7 /'
sleep 1
# first two should not recurse; third one should
$DIG $DIGOPTS @10.53.0.7 test${n}-1.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.test.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl2=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
[ "$ttl1" -eq "$ttl2" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "13.4.2   Check that rndc flushtree removes a domain and all"
echo_i "         subdomains from the cache, along with their ECS"
echo_i "         information. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
# all of these should recurse
$DIG $DIGOPTS @10.53.0.7 test${n}-1.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl1=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
# flush the third one
$RNDCCMD 10.53.0.7 flushtree test.example 2>&1 | sed 's/^/I:ns7 /'
sleep 1
# first two should not recurse; third one should
$DIG $DIGOPTS @10.53.0.7 test${n}-1.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl2=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
[ "$ttl1" -eq "$ttl2" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "13.4.3   Check that rndc flush empties the cache, including"
echo_i "         all ECS information. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
# all of these should recurse
$DIG $DIGOPTS @10.53.0.7 test${n}-1.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl1=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
sleep 1
# flush everything
$RNDCCMD 10.53.0.7 flush 2>&1 | sed 's/^/I:ns7 /'
sleep 1
# all three should recurse
$DIG $DIGOPTS @10.53.0.7 test${n}-1.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 test${n}-2.short.example > dig.out.$n || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 test${n}-3.test.example > dig.out.$n || ret=1
ttl2=`awk '/test.*-3.test.example/ {print $2}' dig.out.$n`
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null || ret=1
[ "$ttl1" -eq "$ttl2" ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "End of tests from Requirements Document."

echo_i "Miscellaneous additional tests:"
n=`expr $n + 1`
echo_i "         Check that when an ECS-tagged response contains a"
echo_i "         CNAME pointing to a record with a short TTL, both"
echo_i "         records are cached correctly. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test${n}.short-ttl.cname.test.example > dig.out.${n}.1 || ret=1
# there should be two ECS queries
nextpart ans8/ans.run > ans.out.$n
lines=`grep 'ClientSubnetOption(' ans.out.$n | wc -l`
[ "$lines" -eq 2 ] || ret=1
# sleep long enough for the non-CNAME A record to expire
ttl=`awk '!/CNAME/ { print $2 + 1 }' dig.out.${n}.1`
sleep ${ttl:-11}
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
# query again
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test${n}.short-ttl.cname.test.example > dig.out.${n}.2 || ret=1
before=`awk '!/CNAME/ { print $2 }' dig.out.${n}.2`
# there should be one ECS query
nextpart ans8/ans.run > ans.out.$n
lines=`grep 'ClientSubnetOption(' ans.out.$n | wc -l`
[ "$lines" -eq 1 ] || ret=1
sleep 1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test${n}.short-ttl.cname.test.example > dig.out.${n}.3 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
after=`awk '!/CNAME/ { print $2 }' dig.out.${n}.3`
test ${before:-0} -gt ${after:-1} || ret=1
# check the cache directly as well
dumpdb || ret=1
dumpdb_grep "^;test${n}\.short-ttl\.cname\.test\.example" "CNAME" || ret=1
dumpdb_grep "^;test${n}\.short-ttl\.test\.example" "A" || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that queries involving CNAME lookup return"
echo_i "         correct SCOPE PREFIX-LENGTH in replies to the"
echo_i "         client. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.1.0/14 test${n}.cname2.test.example > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.52.0.0, 14,' > /dev/null || ret=1
grep "CLIENT-SUBNET: 10.52.0.0/14/14" dig.out.${n}.1 > /dev/null || ret=1
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=10.53.1.0/13 test${n}.cname2.test.example > dig.out.${n}.2 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.48.0.0, 13,' > /dev/null || ret=1
grep "CLIENT-SUBNET: 10.48.0.0/13/15" dig.out.${n}.2 > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of non-zero length for a"
echo_i "         whitelisted name is correctly sent when forwarding"
echo_i "         queries to an upstream resolver. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.0.1 +subnet=10.53.3/24 test${n}.test.example > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.3.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of zero length for a"
echo_i "         whitelisted name is correctly sent when forwarding"
echo_i "         queries to an upstream resolver. ($n)"
ret=0
# discard prior logging
nextpart ns4/named.run > /dev/null
nextpart ns7/named.run > /dev/null
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.0.1 +subnet=0 test${n}.test.example > dig.out.${n}.1 || ret=1
nextpart ns4/named.run > run.out.$n.4
nextpart ns7/named.run > run.out.$n.7
lines4=`grep '^; CLIENT-SUBNET: [0.:]*/0/0' run.out.$n.4 | wc -l`
[ "$lines4" -eq 2 ] || ret=1
lines7=`grep '^; CLIENT-SUBNET: [0.:]*/0/0' run.out.$n.7 | wc -l`
[ "$lines7" -eq 2 ] || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of non-zero length for a"
echo_i "         non-whitelisted name is not sent when forwarding"
echo_i "         queries to an upstream resolver. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.0.1 +subnet=10.53.3/24 test${n}.outside.whitelist > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of zero length for a"
echo_i "         non-whitelisted name is sent when forwarding"
echo_i "         queries to an upstream resolver. ($n)"
ret=0
# discard prior named.run logging
nextpart ns4/named.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.0.1 +subnet=0 test${n}.outside.whitelist > dig.out.${n}.1 || ret=1
nextpart ns4/named.run > run.out.$n
lines=`grep '^; CLIENT-SUBNET: 0.0.0.0/0/0' run.out.$n | wc -l`
[ "$lines" -eq 2 ] || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option is synthesized when querying"
echo_i "         a whitelisted name and forwarding queries to an "
echo_i "         upstream resolver. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.0.1 test${n}.test.example > dig.out.${n}.1 || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option is not synthesized for"
echo_i "         a non-whitelisted name when forwarding queries to an"
echo_i "         upstream resolver. ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.4 -b 10.53.2.1 test${n}.outside.whitelist > dig.out.${n}.1 || ret=1
# ns4 should *not* synthesize an ECS option from the source address
# of this query, therefore ns7 *should* synthesize one from the query
# source address of ns4, which is in 10.53.0/24.
nextpart ans8/ans.run | grep 'ClientSubnetOption(10.53.0.0, 24' > /dev/null && ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of zero length with family"
echo_i "         set to IPv6 but sent over IPv4 is processed correctly ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.7 +subnet=fd92::/0 test${n}.4only.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
grep "CLIENT-SUBNET: ::/0/0" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(0.0.0.0, 0,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check that an ECS option of zero length with family"
echo_i "         set to IPv4 but sent over IPv6 is processed correctly ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
if $TESTSOCK6 fd92:7065:b8e:ffff::6 2> /dev/null
then
    $DIG $DIGOPTS @fd92:7065:b8e:ffff::7 +subnet=10.53/0 test${n}.6only.example > dig.out.$n || ret=1
    grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
    grep "CLIENT-SUBNET: 0.0.0.0/0/0" dig.out.$n > /dev/null || ret=1
    nextpart ans8/ans.run | grep 'ClientSubnetOption(::, 0,' > /dev/null || ret=1
    if [ $ret -eq 1 ] ; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped IPv6 not configured"
fi

echo_i "         Configure a resolver with ecs-privacy"
copy_setports ns5/named3.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig 2>&1 | sed 's/^/I:ns5 /'
sleep 3

n=`expr $n + 1`
echo_i "         Check that ecs-privacy is honored ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 test${n}.test.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
grep "CLIENT-SUBNET" dig.out.$n > /dev/null && ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption([0.:]*, 0,' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "         Check ecs-privacy with ECS forwarding ($n)"
ret=0
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS -b 10.53.0.1 @10.53.0.5 +subnet=127.0.0.1/24 test${n}.4only.example > dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n > /dev/null || ret=1
grep "CLIENT-SUBNET: 127.0.0.0/24/0" dig.out.$n > /dev/null || ret=1
nextpart ans8/ans.run | grep 'ClientSubnetOption(127.0.0.0, 24' > /dev/null || ret=1
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "         Check that rndc dumpdb -ecscache works as expected. ($n)"
ret=0
# discard cache
$RNDCCMD 10.53.0.7 flush
# discard prior ans.run logging
nextpart ans8/ans.run > /dev/null
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test.short-ttl.cname.test.example > dig.out.${n}.1 || ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 test.short-ttl.cname.test.example txt > dig.out.${n}.1 || ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 +subnet=192.168.1.0/24 scope20.test.example > dig.out.${n}.1 || ret=1
$DIG $DIGOPTS +noall +answer @10.53.0.7 -b 10.53.0.1 +subnet=192.168.1.0/24 scope20.test.example aaaa > dig.out.${n}.1 || ret=1
dumpdb || ret=1
grep "^; ECS cache dump of view 'default' (cache default)" ns7/named_dump.db > /dev/null || ret=1
cat ns7/named_dump.db | sed -e '/$DATE/,/Address database/!d' |
    grep -v "DATE" | \
    sed -e 's/[ 	]/ /g' -e 's/  */ /g' | \
    sed -e 's/ 29[0-9] / 300 /g' | \
    sed -e 's/ 359[0-9] / 3600 /g' | \
    sed -e 's/ 8639[0-9] / 86400 /g' | \
    sed -e 's/ [0-9] / 10 /g' > dumpdb.output
grep -E "^;test\.short\-ttl\.cname\.test\.example\. 3600 CNAME test\.short\-ttl\.test\.example\. ;; address prefix \= 10\.53\.0\.0\/16$" dumpdb.output > /dev/null || \
    { ret=1 ; echo_i "grep step 1 failed"; }
grep -E "^;scope20\.test\.example\. 86400 A 10\.53\.0\.8 ;; address prefix \= 192\.168\.0\.0\/20$" dumpdb.output > /dev/null || \
    { ret=1 ; echo_i "grep step 2 failed"; }
grep -E "^;scope20\.test\.example\. 86400 AAAA fd92\:7065\:b8e\:ffff\:\:8 ;; address prefix \= 192\.168\.0\.0\/20$" dumpdb.output > /dev/null || \
    { ret=1 ; echo_i "grep step 3 failed"; }
grep -E "^;test\.short\-ttl\.test\.example. 10 A 10\.53\.0\.8 ;; address prefix \= 10\.53\.0\.0\/16$" dumpdb.output > /dev/null || \
    { ret=1 ; echo_i "grep step 4 failed"; }
grep -E "^;test\.short\-ttl\.test\.example. 10 TXT \"Some text here\" ;; address prefix \= 10\.53\.0\.0\/16$" dumpdb.output > /dev/null || \
    { ret=1 ; echo_i "grep step 5 failed"; }
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "         Check that responses with invalid ECS options are dropped. ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=192.168.1.0/24 scope32.test.example > dig.out.${n}.1 || ret=1
grep SERVFAIL dig.out.${n}.1 > /dev/null && { ret=1; echo "step 1 failed"; }
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=192.168.1.0/24 scope33.test.example > dig.out.${n}.2 || ret=1
grep SERVFAIL dig.out.${n}.2 > /dev/null || { ret=1; echo "step 2 failed"; }
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=fd92:7065:b8e:ffff::/48 scope49.test.example > dig.out.${n}.3 || ret=1
grep SERVFAIL dig.out.${n}.3 > /dev/null && { ret=1; echo "step 3 failed"; }
$DIG $DIGOPTS @10.53.0.7 -b 10.53.0.1 +subnet=fd92:7065:b8e:ffff::/48 scope129.test.example > dig.out.${n}.4 || ret=1
grep SERVFAIL dig.out.${n}.4 > /dev/null || { ret=1; echo "step 4 failed"; }
if [ $ret -eq 1 ] ; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
exit $status

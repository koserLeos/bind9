#!/bin/sh
#
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

MAJOR=1
MINOR=15
dnstest="import dns, dns.version, sys
if (sys.version_info[0] == 3):
    if (dns.version.MAJOR == $MAJOR and dns.version.MINOR < $MINOR):
        sys.exit(1)"
ret=1
if test -n "$PYTHON"
then
        if $PYTHON -c "import dns" 2> /dev/null
        then
                ret=0
        fi
fi

if [ $ret != 0 ]
then
    echo "Python and the dnspython module are required to run the" >&2
    echo "ECS system tests." >&2
    exit 1
fi
ret=1
if $PYTHON -c "$dnstest"
then
	ret=0
fi
if [ $ret != 0 ]
then
    echo "dnspython is version too old (< $MAJOR.$MINOR.0) to run the" >&2
    echo "ECS system tests with python 3." >&2
    exit 1
fi

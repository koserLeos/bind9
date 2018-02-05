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

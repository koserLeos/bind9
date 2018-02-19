#!/bin/sh
#
# Copyright (C) 2012, 2014-2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$

#
# Clean up after zone transfer tests.
#

rm -f ns3/example.bk
rm -f ns3/internal.bk
rm -f */named.memstats
rm -f */named.run
rm -f */ans.run
rm -f */named.stats
rm -f dig.out*
rm -f curl.out.*
rm -f ns*/named.lock
rm -f stats*out

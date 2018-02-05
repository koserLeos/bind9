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

rm -f dig.out.* named*.run ans.out.* run.out.* named*.pid
rm -f */named.memstats */named.recursing */named.run */named.run.prev
rm -f */ans.run */ans.run.prev
rm -f */*.pyc
rm -f ns5/named.conf
rm -f ns7/named_dump.db
rm -f dumpdb.output
rm -rf ans8/__pycache__

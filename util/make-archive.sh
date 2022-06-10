#!/bin/bash

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

autoreconf -fi
./configure
make all
# create archive and parse output for archive name
TARDIR=$(make dist 2>&1 | sed -n 's/tardir=\([^ ]\+\).*/\1/p')
# print created archive name
ls -1 $TARDIR.tar.*

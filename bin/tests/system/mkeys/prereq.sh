#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

symlink_alg=$(basename $PWD | awk -F- '{ print $2 }')
if [ "$symlink_alg" == "eddsa" ]; then
	exec $SHELL ../testcrypto.sh eddsa
else
	exec $SHELL ../testcrypto.sh
fi

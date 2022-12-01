#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

set -e

softhsm2-util --module "$SOFTHSM2_MODULE" --show-slots > softhsm2.out.slots 2> softhsm2.err.slots

softhsm2-util --module "$SOFTHSM2_MODULE" --init-token --free \
	--pin ${HSMPIN:-1234} --so-pin ${HSMPIN:-1234} \
	--label "softhsm2-keyfromlabel" > softhsm2.out.init 2>softhsm2.err.init

awk '/^The token has been initialized and is reassigned to slot/ { print $NF }' softhsm2.out.init

printf '%s' "${HSMPIN:-1234}" > pin
PWD=$(pwd)

#!/bin/sh -e

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

# shellcheck source=conf.sh
. ../../conf.sh

echo_i "ns2/setup.sh"

for zn in multisigner secondary; do
  zone="${zn}"
  infile="${zn}.db.in"
  unsigned="${zn}.db.unsigned"
  zonefile="${zn}.db"

  copy_setports $infile $unsigned

  csk=$("$KEYGEN" -q -fk -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -n zone "$zone")
  cat "$csk.key" >> "$unsigned"
  private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$csk" >> "$unsigned"

  $SIGNER -S -g -z -x -s now-1h -e now+30d -o $zone -O full -f $zonefile $unsigned > signer.out.$zone 2>&1

  cp "dsset-${zn}." ../ns1/
done

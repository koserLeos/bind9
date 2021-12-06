#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Massage the output from ISC_MEM_DEBUG to extract mem_get() calls
# with no corresponding mem_put().

while (<>) {
    $gets{$1} = $_ if (/mutex:init (?:0x)?([0-9a-f]+) func/);
    delete $gets{$1} if /mutex:destroy (?:0x)?([0-9a-f]+) func/;
}
print join('', values %gets);

exit(0);

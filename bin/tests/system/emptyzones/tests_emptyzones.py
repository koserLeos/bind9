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

from typing import Dict

import isctest


def test_emptyzones(servers: Dict[str, isctest.NamedInstance]):
    """check that switching to automatic empty zones works"""
    ns1 = servers["ns1"]
    ns1.copy_setports("named1.conf.in", "named.conf")
    ns1.reload()
    ns1.copy_setports("named2.conf.in", "named.conf")
    ns1.reload()
    ns1.tcp_query("version.bind", "TXT", "CH")


def test_emptyzones_allow_transfer_none(servers: Dict[str, isctest.NamedInstance]):
    """ "check that allow-transfer { none; } works"""
    ns1 = servers["ns1"]
    ns1.copy_setports("named2.conf.in", "named.conf")
    ns1.reload()
    ns1.tcp_query("10.in-addr.arpa", "AXFR").expect_refused()

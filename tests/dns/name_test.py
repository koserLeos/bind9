#!/usr/bin/python3

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


"""
Example property-based test for dns_name_ API.
"""

import pytest

# in FIPs mode md5 fails so we need 4.41.2 or later which does not use md5
try:
    import hashlib

    hashlib.md5(b"1234")
    pytest.importorskip("hypothesis")
except ValueError:
    pytest.importorskip("hypothesis", minversion="4.41.2")

from hypothesis import assume, example, given

pytest.importorskip("dns", minversion="2.0.0")
import dns.name

from strategies import dns_names

from _pi_cffi import ffi, isc

MCTXP = ffi.new('isc_mem_t **')
isc.isc__mem_create(MCTXP[0])


class ISCName:
    def __init__(self, from_bytes=None):
        self.fixedname = ffi.new('dns_fixedname_t *')
        self.name = isc.dns_fixedname_initname(self.fixedname)
        self.cctx = ffi.new("dns_compress_t *")
        self.dctx = ffi.new("dns_decompress_t *")

        if from_bytes is not None:
            isc.dns_comress_init()

@given(pyname=dns_names(suffix=dns.name.root))
def test_name_in_between_wildcards(pyname: dns.name.Name) -> None:
    iscname = ISCName()
    print(pyname)
    assert pyname == dns.name.from_text(name.to_text())

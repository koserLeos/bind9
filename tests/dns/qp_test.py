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

from _qp_test_cffi import ffi
from _qp_test_cffi import lib as isclibs

NULL = ffi.NULL

# MCTXP = ffi.new('isc_mem_t **')
# isclibs.isc__mem_create(MCTXP)


class ISCName:
    """dns_name_t instance with a private fixed buffer"""

    def __init__(self, from_text=None):
        self.fixedname = ffi.new("dns_fixedname_t *")
        self.name = isclibs.dns_fixedname_initname(self.fixedname)
        # self.cctx = ffi.new("dns_compress_t *")
        # self.dctx = ffi.new("dns_decompress_t *")
        self.formatbuf = ffi.new("char[1024]")  # DNS_NAME_FORMATSIZE

        if from_text is not None:
            assert (
                isclibs.dns_name_fromstring(
                    self.name, from_text.encode("ascii"), NULL, 0, NULL
                )
                == 0
            )

    def format(self):
        isclibs.dns_name_format(self.name, self.formatbuf, len(self.formatbuf))
        return ffi.string(self.formatbuf).decode("ascii")


@given(pyname_source=dns_names(suffix=dns.name.root))
def test_fromname_toname_roundtrip(pyname_source: dns.name.Name) -> None:
    """
    name to/from qpkey must not change the name
    """
    iscname_source = ISCName(from_text=str(pyname_source))
    assert pyname_source == dns.name.from_text(iscname_source.format())

    qpkey = ffi.new("dns_qpkey_t *")
    qpkeysize = isclibs.dns_qpkey_fromname(qpkey[0], iscname_source.name)

    iscname_target = ISCName()
    isclibs.dns_qpkey_toname(qpkey[0], qpkeysize, iscname_target.name)

    pyname_target = dns.name.from_text(iscname_target.format())
    assert pyname_source == pyname_target
    print(pyname_source)

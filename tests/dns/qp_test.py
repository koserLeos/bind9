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

from hypothesis import assume, example, event, given
from hypothesis.stateful import Bundle, RuleBasedStateMachine, rule, precondition
import hypothesis

pytest.importorskip("dns", minversion="2.0.0")
import dns.name

from strategies import dns_names

from _qp_test_cffi import ffi
from _qp_test_cffi import lib as isclibs

NULL = ffi.NULL

MCTXP = ffi.new("isc_mem_t **")
isclibs.isc__mem_create(MCTXP)
MCTX = MCTXP[0]


class ISCName:
    """
    dns_name_t instance with a private fixed buffer

    Make sure Python keeps reference to this object as long
    as it can be referenced from the C side.
    """

    def __init__(self, initval=None):
        self.fixedname = ffi.new("dns_fixedname_t *")
        self.cobj = isclibs.dns_fixedname_initname(self.fixedname)
        # self.cctx = ffi.new("dns_compress_t *")
        # self.dctx = ffi.new("dns_decompress_t *")
        self.formatbuf = ffi.new("char[1024]")  # DNS_NAME_FORMATSIZE

        if initval is None:
            return

        if isinstance(initval, dns.name.Name):
            initval = str(initval)
        if isinstance(initval, str):
            assert (
                isclibs.dns_name_fromstring(
                    self.cobj, initval.encode("ascii"), NULL, 0, NULL
                )
                == 0
            )
            return
        raise NotImplementedError(type(initval))

    def cformat(self):
        isclibs.dns_name_format(self.cobj, self.formatbuf, len(self.formatbuf))
        return ffi.string(self.formatbuf).decode("ascii")

    def pyname(self):
        return dns.name.from_text(self.cformat())


@given(pyname_source=dns_names(suffix=dns.name.root))
def test_fromname_toname_roundtrip(pyname_source: dns.name.Name) -> None:
    """
    name to/from qpkey must not change the name
    """
    iscname_source = ISCName(pyname_source)
    assert pyname_source == iscname_source.pyname()

    qpkey = ffi.new("dns_qpkey_t *")
    qpkeysize = isclibs.dns_qpkey_fromname(qpkey[0], iscname_source.cobj)

    iscname_target = ISCName()
    isclibs.dns_qpkey_toname(qpkey[0], qpkeysize, iscname_target.cobj)

    pyname_target = iscname_target.pyname()
    assert pyname_source == pyname_target


class QPIterator:
    def __init__(self, testcase):
        self.testcase = testcase
        self.iter_generation = testcase.generation
        self.qp = testcase.qp
        self.citer = ffi.new("dns_qpiter_t *")
        print(isclibs.dns_qpiter_init)
        isclibs.dns_qpiter_init(self.qp, self.citer)
        self.expected = sorted(testcase.model.items())

    def _step(self, cfunc):
        iscname = ISCName()
        pval_r = ffi.new("void **")
        ival_r = ffi.new("uint32_t *")
        ret = cfunc(self.citer, iscname.cobj, pval_r, ival_r)
        print("_step", cfunc, "returned", ret)
        if ret == isclibs.ISC_R_NOMORE:
            raise StopIteration(cfunc)
        elif ret == isclibs.ISC_R_FAILURE:
            raise RuntimeError(cfunc)
        print("  -> iterator returned: ", iscname.pyname(), pval_r[0], ival_r[0])
        assert ret == isclibs.ISC_R_SUCCESS
        return iscname, pval_r[0], ival_r[0]

    def is_valid(self):
        """Check if QP this iterator referenced is supposed to be still valid"""
        return self.iter_generation == self.testcase.generation

    def next_(self):
        return self._step(isclibs.dns_qpiter_next)

    def prev(self):
        return self._step(isclibs.dns_qpiter_prev)

    def current(self):
        return self._step(isclibs.dns_qpiter_current)


class BareQPTest(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.generation = 0
        print("TEST RESTART FROM SCRATCH, GENERATION", self.generation)

        self.qpptr = ffi.new("dns_qp_t **")
        isclibs.dns_qp_create(MCTX, ffi.addressof(isclibs.qp_methods), NULL, self.qpptr)
        self.qp = self.qpptr[0]

        self.model = {}

    names = Bundle("names")

    def invalidate_refs(self):
        """Mark current QP as changed - iterators which depend on unchanged state are now invalid"""
        self.generation += 1
        print("GENERATION ", self.generation)

    @rule(target=names, pyname=dns_names())
    def add(self, pyname):
        hypothesis.event("ADD")
        print("ADD", pyname)
        self.invalidate_refs()

        iscname = ISCName(pyname)

        ret = isclibs.dns_qp_insert(self.qp, iscname.cobj, 0)
        if pyname not in self.model:
            assert ret == isclibs.ISC_R_SUCCESS
            self.model[pyname] = iscname
        else:
            assert ret == isclibs.ISC_R_EXISTS

        return pyname

    @rule(pyname=names)
    def delete(self, pyname):
        hypothesis.event("DELETE")
        print("DELETE", pyname)
        self.invalidate_refs()
        exists = pyname in self.model

        iscname = ISCName(pyname)

        pval = ffi.new("void **")
        ret = isclibs.dns_qp_deletename(self.qp, iscname.cobj, pval, NULL)
        if exists:
            assert ret == isclibs.ISC_R_SUCCESS
            assert pval[0] == self.model[pyname].cobj
            del self.model[pyname]
        else:
            assert ret == isclibs.ISC_R_NOTFOUND

    def _iterate_compare(self, tmp_iter, expected, stepfunc):
        """QP must be non-empty, and must be positioned on first item"""

        got_iscname, got_cobj, _ = tmp_iter.current()
        qp_count = 1
        for exp_pyname, exp_iscname in expected:
            assert exp_pyname == got_iscname.pyname()
            assert exp_iscname.cobj == ffi.cast("dns_name_t *", got_cobj)

            try:
                got_iscname, got_cobj, _ = stepfunc()
                qp_count += 1
            except StopIteration:
                pass

        with pytest.raises(StopIteration):
            # QP must not have more items than we recorded in model
            stepfunc()

        assert qp_count == len(
            tmp_iter.expected
        ), "number of keys during full forward iteration must match"

    @rule()
    def values_agree(self):
        """Iterate through all values and check ordering"""
        tmp_iter = QPIterator(self)
        hypothesis.event("CHECK", len(tmp_iter.expected))

        # not-yet positioned iterator must always fail
        with pytest.raises(RuntimeError):
            got_iscname, got_cobj, _ = tmp_iter.current()

        # prev() gives the last entry unless the QP is empty
        try:
            got_iscname, got_cobj, _ = tmp_iter.prev()
        except StopIteration:
            assert len(tmp_iter.expected) == 0

        # try next() will fail if the set is empty or has only one item
        try:
            got_iscname, got_cobj, _ = tmp_iter.next_()
        except StopIteration:
            assert len(tmp_iter.expected) <= 1
            if len(tmp_iter.expected) == 0:
                return

        self._iterate_compare(tmp_iter, sorted(tmp_iter.expected), tmp_iter.next_)
        self._iterate_compare(
            tmp_iter, sorted(tmp_iter.expected, reverse=True), tmp_iter.prev
        )


TestTrees = BareQPTest.TestCase
# TestTrees.settings = hypothesis.settings(
# max_examples=50, stateful_step_count=10
# )

# Or just run with pytest's unittest support
if __name__ == "__main__":
    state = BareQPTest()
    names_0 = state.add(pyname=dns.name.root)
    state.values_agree()
    # unittest.main()

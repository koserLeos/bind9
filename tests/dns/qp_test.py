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

from strategies import dns_names, composite

from _qp_test_cffi import ffi
from _qp_test_cffi import lib as isclibs

NULL = ffi.NULL

MCTXP = ffi.new("isc_mem_t **")
isclibs.isc__mem_create(MCTXP)
MCTX = MCTXP[0]


@composite
def subdomains(draw, named_bundle):
    parent = draw(named_bundle)
    # the parent name has less then two bytes left, no way to add a subdomain to it
    if len(parent) + sum(map(len, parent)) > 253:
        return parent
    subdomain = draw(dns_names(suffix=parent))
    return subdomain


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
        # print(id(self), isclibs.dns_qpiter_init)
        isclibs.dns_qpiter_init(self.qp, self.citer)

        self.model = testcase.model.copy()
        self.sorted = sorted(self.model)
        self.position = None

    def _step(self, cfunc):
        iscname = ISCName()
        got_pval_r = ffi.new("void **")
        got_ival_r = ffi.new("uint32_t *")
        got_ret = cfunc(self.citer, iscname.cobj, got_pval_r, got_ival_r)
        print(
            id(self),
            "_step",
            cfunc,
            "\n-> returned: ",
            got_ret,
            iscname.pyname(),
            got_pval_r[0],
            got_ival_r[0],
        )
        return got_ret, iscname, got_pval_r[0], got_ival_r[0]

    def _check_return_values(self, got_iscname, got_pval_r, _got_ival_r):
        assert self.position is not None, "usage error in test script"
        exp_pyname = self.sorted[self.position]
        exp_iscname = self.model[exp_pyname]
        assert exp_pyname == got_iscname.pyname()
        assert exp_iscname.cobj == got_pval_r

    def is_valid(self):
        """Check if QP this iterator referenced is supposed to be still valid"""
        return self.iter_generation == self.testcase.generation

    def next_(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_next
        )
        if len(self.model) == 0 or self.position == len(self.model) - 1:
            assert got_ret == isclibs.ISC_R_NOMORE
            self.position = None
        else:
            assert got_ret == isclibs.ISC_R_SUCCESS
            if self.position is None:
                self.position = 0
            else:
                self.position += 1
            self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r

    def prev(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_prev
        )
        if len(self.model) == 0 or self.position == 0:
            assert got_ret == isclibs.ISC_R_NOMORE
            self.position = None
        else:
            assert got_ret == isclibs.ISC_R_SUCCESS
            if self.position is None:
                self.position = len(self.model) - 1
            else:
                self.position -= 1
            self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r

    def current(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_current
        )

        if self.position is None:
            assert got_ret == isclibs.ISC_R_FAILURE
            return

        assert got_ret == isclibs.ISC_R_SUCCESS
        self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r


class BareQPTest(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.generation = 0
        print("\n\nTEST RESTART FROM SCRATCH, GENERATION", self.generation)

        self.qpptr = ffi.new("dns_qp_t **")
        isclibs.dns_qp_create(MCTX, ffi.addressof(isclibs.qp_methods), NULL, self.qpptr)
        self.qp = self.qpptr[0]

        self.model = {}
        self.iter_ = QPIterator(self)

    names = Bundle("names")
    iterators = Bundle("iterators")

    def invalidate_refs(self):
        """Mark current QP as changed - iterators which depend on unchanged state are now invalid"""
        self.generation += 1
        return  # TODO

        self.iter_ = QPIterator(self)
        print("GENERATION ", self.generation)

    @rule(target=names, pyname=dns_names())
    def add_random(self, pyname):
        hypothesis.event("ADD random")
        return self._add(pyname)

    @precondition(lambda self: len(self.model) > 0)
    @rule(target=names, pyname=subdomains(names))
    def add_subdomain(self, pyname):
        hypothesis.event("ADD subdomain")
        return self._add(pyname)

    def _add(self, pyname):
        iscname = ISCName(pyname)

        ret = isclibs.dns_qp_insert(self.qp, iscname.cobj, 0)
        print("insert", pyname, ret)
        hypothesis.event("INSERT", ret)
        if pyname not in self.model:
            assert ret == isclibs.ISC_R_SUCCESS
            self.model[pyname] = iscname
        else:
            assert ret == isclibs.ISC_R_EXISTS

        self.invalidate_refs()
        return pyname

    @rule(pyname=names)
    def delete(self, pyname):
        print("DELETENAME", pyname)
        exists = pyname in self.model

        iscname = ISCName(pyname)

        pval = ffi.new("void **")
        ret = isclibs.dns_qp_deletename(self.qp, iscname.cobj, pval, NULL)
        hypothesis.event("DELETENAME", ret)
        if exists:
            assert ret == isclibs.ISC_R_SUCCESS
            assert pval[0] == self.model[pyname].cobj
            del self.model[pyname]
        else:
            assert ret == isclibs.ISC_R_NOTFOUND
        self.invalidate_refs()

    def iter_init(self):
        hypothesis.event("init")
        self.iter_ = QPIterator(self)

    @rule()
    def iter_next(self):
        if not self.iter_.is_valid():
            hypothesis.event("iter invalid")
            return

        hypothesis.event("next", self.iter_.position)
        self.iter_.next_()

    @rule()
    def iter_prev(self):
        if not self.iter_.is_valid():
            hypothesis.event("iter invalid")
            return

        hypothesis.event("prev", self.iter_.position)
        self.iter_.prev()

    @rule()
    def iter_current(self):
        if not self.iter_.is_valid():
            hypothesis.event("iter invalid")
            return

        hypothesis.event("current")
        self.iter_.current()

    @rule(pylookupname=dns_names())
    def lookup_random(self, pylookupname):
        return self._lookup(pylookupname)

    @rule(pylookupname=names)
    def lookup_known(self, pylookupname):
        return self._lookup(pylookupname)

    @precondition(lambda self: len(self.model) > 0)
    @rule(pylookupname=subdomains(names))
    def lookup_subdomain(self, pylookupname):
        return self._lookup(pylookupname)

    def _lookup(self, pylookupname):
        outiter = QPIterator(self)
        lookupname = ISCName(pylookupname)
        foundname = ISCName()
        ret = isclibs.dns_qp_lookup(
            self.qp, lookupname.cobj, foundname.cobj, outiter.citer, NULL, NULL, NULL
        )
        print("LOOKUP", ret, pylookupname)
        hypothesis.event("LOOKUP", ret)

        # verify that no unepected parent name exists in our model
        if ret == isclibs.ISC_R_NOTFOUND:
            # no parent can be present, not even the root
            common_labels = 0
        elif ret == isclibs.DNS_R_PARTIALMATCH:
            assert (
                foundname.pyname() < pylookupname
            ), "foundname is not a subdomain of looked up name"
            common_labels = len(foundname.pyname())
        elif ret == isclibs.ISC_R_SUCCESS:
            # exact match!
            assert pylookupname == foundname.pyname()
            common_labels = len(pylookupname)
        else:
            raise NotImplementedError(ret)

        for splitidx in range(len(pylookupname), common_labels, -1):
            parentname = pylookupname.split(splitidx)[1]
            assert (
                parentname not in self.model
            ), "found parent node which reportedly does not exist"

    @rule()
    def values_agree_forward(self):
       """Iterate through all values and check ordering"""
       tmp_iter = QPIterator(self)
       hypothesis.event("values_agree_forward", len(tmp_iter.model))

       qp_count = 0
       while (got_ret := tmp_iter.next_()[0]) == isclibs.ISC_R_SUCCESS:
           qp_count += 1

       assert qp_count == len(tmp_iter.model)

    @rule()
    def values_agree_backwards(self):
       """Iterate through all values and check ordering"""
       tmp_iter = QPIterator(self)
       hypothesis.event("values_agree_backwards", len(tmp_iter.model))

       qp_count = 0
       while (got_ret := tmp_iter.prev()[0]) == isclibs.ISC_R_SUCCESS:
           qp_count += 1

       assert qp_count == len(tmp_iter.model)


TestTrees = BareQPTest.TestCase
TestTrees.settings = hypothesis.settings(
    max_examples=100, deadline=None
)  # , stateful_step_count=10

# Or just run with pytest's unittest support
if __name__ == "__main__":
    unittest.main()

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


import isctest.mark


# The "checking that BIND 9 doesn't crash on long TCP messages" check of the
# tcp system test is unstable when free memory is lacking. See issue #4298.
@isctest.mark.flaky(max_runs=2)
def test_tcp(run_tests_sh):
    run_tests_sh()

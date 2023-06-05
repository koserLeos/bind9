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

import pytest


# "tcp:checking that BIND 9 doesn't crash on long TCP messages" check fails
# intermittently, see #4038.
@pytest.mark.serial
def test_tcp(run_tests_sh):
    run_tests_sh()

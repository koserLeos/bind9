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

import os
from typing import Optional

import dns.query
import dns.message


QUERY_TIMEOUT = 10


def udp(
    message: dns.message.Message,
    ip: str,
    port: Optional[int] = None,
    source: Optional[str] = None,
    timeout: int = QUERY_TIMEOUT,
) -> dns.message.Message:
    if port is None:
        port = int(os.environ["PORT"])
    return dns.query.udp(message, ip, timeout, port=port, source=source)


def tcp(
    message: dns.message.Message,
    ip: str,
    port: Optional[int] = None,
    source: Optional[str] = None,
    timeout: int = QUERY_TIMEOUT,
) -> dns.message.Message:
    if port is None:
        port = int(os.environ["PORT"])
    return dns.query.tcp(message, ip, timeout, port=port, source=source)


def tls(  # pylint: disable=too-many-arguments
    message: dns.message.Message,
    ip: str,
    port: Optional[int] = None,
    source: Optional[str] = None,
    timeout: int = QUERY_TIMEOUT,
    verify: Optional[bool] = None,
) -> dns.message.Message:
    if port is None:
        port = int(os.environ["TLSPORT"])
    if verify is None:
        verify = False
    return dns.query.tls(message, ip, timeout, port=port, source=source, verify=verify)

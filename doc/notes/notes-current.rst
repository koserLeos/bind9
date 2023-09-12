.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Notes for BIND 9.19.17
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Add support for User Statically Defined Tracing (USDT) probes - static tracing
  points for user-level software.  This allows a fine-grained application
  tracing with zero-overhead when the probes are not enabled. :gl:`#4041`

Removed Features
~~~~~~~~~~~~~~~~

- The :any:`dnssec-must-be-secure` option has been deprecated and will be
  removed in a future release. :gl:`#4263`

Feature Changes
~~~~~~~~~~~~~~~

- Make :iscman:`nsupdate` honor the ``-v`` option for SOA queries, that is send
  the request over TCP, only if the server is specified. :gl:`#1181`

- Extend client side support for the EDNS EXPIRE option to IXFR and
  AXFR query types. ``named`` will now be making EDNS queries AXFR
  and IXFR queries with EDNS options present.  :gl:`#4170`

- Compiling with jemalloc versions older than 4.0.0 is no longer supported;
  those versions do not provide the features required by current BIND 9
  releases. :gl:`#4296`

- The ``tcp-clients`` configuration option now also accepts value as percent of
  maximum allowed file descriptors.  The default has been changed to ``50%``.
  :gl:`#3958`

Bug Fixes
~~~~~~~~~

- The value of If-Modified-Since header in statistics channel was not checked
  for length leading to possible buffer overflow by an authorized user.  We
  would like to emphasize that statistics channel must be properly setup to
  allow access only from authorized users of the system. :gl:`#4124`

  This issue was reported independently by Eric Sesterhenn of X41 D-SEC and
  Cameron Whitehead.

- The value of Content-Length header in statistics channel was not
  bound checked and negative or large enough value could lead to
  overflow and assertion failure.  :gl:`#4125`

  This issue was reported by Eric Sesterhenn of X41 D-SEC.

- Address memory leaks due to not clearing OpenSSL error stack. :gl:`#4159`

  This issue was reported by Eric Sesterhenn of X41 D-SEC.

- Following the introduction of krb5-subdomain-self-rhs and
  ms-subdomain-self-rhs update rules, removal of nonexistent PTR
  and SRV records via UPDATE could fail. This has been fixed. :gl:`#4280`

- The value of :any:`stale-refresh-time` was set to zero after ``rndc flush``.
  This has been fixed. :gl:`#4278`

- BIND could consume more memory than it needs. That has been fixed by
  using specialised jemalloc memory arenas dedicated to sending buffers. It
  allowed us to optimize the process of returning memory pages back to
  the operating system. :gl:`#4038`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.

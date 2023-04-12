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

Notes for BIND 9.19.12
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- BIND now depends on ``liburcu``, Userspace RCU, for lock-free data
  structures. :gl:`#3934`

- The new ``delv +ns`` option activates name server mode, in which ``delv``
  sets up an internal recursive resolver and uses that, rather than an
  external server, to look up the requested query name and type. All messages
  sent and received during the resolution and validation process are logged.
  This can be used in place of ``dig +trace``: it more accurately
  reproduces the behavior of ``named`` when resolving a query.

  The log message ``resolver priming query complete`` was moved from the
  INFO log level to the DEBUG(1) log level, to prevent ``delv`` from
  emitting that message when setting up its internal resolver. :gl:`#3842`

- A new configuration option :any:`checkds` is introduced that when set to
  ``yes`` will detect :any:`parental-agents` automatically by resolving the
  parent NS records. These name servers will be used to check the DS RRset
  during a KSK rollover initiated by :any:`dnssec-policy`. :gl:`#3901`

Removed Features
~~~~~~~~~~~~~~~~

- The TKEY Mode 2 (Diffie-Hellman Exchanged Keying Mode) has been removed and
  using TKEY Mode 2 is now a fatal error.  Users are advised to switch to TKEY
  Mode 3 (GSS-API). :gl:`#3905`

- Zone type ``delegation-only``, and the ``delegation-only`` and
  ``root-delegation-only`` options, have been removed. Using them
  is a configuration error.

  These options were created to address the SiteFinder controversy, in
  which certain top-level domains redirected misspelled queries to other
  sites instead of returning NXDOMAIN responses. Since top-level domains are
  now DNSSEC signed, and DNSSEC validation is active by default, the
  options are no longer needed. :gl:`#3953`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Performance of DNSSEC validation in zones with many DNSKEY records
  has been improved. :gl:`#3981`

- When notify source-port would be configured for multiple destinations and
  zones, the first unresponsive server would block the local ip:port until the
  timeout making the following notifies to silently fail.  ``named`` now retries
  sending the notify over the TCP and logs any failures to send notify.
  :gl:`#4001` :gl:`#4002`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.

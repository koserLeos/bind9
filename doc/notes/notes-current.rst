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

Notes for BIND 9.19.25
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Added a new statistics variable ``recursive high-water`` that reports
  the maximum number of simultaneous recursive clients BIND has handled
  while running. :gl:`#4668`

- Added self update-policy rules for reverse names for IPv6 prefix
  lengths /48, /52, /56, /60 and /64 being common ISP prefix delegation
  size.  The rule names are 48-self through 64-self and behave similarly
  to 6to4-self.

  A typical use would be where you have an IPv6 prefix delegation pool
  and this would allow the clients to delegate reverse zones matching
  the prefix delegation.
  
  ::

     Prefix delegation pool: 2001:DB8::/32 with /48 delegations.

     zone  8.b.d.0.1.0.0.2.IP6.ARPA {
        ...
        update-policy {
           grant * 48-self . NS(10) DS(8);
           grant dhcp6-server-key subzone ANY;
        };
     };
  
  This allows secure delegations to be added to 8.b.d.0.1.0.0.2.IP6.ARPA
  at 0.0.0.0.8.b.d.0.1.0.0.2.IP6.ARPA through f.f.f.f.8.b.d.0.1.0.0.2.IP6.ARPA
  and for the DHCPv6 server to remove the delegation when the prefix delegation
  expires. :gl:`#4752`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- An RPZ response's SOA record TTL was set to 1 instead of the SOA TTL, if
  ``add-soa`` was used. This has been fixed. :gl:`#3323`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.

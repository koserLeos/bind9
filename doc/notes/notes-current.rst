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

Notes for BIND 9.16.49
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- A regression in cache-cleaning code enabled memory use to grow
  significantly more quickly than before, until the configured
  ``max-cache-size`` limit was reached. This has been fixed. :gl:`#4596`

- A use-after-free assertion might get triggered when the overmem cache
  cleaning triggers. :gl:`#4595`

  ISC would like to thank to Jinmei Tatuya from Infoblox for bringing
  this issue to our attention.

- The TTL-based cleaning of the cached DNS records was ineffective
  cleaning less records from the cache than adding over the time.
  This could result in a significant backlog of DNS records to be
  cleaned which could result in memory growth and ultimately triggering
  overmem LRU-based cleaning that's more aggressive, but also slower.
  :gl:`#4591`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.

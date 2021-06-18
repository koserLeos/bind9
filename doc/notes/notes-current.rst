.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.19
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

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

- Fixed a bug that caused the NSEC salt to be changed for KASP zones on
  every startup. :gl:`#2725`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`

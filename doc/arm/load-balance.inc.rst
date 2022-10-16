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
.. _load_balancing:

Load Balancing
--------------

Load balancing distributes client service requests across a group of server machines,
to reduce the overall load on any one server. There are many ways to achieve
load balancing:

   - Client-side method is to publish DNS records with support for load-balancing
     (such as :ref:`HTTPS <https_balance>` records, :ref:`MX <mx_balance>`
     records, :ref:`SRV <srv_balance>` records).
   - :ref:`Tailored-response method <tailored_responses>`, which takes
     advantage of built-in BIND 9 features such as GeoIPs within :any:`acl`
     blocks, :any:`view` blocks to send different clients tailored responses.
   - :ref:`Last resort <last_resort_balance>` option, :any:`rrset-order` and
     :any:`sortlist` features in BIND.

Each approach is described in the following sections and the limits to each are
identified. Generic limitations are described together in section
:ref:`balancing_caveats`.

.. note::
   This section deals with the use of DNS to balance end-user services.
   Load balancing of DNS service is not addressed by these techniques.

.. _https_balance:

Balancing Web Traffic (HTTPS Records)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TODO

.. _mx_balance:

Balancing Mail (MX Records)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sharing load between multiple mail servers is controlled by
:ref:`MX<mx_records>` resource records. These records contain a *preference*
value. One primary use of this value is to achieve resilience of the mail
service by designating a primary server and one or more secondary, or backup,
servers. The :ref:`MX<mx_records>` resource record of the primary server is
given a low *preference* value and the :ref:`MX<mx_records>` resource record of
the secondary server(s) is given higher *preference* values. *preference* can
therefore be regarded more like a *cost*; the lowest-cost server is preferred.

However, *preference* can also be used to achieve load balancing between two or
more mail servers by assigning them the same value; for example:

.. code-block:: none

   ; zone file fragment
   @       MX      10 mail.example.com.
   @       MX      10 mail1.example.com.
   @       MX      10 mail2.example.com.
   ...
   mail    A       192.168.0.4
   mail1   A       192.168.0.5
   mail2   A       192.168.0.6

**mail**, **mail1** and **mail2** are all considered to have equal preference,
or cost. The authoritative name server delivers the MX records in the order
defined by the :any:`rrset-order` statement, and the receiving
SMTP software selects one based on its algorithm. In some cases the SMTP
selection algorithm may work against the definition of the RRset-order
statement.

To avoid problems if the receiving mail system does
reverse lookups as a spam check, define the PTR records for 192.168.0.4,
192.168.0.5, and 192.168.0.6 to mail.example.com.

.. note::
   In both the above cases, each mail server must be capable of handling and
   synchronizing the load for all the mailboxes served by the domain, This
   can be accomplished either using some appropriate back-end or by access
   to a common file system (NAS, NFS, etc.), or by defining all but one
   server to be a mail relay or forwarder.

.. _srv_balance:

Balancing Other Services (SRV Records)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :ref:`SRV<srv_rr>` resource record allows an application to **discover**
the server name or names (and optional port number) on which a service - SIP or
LDAP, for example - is provided. As such, it offers another approach to load
balancing. SRV RRs contain both *priority* and *weight* fields, allowing a fine
level of granular configuration as well as providing some level of failover.
However, the end application must be **SRV-aware** for this approach to work.
Application support for SRV is patchy at best - varying from very high in SIP
(VoIP) to non-existent (browsers).

.. _last_resort_balance:

Last Resort Option (A/AAAA records)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some services do not have service-specific record type or domain name, and rely
on A/AAAA records to map service name to addresses.
If the requirement is to load-share services without specialized resource record,
then defining multiple A/AAAA records with the same name and different IP
addresses, as in the example below, can be used as an **imperfect workaround**.
Please note this technique relies on quirks in client implementations and is
not reliable.

.. note::
   This is legacy method is still in use for HTTP traffic, but it is
   becoming obsolete as :ref:`HTTPS <https_balance>` resource record support in
   clients is rolled out.

This method is best illustrated on a simple zone file:

.. code-block:: none

   ; zone file fragment

   ftp  A   192.168.0.4
        A   192.168.0.5
        A   192.168.0.6
   ...
   www  A   192.168.0.7
        A   192.168.0.8

The authoritative name server delivers all the IP addresses from the zone file;
the first IP address in the returned list is defined according to the value
of the :any:`rrset-order` or :any:`sortlist` statements. The **ftp** and **www**
servers must all be exact (synchronized) replicas of each other in this scenario.

.. warning::
   Use this method only as last resort option.
   Resource record sets, by DNS protocol definition, can be reordered at any
   time. Intermediate resolvers might reorder records and ruin any
   load-balancing attempts. Similarly client side is allowed to reorder records
   at will.

.. _tailored_responses:

Balancing Services with Split-Horizon (GeoIP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All application-specific approaches listed above can be combined with BIND's
:any:`view` feature to create a split horizon (or GeoIP-aware) configuration.
Split horizon uses the client's source IP address to respond with a specific
set of records, thus balancing for geographic or even service
provider-specific traffic sources (please see :ref:`Example Split-Horizon
Configuration<split_dns>`).

.. _balancing_caveats:

Effectiveness of DNS Service Load Balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The previous sections have addressed some of the techniques that may be used
to balance service load using DNS functionality. However, the following points
should also be considered:

1. Data supplied from the authoritative name server will reflect both the
zone file content, such as multiple RRs, and any BIND 9 operational control
statements, such as :any:`rrset-order` and :any:`sortlist`.

2. When this data is cached by a resolver and subsequently supplied from its
cache, two consequences apply:

   a. The order in which multiple IPs appear **can change** within
      the resolver's cache; it is no longer controlled by the authoritative name
      server's policies. If data is supplied from a pathologically small number
      of caches, any balancing effect may become distorted.

   b. The resolver may be configured with its own policies using
      :any:`rrset-order` or the (relatively rare) :any:`sortlist`
      statement, which may distort the aims of the authoritative name server.

   c. Changes on the authoritative side might not take effect until :term:`TTL`
      expires.

3. To account for server load or availability data on the authoritative server
   must be modified using :ref:`dynamic_update`. For instance, certain
   transactions may generate very high CPU or resource loads, or certain servers
   in a set may simply be unavailable. For this type of control only a local load
   balancer - one which measures service response times, server loading, and
   potentially other metrics - must modify content of DNS zone, and the
   dynamically modified records should use sufficiently low :term:`TTL` values.

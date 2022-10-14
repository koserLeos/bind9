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
load balancing: one fairly primitive method is to use
:ref:`zone file<zone_file>` features (such as MX records, SRV
records, and multiple A records), but it is also possible to take advantage
of built-in BIND 9 features such as GeoIPs within :any:`acl` blocks, :any:`view`
blocks, and the :ref:`rrset-order<rrset_ordering>` statement. Each approach is described
in the following sections and the limits to each are identified.

.. note::
   This section deals with the use of DNS to balance end-user services.
   Load balancing of DNS service is not addressed by these techniques.

Balancing Mail
~~~~~~~~~~~~~~

Sharing load between multiple mail servers can be achieved in one of two ways.

	1. :ref:`MX<mx_records>` resource records contain a **preference** value. One primary use of this value is to achieve resilience of the mail service by designating a primary server and one or more secondary, or backup, servers. The :ref:`MX<mx_records>` resource record of the primary server is given a low **preference** value and the :ref:`MX<mx_records>` resource record of the secondary server(s) is given higher **preference** values. **preference** can therefore be regarded more like a cost; the lowest-cost server is preferred.

However, **preference** can also be used to achieve load balancing between two or more mail servers by assigning them the same value; for example:

		.. code-block:: c

			; zone file fragment
			IN  MX  10  mail.example.com.
			IN  MX  10  mail1.example.com.
			IN  MX  10  mail2.example.com.
			....
			mail  IN  A       192.168.0.4
			mail1 IN  A       192.168.0.5
			mail2 IN  A       192.168.0.6

		**mail**, **mail1** and **mail2** are all considered to have equal preference, or cost. The authoritative name server delivers the MX records in the order defined
		by the :ref:`rrset-order<rrset_ordering>` statement, and the receiving SMTP
		software selects one based on its algorithm. In some cases the SMTP selection
		algorithm may work against the definition of the RRset-order statement.

	2. Define multiple A records with the same mail server name:

		.. code-block:: c

			; zone file fragment
			IN  MX  10  mail.example.com.
			....
			mail    IN  A       192.168.0.4
			        IN  A       192.168.0.5
			        IN  A       192.168.0.6

		In this case, the load-balancing effect is under the control of BIND and the
		RRset-order statement. To avoid problems if the receiving mail system does
		reverse lookups as a spam check, define the PTR records for 192.168.0.4,
		192.168.0.5, and 192.168.0.6 to mail.example.com.

	.. note::
	   In both the above cases, each mail server must be capable of handling
	   and synchronizing the load for all the mailboxes served by the domain,
	   This can be accomplished either using some appropriate back-end or by access to a common file system
	   (NAS, NFS, etc.), or by defining all but one server to be a mail relay or forwarder.

Balancing Other Services
~~~~~~~~~~~~~~~~~~~~~~~~

If the requirement is to load-share FTP, web, or other services, then defining
multiple A records with the same name and different IP addresses, as in the
example below, is an effective solution.

	.. code-block:: c

		; zone file fragment

		ftp   	IN  A   192.168.0.4
			IN  A   192.168.0.5
			IN  A   192.168.0.6
		....
		www   	IN  A   192.168.0.7
			IN  A   192.168.0.8

	.. note::
	   While the above example shows IPv4 addresses using A RRs, the principle applies
	   equally to IPv6 addresses using AAAA RRs.

The authoritative name server delivers all the IP addresses from the zone file;
the first IP address in the returned list is defined according to the value
of the :ref:`rrset-order<rrset_ordering>` statement. The **ftp** and **www**
servers must all be exact (synchronized) replicas of each other in this scenario.
In summary, multiple RRs can be an extremely effective load-balancing tool
and can even provide powerful failover capabilities, depending on the application.

	.. note::
	   Since clients receive all of the addresses for a service, it becomes the client's
	   responsibility to choose one to use; some clients may not be able to do this.
	   Further, just because DNS has supplied multiple addresses it does not mean that
	   they all work. Clients may choose the address of a server that is currently
	   unavailable, meaning that the client itself needs to have some way to retry
	   using a different address from the set.

Balancing Using SRV
~~~~~~~~~~~~~~~~~~~

The :ref:`SRV<srv_rr>` resource record allows an application to **discover** the
server name or names (and optional port number) on which a service - SIP or LDAP, for example - is
provided. As such, it offers another approach to load balancing. SRV RRs contain
both *priority* and *weight* fields, allowing a fine level of granular
configuration as well as providing some level of failover. However, the end
application must be **SRV-aware** for this approach to work. Application
support for SRV is patchy at best - varying from very high in SIP (VoIP) to
non-existent (browsers).


Balancing Services with Split-Horizon (GeoIP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An alternative approach to load balancing may be provisioned using BIND's
:any:`view` block to create a split horizon (or GeoIP-aware) configuration.
Split horizon uses the client's source IP address to respond with a specific
service IP address, thus balancing for geographic or even service provider-specific
traffic sources (please see :ref:`Example Split-Horizon Configuration<split_dns>`).


Effectiveness of DNS Service Load Balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The previous sections have addressed some of the techniques that may be used
to balance service load using DNS functionality. However, the following points
should also be considered:

	1. Data supplied from the authoritative name server will reflect both the
	zone file content, such as multiple RRs, and any BIND 9 operational control
	statements, such as :ref:`rrset-order<rrset_ordering>`.

	2. When this data is cached by a resolver and subsequently supplied from its
	cache, two consequences apply:

		a. The order in which multiple IPs appear is essentially **frozen** within
		the resolver's cache; it is no longer controlled by the authoritative name
		server's policies. If data is supplied from a pathologically small number
		of caches, any balancing effect may become distorted.

		b. The resolver may be configured with its own policies using
		:ref:`rrset-order<rrset_ordering>` or the (relatively rare) :any:`sortlist`
		statement, which may distort the aims of the authoritative name server.

What DNS load balancing cannot do is to account for service loading or availability; for instance,
certain transactions may generate very high CPU or resource loads, or certain servers in a set may simply be unavailable (as already mentioned). For this
type of control only a local load balancer - one which measures service response
times, server loading, and potentially other metrics - will be effective.

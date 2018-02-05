#!/usr/bin/python
############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

############################################################################
# ans.py: See README.anspy for details.
############################################################################

from __future__ import print_function
import os
import sys
import signal
import socket
import select
import struct
import copy
import dns, dns.message, dns.query

from dns.rdatatype import *
from dns.rdataclass import *
from dns.rcode import *
# NOTE: this requires at least version 2.1.0 of the ClientSubnetOption module
from clientsubnetoption import ClientSubnetOption, FAMILY_IPV4, FAMILY_IPV6
from pprint import pprint

############################################################################
# Answer database; starts off empty and can be updated by using send.pl.
############################################################################
answer_db = { }

############################################################################
# Handle incoming requests over the control channel.
#
# See the above discussion of answer_db for input format details.
############################################################################
def ctl_channel(msg):
    for statement in msg.splitlines():
        try:
            key, data = statement.split('|')
        except:
            continue
        data = list(map(str.strip, data.split(',')))
        print('received: %s: %s' % (key, str(data)))
        if len(data) > 2:
            data.insert(1, None)
        answer_db[key] = data
    pprint (answer_db)

############################################################################
# Format an ECS option in a way that can be used as a lookup key in
# answer_db.
############################################################################
def ecs_to_str(name, ecs):
    if ecs.family == FAMILY_IPV4:
        addr = socket.inet_ntop(socket.AF_INET, struct.pack('!L', ecs.ip))
        return ('%s/%s/%d' % (name, addr, ecs.mask))
    elif ecs.family == FAMILY_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6,
                struct.pack('!QQ', ecs.ip >> 64, ecs.ip & (2 ** 64 - 1)))
        return ('%s/%s/%d' % (name, addr, ecs.mask))
    return None

############################################################################
# Respond to a DNS query.
#
# - If the QNAME and ECS option in the query match a key in answer_db, then
#   we return the answer specified in answer_db.
# - Otherwise, there are default answers that can be returned for QTYPEs
#   A, AAAA, and TXT (XXX: this list should be updated)
# - Certain QNAME patterns trigger specific response behaviors:
#   + If QNAME is of the form x.drop.y.z (where x, y, and z are arbitrary
#     labels), drop the query and do not respond
#   + If QNAME is of the form x.noecs.y.z (where x, y, and z are arbitrary
#     labels), respond to the query with no ECS option.
#   + If QNAME is of the form x.refuse.y.z (where x, y, and z are arbitrary
#     labels), respond to the query with REFUSED iff. an ECS option was
#     included in the query.
#   + If QNAME is of the form x.nxdomain.y.z (where x, y, and z are arbitrary
#     labels), respond to the query with NXDOMAIN
#   + If QNAME is of the form x.short-ttl.y.z (where x, y, and z are arbitrary
#     labels), respond to the query with TTL=10
#   + If QNAME is of the form x.cname.y.z (where x, y, and z are arbitrary
#     labels), respond to the query with a CNAME chain pointing to x.y.z
#   + If QNAME is of the form x.y.6only.z, only AAAA records are added to
#     the additonal section for the name server.
#   + If QNAME is of the form x.y.4only.z, only A records are added to
#     the additonal section for the name server.
############################################################################
def create_response(msg):
    ttl = 86400
    custom_scope = None
    source = 0
    chain = True
    only4 = False
    only6 = False
    m = dns.message.from_wire(msg)
    qname = m.question[0].name.to_text()
    labels = qname.lower().split('.')
    labels2 = labels
    domain = '.'.join(labels)
    if len(labels) >= 3:
        domain = '.'.join(labels[-3:])
    rrtype = m.question[0].rdtype
    typename = dns.rdatatype.to_text(rrtype)
    print ('query: ' + qname + '/' + typename)
    print ('domain?: ' + domain)
    query_ecs = None
    for option in m.options:
        print (option)
        if isinstance(option, ClientSubnetOption):
            key = ecs_to_str(qname, option)
            source = option.mask
            print ('ECS: %s' % key)
            print ('CS F:%d ADDR:%x SOURCE:%d SCOPE:%d' %
                    (option.family, option.ip, option.mask, option.scope))
            query_ecs = option

    # if the query has "cname" as its third label from the right,
    # send a CNAME chain
    cname = None
    if len(labels) >= 4 and (labels[-4].lower() == 'cname' or labels[-4].lower() == 'cname2'):
        if labels[-4].lower() == 'cname2':
            chain = False
            cname = 'outside.whitelist.'
            if source == 14:
                custom_scope = 14
            elif source == 13:
                custom_scope = 15
        else:
            labels2 = copy.copy(labels)
            labels2.pop(-4)
            cname = '.'.join(labels2)

    # if the query has "4only" as its second label from the right,
    # don't send A records in the additional section
    if len(labels) >= 3 and labels[-3].lower() == '4only':
        only4 = True

    # if the query has "6only" as its second label from the right,
    # don't send A records in the additional section
    if len(labels) >= 3 and labels[-3].lower() == '6only':
        only6 = True

    # if the query has "drop" as its third label from the right,
    # don't send a response
    if len(labels) >= 4 and labels[-4].lower() == 'drop':
        return

    # if the query has "noecs" as its third label from the right,
    # send a response, but omit the ECS option
    if len(labels) >= 4 and labels[-4].lower() == 'noecs':
        query_ecs = False

    # if the query has "refuse" as its third label from the right,
    # send a normal response if the query had no ECS option, but
    # REFUSED if it had one.
    refuse = False
    if len(labels) >= 4 and labels[-4].lower() == 'refuse' and query_ecs:
        refuse = True

    # if the query has "nxdomain" as its third label from the right,
    # send an NXDOMAIN response.
    nxdomain = False
    if len(labels) >= 4 and labels[-4].lower() == 'nxdomain':
        nxdomain = True

    # if the query has "short-ttl" as its third label from the right,
    # send a response with TTL=10.
    if (len(labels) >= 4 and labels[-4].lower() == 'short-ttl') or (len(labels2) >= 4 and labels2[-4].lower() == 'short-ttl'):
        ttl = 10
        if query_ecs:
            if query_ecs.family is FAMILY_IPV4:
                custom_scope = 16
            else:
                custom_scope = 48

    # if the query has "scope20" as its third label from the right, send
    # a response with scope=20.
    if (len(labels) >= 4 and labels[-4].lower() == 'scope20') or (len(labels2) >= 4 and labels2[-4].lower() == 'scope20'):
        if query_ecs:
            custom_scope = 20

    r = dns.message.make_response(m)

    # Some default answers to use if QNAME and ECS didn't match
    # anything in answer_db
    additional = None
    if typename == 'A':
        answer = '10.53.0.8'
    elif typename == 'AAAA':
        answer = 'fd92:7065:b8e:ffff::8'
    elif typename == 'TXT':
        answer = 'Some\ text\ here'
    elif typename == 'NS':
        domain = qname
        answer = ('ns1.%s' % domain)
        answer2 = ('ns2.%s' % domain)
        answer3 = ('ns3.%s' % domain)
        additionalA = '10.53.0.8'
        additionalAAAA = 'fd92:7065:b8e:ffff::8'
    else:
        answer = None
    cso = None

    if query_ecs:
        cso = query_ecs
        answer_rec = answer_db.get(key)
        if answer_rec:
            answer = answer_rec[0]
            # use the IP and source prefix length from the query,
            # just update the scope. (XXX: currently there is no
            # way to construct an ECS option from address/source/scope;
            # the address and source fields in answer_db are unused.)
            if answer_rec[1] is None:
                print ('send scope: %s' % answer_rec[4])
                cso.scope = int(answer_rec[4])
            else:
                data = answer_rec[1]
                print ('send option data: "%s"' % answer_rec[1])
                cso = dns.edns.GenericOption(8, bytearray.fromhex(data))
        elif custom_scope is not None:
                cso.scope = custom_scope

    if refuse:
        r.set_rcode(dns.rcode.from_text('REFUSED'))
        answer = None
    elif cname:
        r.answer.append(dns.rrset.from_text(qname, 3600, IN, CNAME, cname))
        qname = cname

    if nxdomain:
        if not cname:
            r.set_rcode(dns.rcode.from_text('NXDOMAIN'))
        r.authority.append(dns.rrset.from_text(domain, 3600, IN, SOA, '. . 2015082610 7200 3600 1209600 3600'))
        answer = None

    if answer and chain:
        print('send answer: %s' % answer)
        r.answer.append(dns.rrset.from_text(qname, ttl, IN, rrtype, answer))
        if typename == 'NS':
            r.answer.append(dns.rrset.from_text(qname, 86400, IN, rrtype, answer2))
            r.answer.append(dns.rrset.from_text(qname, 86400, IN, rrtype, answer3))
            print('with additional section: %s' % additionalA)
            if not only6:
                r.additional.append(dns.rrset.from_text(('ns1.%s' % domain), 86400, IN, A, additionalA))
                r.additional.append(dns.rrset.from_text(('ns2.%s' % domain), 86400, IN, A, additionalA))
                r.additional.append(dns.rrset.from_text(('ns3.%s' % domain), 86400, IN, A, additionalA))
            if not only4:
                r.additional.append(dns.rrset.from_text(('ns1.%s' % domain), 86400, IN, AAAA, additionalAAAA))
                r.additional.append(dns.rrset.from_text(('ns2.%s' % domain), 86400, IN, AAAA, additionalAAAA))
                r.additional.append(dns.rrset.from_text(('ns3.%s' % domain), 86400, IN, AAAA, additionalAAAA))
    elif chain:
        r.authority.append(dns.rrset.from_text(domain, 3600, IN, SOA, '. . 2015082610 7200 3600 1209600 3600'))

    r.flags |= dns.flags.AA

    r.use_edns(options=[cso] if cso else None)
    return r.to_wire()

def sigterm(signum, frame):
    print ("Shutting down now...")
    os.remove('ans.pid')
    running = 0
    sys.exit(0)

############################################################################
# Main
#
# Set up responder and control channel, open the pid file, and start
# the main loop, listening for queries on the query channel or commands
# on the control channel and acting on them.
############################################################################
ip4 = "10.53.0.8"
ip6 = "fd92:7065:b8e:ffff::8"
sock = 5300

try:
    query4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        query4_socket.bind((ip4, sock))
    except socket.error as msg:
        query4_socket.close()
        query4_socket = None
except socket.error as msg:
    query4_socket = None

if query4_socket is None:
    print('unable to create %s port %d' % (ip4, sock))
    sys.exit(1)

try:
    query6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        query6_socket.bind((ip6, sock))
    except socket.error as msg:
        query6_socket.close()
        query6_socket = None
except socket.error as msg:
    query6_socket = None

try:
    ctrl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ctrl_socket.bind((ip4, sock + 1))
        ctrl_socket.listen(5)
    except socket.error as msg:
        ctrl_socket.close()
        ctrl_socket = None
except socket.error as msg:
    ctrl_socket = None

if ctrl_socket is None:
    print('unable to create %s port %d' % (ip4, sock + 1))
    sys.exit(1)

signal.signal(signal.SIGTERM, sigterm)

f = open('ans.pid', 'w')
pid = os.getpid()
print (pid, file=f)
f.close()

running = 1

print ("Listening on %s port %d" % (ip4, sock))
if not query6_socket is None:
     print ("Listening on %s port %d" % (ip6, sock))
print ("Control channel on %s port %d" % (ip4, sock + 1))
print ("Ctrl-c to quit")

if query6_socket is None:
    input = [query4_socket, ctrl_socket]
else:
    input = [query4_socket, query6_socket, ctrl_socket]

while running:
    try:
        inputready, outputready, exceptready = select.select(input, [], [])
    except select.error as e:
        break
    except socket.error as e:
        break
    except KeyboardInterrupt:
        break

    for s in inputready:
        if s == ctrl_socket:
            # Handle control channel input
            conn, addr = s.accept()
            print ("Control channel connected")
            while True:
                msg = conn.recv(65535)
                if not msg:
                    break
# python2 returns 'str', python3 returns 'byte', however 'str' and 'byte'
# are aliases in python2 but not in python 3 hence the 'is not'.
                if type(msg) is not str:
                    msg = msg.decode('ascii')
                ctl_channel(msg)
            conn.close()
        if s == query4_socket or s == query6_socket:
            print ("Query received on %s" %
                    (ip4 if s == query4_socket else ip6))
            # Handle incoming queries
            msg = s.recvfrom(65535)
            rsp = create_response(msg[0])
            if rsp:
                s.sendto(rsp, msg[1])
    if not running:
        break

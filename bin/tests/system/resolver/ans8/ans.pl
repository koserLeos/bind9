#!/usr/bin/perl
#
# Copyright (C) 2017, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use IO::File;
use IO::Socket;
use Data::Dumper;
use Net::DNS;
use Net::DNS::Packet;
use strict;

# Ignore SIGPIPE so we won't fail if peer closes a TCP socket early
local $SIG{PIPE} = 'IGNORE';

# Flush logged output after every line
local $| = 1;

my $server_addr = "10.53.0.8";
my $udpsock = IO::Socket::INET->new(LocalAddr => "$server_addr",
   LocalPort => 5300, Proto => "udp", Reuse => 1) or die "$!";
my $tcpsock = IO::Socket::INET->new(LocalAddr => "$server_addr",
   LocalPort => 5300, Proto => "tcp", Listen => 5, Reuse => 1) or die "$!";

print "listening on $server_addr:5300.\n";

my $pidf = new IO::File "ans.pid", "w" or die "cannot open pid file: $!";
print $pidf "$$\n" or die "cannot write pid file: $!";
$pidf->close or die "cannot close pid file: $!";;
sub rmpid { unlink "ans.pid"; exit 1; };

$SIG{INT} = \&rmpid;
$SIG{TERM} = \&rmpid;

sub handleUDP {
	my ($buf) = @_;
	my $request;

	if ($Net::DNS::VERSION > 0.68) {
		$request = new Net::DNS::Packet(\$buf, 0);
		$@ and die $@;
	} else {
		my $err;
		($request, $err) = new Net::DNS::Packet(\$buf, 0);
		$err and die $err;
	}

	my @questions = $request->question;
	my $qname = $questions[0]->qname;
	my $qtype = $questions[0]->qtype;
	my $qclass = $questions[0]->qclass;
	my $id = $request->header->id;

	my $packet = new Net::DNS::Packet();

	$packet->header->qr(1);
	$packet->header->aa(0);
	$packet->header->id($id);

	if ($qname eq "truncated.no-questions") {
		$packet->header->tc(1);
	} else {
		$packet->header->tc(0);
	}

	return $packet->data;
}

sub handleTCP {
	my ($buf) = @_;
	my $request;

	if ($Net::DNS::VERSION > 0.68) {
		$request = new Net::DNS::Packet(\$buf, 0);
		$@ and die $@;
	} else {
		my $err;
		($request, $err) = new Net::DNS::Packet(\$buf, 0);
		$err and die $err;
	}

	my @questions = $request->question;
	my $qname = $questions[0]->qname;
	my $qtype = $questions[0]->qtype;
	my $qclass = $questions[0]->qclass;
	my $id = $request->header->id;

	my @results = ();
	my $packet = new Net::DNS::Packet($qname, $qtype, $qclass);

	$packet->header->qr(1);
	$packet->header->aa(1);
	$packet->header->id($id);

	$packet->push("answer", new Net::DNS::RR("$qname 300 A 1.2.3.4"));
	push(@results, $packet->data);

	return \@results;
}

# Main
my $rin;
my $rout;
for (;;) {
	$rin = '';
	vec($rin, fileno($tcpsock), 1) = 1;
	vec($rin, fileno($udpsock), 1) = 1;

	select($rout = $rin, undef, undef, undef);

	if (vec($rout, fileno($udpsock), 1)) {
		printf "UDP request\n";
		my $buf;
		$udpsock->recv($buf, 512);
		my $result = handleUDP($buf);
		my $num_chars = $udpsock->send($result);
		print "  Sent $num_chars bytes via UDP\n";
	} elsif (vec($rout, fileno($tcpsock), 1)) {
		my $conn = $tcpsock->accept;
		my $buf;
		for (;;) {
			my $lenbuf;
			my $n = $conn->sysread($lenbuf, 2);
			last unless $n == 2;
			my $len = unpack("n", $lenbuf);
			$n = $conn->sysread($buf, $len);
			last unless $n == $len;
			print "TCP request\n";
			my $result = handleTCP($buf);
			foreach my $response (@$result) {
				$len = length($response);
				$n = $conn->syswrite(pack("n", $len), 2);
				$n = $conn->syswrite($response, $len);
				print "    Sent: $n chars via TCP\n";
			}
		}
		$conn->close;
	}
}

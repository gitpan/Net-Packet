#!/usr/bin/perl

# $Date: 2004/09/29 20:21:56 $
# $Revision: 1.1.1.1.2.2 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('m:M:i:a:d:v', \%opts);

die "Usage: arp-reply.pl  -i dstIp -a isAtMac [ -M srcMac ] [ -m dstMac ] ".
    "(or will broadcast) [ -d device ] [ -v ]\n"
   unless $opts{i} && $opts{a};

$Net::Packet::Debug = 3 if $opts{v};

$Net::Packet::Dev = $opts{d} if $opts{d};
$Net::Packet::Mac = $opts{M} if $opts{M};

use Net::Packet::Simple;
my $frame = Net::Packet::Simple->arpReply(
   srcMac => $Net::Packet::Mac,
   ip     => Net::Packet::getHostIpv4Addr($opts{i}),
   isAt   => $opts{a},
   toMac  => $opts{m} ? $opts{m} : 'broadcast',
);

print "Sending:\n";
$frame->ethPrint;
$frame->arpPrint;

$frame->send;

#!/usr/bin/perl

# $Date: 2004/09/29 20:21:56 $
# $Revision: 1.1.1.1.2.2 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:d:v', \%opts);

die "Usage: icmp-mask.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

$Net::Packet::Debug = 3 if $opts{v};

$Net::Packet::Dev = $opts{d} if $opts{d};
$Net::Packet::Ip  = $opts{I} if $opts{I};

use Net::Packet::Frame;

use Net::Packet::IPv4 qw(/NETPKT_*/);
my $ip = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_ICMPv4,
   dst      => Net::Packet::getHostIpv4Addr($opts{i}),
);

use Net::Packet::ICMPv4 qw(/NETPKT_*/);
my $mask = Net::Packet::ICMPv4->new(
   type => NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST,
);

my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $mask);

$frame->send;

until ($Net::Packet::Timeout) {
   if ($Net::Packet::Dump->next && $frame->recv) {
      print "Reply:\n";
      $frame->reply->icmpPrint;
      last;
   }
}

#!/usr/bin/perl

# $Date: 2004/09/29 20:21:56 $
# $Revision: 1.1.1.1.2.2 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:i:I:v', \%opts);

die "Usage: chaos-query.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

$Net::Packet::Debug = 3 if $opts{v};

$Net::Packet::Dev = $opts{d} if $opts{d};
$Net::Packet::Ip  = $opts{I} if $opts{I};

use Net::Packet::Frame;
use Net::Packet::IPv4 qw(/NETPKT_*/);
my $l3 = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_UDP,
   src      => $Net::Packet::Ip,
   dst      => Net::Packet::getHostIpv4Addr($opts{i}),
);

my $l4 = Net::Packet::UDP->new(dst => 53);

my $l7 = Net::Packet::Layer7->new(
   data => "\x33\xde\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65".
           "\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
);

my $frame = Net::Packet::Frame->new(l3 => $l3, l4 => $l4, l7 => $l7);

print "Request:\n";
$frame->ipPrint;
$frame->udpPrint;
$frame->l7Print;
$frame->send;

until ($Net::Packet::Timeout) {
   if ($Net::Packet::Dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->udpPrint;
      $frame->reply->l7Print;
      last;
   }
}

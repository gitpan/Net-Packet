#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:i:I:v', \%opts);

die "Usage: chaos-query.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

$Dev = $opts{d} if $opts{d};
$Ip  = $opts{I} if $opts{I};

use Net::Packet::IPv4 qw(/NETPKT_*/);
my $l3 = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_UDP,
   dst      => $opts{i},
);

require Net::Packet::UDP;
my $l4 = Net::Packet::UDP->new(dst => 53);

require Net::Packet::Layer7;
my $l7 = Net::Packet::Layer7->new(
   data => "\x33\xde\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65".
           "\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
);

require Net::Packet::Frame;
my $frame = Net::Packet::Frame->new(l3 => $l3, l4 => $l4, l7 => $l7);

print "Request:\n";
$frame->ipPrint;
$frame->udpPrint;
$frame->l7Print;
$frame->send;

until ($Timeout) {
   if ($Dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->udpPrint;
      $frame->reply->l7Print;
      last;
   }
}

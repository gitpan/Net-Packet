#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:d:v', \%opts);

die "Usage: icmp-echo.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

$Dev = $opts{d} if $opts{d};
$Ip  = $opts{I} if $opts{I};

use Net::Packet::IPv4 qw(/NETPKT_*/);
my $ip = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_ICMPv4,
   dst      => $opts{i},
);

use Net::Packet::ICMPv4 qw(/NETPKT_*/);
my $echo = Net::Packet::ICMPv4->new(
   type => NETPKT_ICMPv4_TYPE_ECHO_REQUEST,
   data => "test",
);

require Net::Packet::Frame;
my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $echo);

$frame->send;

until ($Timeout) {
   if ($Dump->next && $frame->recv) {
      print "Reply:\n";
      $frame->reply->ipPrint;
      $frame->reply->icmpPrint;
      last;
   }
}

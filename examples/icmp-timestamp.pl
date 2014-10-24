#!/usr/bin/perl

#
# $Id: icmp-timestamp.pl,v 1.2.2.7 2005/05/22 19:09:31 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:d:v', \%opts);

die "Usage: icmp-timestamp.pl -i dstIp [-I srcIp] [-d device] [-v]\n"
   unless $opts{i};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I};
$Env->debug(3)      if $opts{v};

my $ip = Net::Packet::IPv4->new(
   protocol => NP_IPv4_PROTOCOL_ICMPv4,
   dst      => $opts{i},
);

my $timestamp = Net::Packet::ICMPv4->new(
   type               => NP_ICMPv4_TYPE_TIMESTAMP_REQUEST,
   originateTimestamp => 0xffffffff,
   receiveTimestamp   => 0,
   transmitTimestamp  => 0,
   data               => "test",
);

my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $timestamp);

$frame->send;

until ($Env->dump->timeout) {
   if ($frame->recv) {
      print "Reply:\n";
      print $frame->reply->l3->print, "\n";
      print $frame->reply->l4->print, "\n";
      last;
   }
}

#!/usr/bin/perl

# $Date: 2004/09/29 20:21:56 $
# $Revision: 1.1.1.1.2.2 $

use strict;
use warnings;

use Net::Packet;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:v', \%opts);

die "Usage: send-syn.pl -i dstIp -p dstPort [ -I srcIp ] [ -d device ] ".
    "[ -v ]\n"
   unless $opts{i} && $opts{p};

$Net::Packet::Debug = 3 if $opts{v};

# Overwrite autochosen one
$Net::Packet::Dev = $opts{d} if $opts{d};
$Net::Packet::Ip  = $opts{I} if $opts{I};

use Net::Packet::Simple;
my $frame = Net::Packet::Simple->tcpSyn(
   ipSrc   => $Net::Packet::Ip,
   ipDst   => Net::Packet::getHostIpv4Addr($opts{i}),
   dstPort => $opts{p},
);

print "Request:\n";
$frame->ipPrint;
$frame->tcpPrint;
$frame->send;

until ($Net::Packet::Timeout) {
   if ($Net::Packet::Dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->tcpPrint;
      last;
   }
}

#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:v', \%opts);

die "Usage: send-syn.pl -i dstIp -p dstPort [ -I srcIp ] [ -d device ] ".
    "[ -v ]\n"
   unless $opts{i} && $opts{p};

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

# Overwrite autochosen one
$Dev = $opts{d} if $opts{d};
$Ip  = $opts{I} if $opts{I};

require Net::Packet::Simple;
my $frame = Net::Packet::Simple->tcpSyn(
   ipSrc   => $Ip,
   ipDst   => $opts{i},
   dstPort => $opts{p},
);

print "Request:\n";
$frame->ipPrint;
$frame->tcpPrint;
$frame->send;

until ($Timeout) {
   if ($Dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->tcpPrint;
      last;
   }
}

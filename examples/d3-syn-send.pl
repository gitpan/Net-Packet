#!/usr/bin/perl

#
# $Id: d3-syn-send.pl,v 1.1.2.1 2006/03/15 15:09:43 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:v', \%opts);

die "Usage: d3-send-syn.pl -i dstIp -p dstPort [-I srcIp] [-d device] [-v]\n"
   unless $opts{i} && $opts{p};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I};
$Env->debug(3)      if $opts{v};

my $d4 = Net::Packet::DescL3->new(
   target => $opts{i},
);

my $frame = Net::Packet::Frame->new(
   l3 => Net::Packet::IPv4->new(
      dst => $opts{i},
   ),
   l4 => Net::Packet::TCP->new(
      dst => $opts{p},
   ),
);

$frame->send;

until ($Env->dump->timeout) {
   if ($frame->recv) {
      print "Reply:\n";
      print $frame->reply->l3->print, "\n";
      print $frame->reply->l4->print, "\n";
      last;
   }
}

#!/usr/bin/perl

# $Date: 2005/01/23 15:44:17 $
# $Revision: 1.2.2.6 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:d:m:p:v', \%opts);

die "Usage: ip6-syn-send -i ipDst -m macDst -p dstPort [-M srcMac] ".
    "[-d dev] [-v]\n"
   unless $opts{i} && $opts{m} && $opts{p};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->mac($opts{M}) if $opts{M};
$Env->debug(3)      if $opts{v};

my $eth = Net::Packet::ETH->new(
   type => NP_ETH_TYPE_IPv6,
   dst  => $opts{m},
);

my $tcp = Net::Packet::TCP->new(
   dst     => $opts{p},
   options => "\x02\x04\x05\xa0",
);

my $ip6 = Net::Packet::IPv6->new(
   dst => $opts{i},
);

my $l7 = Net::Packet::Layer7->new(
   data => "test",
);

my $frame = Net::Packet::Frame->new(
   l2 => $eth,
   l3 => $ip6,
   l4 => $tcp,
   l7 => $l7,
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

#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:v', \%opts);

die "Usage: d4-send-syn.pl -i dstIp -p dstPort [-I srcIp] [-d device] [-v]\n"
   unless $opts{i} && $opts{p};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I};
$Env->debug(3)      if $opts{v};

my $d4 = Net::Packet::DescL4->new(
   target   => $opts{i},
   protocol => NP_DESC_IPPROTO_TCP,
   family   => NP_LAYER_IPv4,
);

my $frame = Net::Packet::Frame->new(
   l4 => Net::Packet::TCP->new(
      dst => $opts{p},
   ),
);

$frame->send;

until ($Env->dump->timeout) {
   if ($frame->recv) {
      print "Reply:\n";
      print $frame->reply->l4->print, "\n";
      last;
   }
}

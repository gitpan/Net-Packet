#!/usr/bin/perl

# $Date: 2005/01/18 21:41:14 $
# $Revision: 1.2.2.4 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('m:M:i:a:d:v', \%opts);

die "Usage: arp-reply.pl -i dstIp -a isAtMac [-M srcMac] [-m dstMac] ".
    "(or will broadcast) [-d device] [-v]\n"
   unless $opts{i} && $opts{a};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->mac($opts{M}) if $opts{M};
$Env->debug(3)      if $opts{v};

my $eth = Net::Packet::ETH->new(
   type => NP_ETH_TYPE_ARP,
);
$eth->dst($opts{m}) if $opts{m};

my $arp = Net::Packet::ARP->new(
   opCode => NP_ARP_OPCODE_REPLY,
   src    => $opts{a},
   srcIp  => $opts{i},
   dstIp  => $opts{i},
);
$arp->dst($opts{m}) if $opts{m};

my $frame = Net::Packet::Frame->new(l2 => $eth, l3 => $arp);

print "Sending:\n";
print $frame->l2->print, "\n";
print $frame->l3->print, "\n";

$frame->send;

#!/usr/bin/perl

# $Date: 2005/01/23 15:44:17 $
# $Revision: 1.2.2.7 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:M:d:vt', \%opts);

die "Usage: arp-request.pl -i dstIp [-I srcIp] [-M srcMac] [-d device] ".
    "[-v] [-t timeout]\n"
   unless $opts{i};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I};
$Env->mac($opts{M}) if $opts{M};
$Env->debug(3)      if $opts{v};

my $eth = Net::Packet::ETH->new(
   type => NP_ETH_TYPE_ARP,
);

my $arp = Net::Packet::ARP->new(
   opCode => NP_ARP_OPCODE_REQUEST,
   dstIp  => $opts{i},
);

my $frame = Net::Packet::Frame->new(l2 => $eth, l3 => $arp);

my $dump = Net::Packet::Dump->new(
   filter        => $frame->getFilter,
   timeoutOnNext => $opts{t} ? $opts{t} : 3,
);

print "Request:\n";
print $frame->l2->print, "\n";
print $frame->l3->print, "\n";
print "padding: ", unpack('H*', $frame->padding), "\n";
$frame->send;

until ($dump->timeout) {
   if ($frame->recv) {
      print "\nReply:\n";
      print $frame->reply->l2->print, "\n";
      print $frame->reply->l3->print, "\n";
      print "padding: ", unpack('H*', $frame->reply->padding), "\n";
      print "\n", $frame->reply->l3->srcIp, " is-at ", $frame->reply->l3->src,
            "\n";
      last;
   }
}

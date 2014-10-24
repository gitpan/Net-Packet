#!/usr/bin/perl

# $Date: 2005/01/23 15:44:17 $
# $Revision: 1.2.2.6 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:p:d:I:v', \%opts);

die "Usage: udp-send.pl -i dstIp -p dstPort [-d device] [-I srcIp] [-v]\n"
   unless $opts{i} && $opts{p};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I};
$Env->debug(3)      if $opts{v};

my $ip = Net::Packet::IPv4->new(
   protocol => NP_IPv4_PROTOCOL_UDP,
   dst      => $opts{i},
);

my $udp = Net::Packet::UDP->new(
   dst => $opts{p},
);

my $frame = Net::Packet::Frame->new(
   l3 => $ip,
   l4 => $udp,
);

$frame->send;

until ($Env->dump->timeout) {
   if ($frame->recv) {
      print "Reply:\n";
      print $frame->reply->l3->print, "\n";
      print $frame->reply->l4->print, "\n";
      if ($frame->reply->l4->error) {
         print "Reply ICMP error:\n";
         print($frame->reply->l4->error->l3->print, "\n")
            if $frame->reply->l4->error->l3;
         print($frame->reply->l4->error->l4->print, "\n")
            if $frame->reply->l4->error->l4;
      }
      last;
   }
}

#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.2.2 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:p:d:I:v', \%opts);

die "Usage: udp-send.pl -i dstIp -p dstPort [-d device] [-I srcIp] [-v]\n"
   unless $opts{i} && $opts{p};

use Net::Packet qw(:globals);

$Debug = 3        if $opts{v};
$Dev   = $opts{d} if $opts{d};
$Ip    = $opts{I} if $opts{I};

use Net::Packet::IPv4 qw(/NETPKT_*/);
my $ip = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_UDP,
   dst      => $opts{i},
);

require Net::Packet::UDP;
my $udp = Net::Packet::UDP->new(
   dst => $opts{p},
);

require Net::Packet::Frame;
my $frame = Net::Packet::Frame->new(
   l3 => $ip,
   l4 => $udp,
);

$frame->send;

until ($Timeout) {
   if ($Dump->next && $frame->recv) {
      print "Reply:\n";
      $frame->reply->ipPrint;
      $frame->reply->l4Print;
      if ($frame->reply->l4->error) {
         print "Reply ICMP error:\n";
         $frame->reply->l4->error->ipPrint if $frame->reply->l4->error->l3;
         $frame->reply->l4->error->l4Print if $frame->reply->l4->error->l4;
      }
      last;
   }
}

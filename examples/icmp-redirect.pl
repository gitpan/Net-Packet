#!/usr/bin/perl

# $Date: 2004/10/03 18:33:10 $
# $Revision: 1.1.2.1 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:d:I:g:v', \%opts);

die "Usage: icmp-redirect.pl -i dstIp  -g gateway [-d device] [-I srcIp] [-v]\n"
   unless $opts{i} && $opts{g};

use Net::Packet qw(:globals);

$Debug = 3        if $opts{v};
$Dev   = $opts{d} if $opts{d};
$Ip    = $opts{I} if $opts{I};

use Net::Packet::IPv4 qw(/NETPKT_*/);
my $ip = Net::Packet::IPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_ICMPv4,
   dst      => $opts{i},
);

my $iperror = Net::Packet::IPv4->new(dst => "192.168.0.1");

require Net::Packet::TCP;
my $tcperror = Net::Packet::TCP->new(dst => 6666);

require Net::Packet::Frame;
my $error = Net::Packet::Frame->new(l3 => $iperror, l4 => $tcperror);

use Net::Packet::ICMPv4 qw(/NETPKT_*/);
my $icmp = Net::Packet::ICMPv4->new(
   type    => NETPKT_ICMPv4_TYPE_REDIRECT,
   code    => NETPKT_ICMPv4_CODE_FOR_HOST,
   gateway => $opts{g},
   error   => $error,
);

require Net::Packet::Frame;
my $frame = Net::Packet::Frame->new(
   l3 => $ip,
   l4 => $icmp,
);

$frame->send;

until ($Timeout) {
   if ($Dump->next && $frame->recv) {
      $frame->reply->ipPrint;
      $frame->reply->l4Print;
      if ($frame->reply->l4->error) {
         $frame->reply->l4->error->ipPrint if $frame->reply->l4->error->l3;
         $frame->reply->l4->error->l4Print if $frame->reply->l4->error->l4;
      }
      last;
   }
}

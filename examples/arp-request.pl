#!/usr/bin/perl

# $Date: 2004/09/29 20:21:56 $
# $Revision: 1.1.1.1.2.2 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:M:d:vt', \%opts);

die "Usage: arp-request.pl -i dstIp [ -I srcIp ] [ -M srcMac ] [ -d device ] ".
    "[ -v ] [ -t timeout ]\n"
   unless $opts{i};

$Net::Packet::Debug = 3 if $opts{v};

$Net::Packet::Dev = $opts{d} if $opts{d};
$Net::Packet::Ip  = $opts{I} if $opts{I};
$Net::Packet::Mac = $opts{M} if $opts{M};

use Net::Packet::Simple;
my $frame = Net::Packet::Simple->arpRequest(
   whoHas  => Net::Packet::getHostIpv4Addr($opts{i}),
   tell    => $Net::Packet::Ip,
   tellMac => $Net::Packet::Mac,
   toMac   => 'broadcast',
);

use Net::Packet::Dump;
my $dump = Net::Packet::Dump->new(
   filter        => $frame->getFilter,
   timeoutOnNext => $opts{t} ? $opts{t} : 3,
);

print "Request:\n";
$frame->ethPrint;
$frame->arpPrint;
$frame->send;

until ($Net::Packet::Timeout) {
   if ($dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ethPrint;
      $frame->reply->arpPrint;
      print "\n", $frame->reply->arpSrcIp, " is-at ", $frame->reply->arpSrc,
            "\n";
      last;
   }
}

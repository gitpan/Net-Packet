#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:M:d:vt', \%opts);

die "Usage: arp-request.pl -i dstIp [ -I srcIp ] [ -M srcMac ] [ -d device ] ".
    "[ -v ] [ -t timeout ]\n"
   unless $opts{i};

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

$Dev = $opts{d} if $opts{d};
$Ip  = $opts{I} if $opts{I};
$Mac = $opts{M} if $opts{M};

require Net::Packet::Simple;
my $frame = Net::Packet::Simple->arpRequest(
   whoHas  => $opts{i},
   tell    => $Ip,
   tellMac => $Mac,
   toMac   => 'broadcast',
);

require Net::Packet::Dump;
my $dump = Net::Packet::Dump->new(
   filter        => $frame->getFilter,
   timeoutOnNext => $opts{t} ? $opts{t} : 3,
);

print "Request:\n";
$frame->ethPrint;
$frame->arpPrint;
$frame->send;

until ($Timeout) {
   if ($dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ethPrint;
      $frame->reply->arpPrint;
      print "\n", $frame->reply->arpSrcIp, " is-at ", $frame->reply->arpSrc,
            "\n";
      last;
   }
}

#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('m:M:i:a:d:v', \%opts);

die "Usage: arp-reply.pl  -i dstIp -a isAtMac [ -M srcMac ] [ -m dstMac ] ".
    "(or will broadcast) [ -d device ] [ -v ]\n"
   unless $opts{i} && $opts{a};

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

$Dev = $opts{d} if $opts{d};
$Mac = $opts{M} if $opts{M};

require Net::Packet::Simple;
my $frame = Net::Packet::Simple->arpReply(
   srcMac => $Mac,
   ip     => $opts{i},
   isAt   => $opts{a},
   toMac  => $opts{m} ? $opts{m} : 'broadcast',
);

print "Sending:\n";
$frame->ethPrint;
$frame->arpPrint;

$frame->send;

#!/usr/bin/perl

# $Date: 2004/09/29 17:46:23 $
# $Revision: 1.1.1.1.2.1 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:f:v347khp', \%opts);

die "Usage: sniffer.pl [ -f filter ] [ -d device ] [ -v ] [ -3 ] [ -4 ] ".
    "[ -7 ] [ -p ]\n".
    " -d:   device to sniff on\n".
    " -f:   filter to use\n".
    " -3:   print layer 3\n".
    " -4:   print layer 4\n".
    " -7:   print layer 7\n".
    " -v:   be verbose\n".
    " -k:   keep captured savefile\n".
    " -p:   use promiscuous mode\n".
    ""
   if $opts{h};

$Net::Packet::Debug   = 3        if     $opts{v};
$Net::Packet::Dev     = $opts{d} if     $opts{d};
$Net::Packet::Promisc = 1        if     $opts{p};
$opts{f}              = ""       unless $opts{f};

use Net::Packet::Dump;
use Net::Packet::Frame;

my $dump = Net::Packet::Dump->new(
   filter          => $opts{f},
   overwrite       => 1,
   unlinkOnDestroy => $opts{k} ? 0 : 1,
   noStore         => 1,
);

while (1) {
   if ($dump->next) {
      $dump->nextFrame->l3Print if ($opts{3} && $dump->nextFrame->l3);
      $dump->nextFrame->l4Print if ($opts{4} && $dump->nextFrame->l4);
      $dump->nextFrame->l7Print if ($opts{7} && $dump->nextFrame->l7);
   }
}

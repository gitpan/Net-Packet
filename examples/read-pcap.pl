#!/usr/bin/perl
#
# $Id: read-pcap.pl,v 1.2.2.2 2006/06/04 13:23:13 gomor Exp $
#
use strict;
use warnings;

use Getopt::Std;

my %opts;
getopts('f:F:', \%opts);

die "Usage: $0 -f file [-F filter]\n"
   unless $opts{f};

use Net::Packet;
$Env->noFrameAutoDesc(1);
$Env->noFrameAutoDump(1);

my $dump = Net::Packet::Dump->new(
   file          => $opts{f},
   filter        => $opts{F} || '',
   noStore       => 1,
   unlinkOnClean => 0,
);

$dump->start;
while ($_ = $dump->next) {
   print $_->l2->print, "\n" if $_->l2;
   print $_->l3->print, "\n" if $_->l3;
   print $_->l4->print, "\n" if $_->l4;
   print $_->l7->print, "\n" if $_->l7;
}
$dump->stop;
$dump->clean;

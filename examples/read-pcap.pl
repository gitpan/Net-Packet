#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;

my %opts;
getopts('f:F:', \%opts);

die "Usage: read-pcap.pl -f file [-F filter]\n"
   unless $opts{f};

use Net::Pkt;

my $dump = Net::Packet::Dump->new(
   unlinkOnDestroy => 0,
   file            => $opts{f},
   filter          => $opts{F} || "",
   callStart       => 0,
   noStore         => 1,
);

while ($_ = $dump->next) {
   print $_->l2->print, "\n" if $_->l2;
   print $_->l3->print, "\n" if $_->l3;
   print $_->l4->print, "\n" if $_->l4;
   print $_->l7->print, "\n" if $_->l7;
}

$dump->stop;

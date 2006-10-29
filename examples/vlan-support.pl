#!/usr/bin/perl
#
# $Id: vlan-support.pl,v 1.2.2.2 2006/06/04 13:23:13 gomor Exp $
#
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('f:', \%opts);

die("Usage: $0 -f pcapFile\n") unless $opts{f};

use Net::Packet;

$Env->debug(3);

print "VERSION: ", $Net::Packet::VERSION, "\n";

my $d = Net::Packet::Dump->new(
   unlinkOnClean => 0,
   file          => $opts{f},
);
$d->start;
$d->nextAll;
$d->stop;

for ($d->frames) {
   print $_->l2->print, "\n";
   print $_->l3->print, "\n";
   print $_->l4->print, "\n" if $_->l4;
   print $_->l7->print, "\n" if $_->l7;
}

exit(0);

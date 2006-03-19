#!/usr/bin/perl

#
# $Id: vlan-support.pl,v 1.1.2.2 2006/03/12 11:09:10 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('f:', \%opts);

die("Usage: $0 -f pcapFile\n") unless $opts{f};

use Net::Pkt;

$Env->debug(3);

print "VERSION: ", $Net::Packet::VERSION, "\n";

my $d = Net::Packet::Dump->new(
   unlinkOnDestroy => 0,
   file            => $opts{f},
   callStart       => 0,
);

$d->analyze;
for ($d->frames) {
   print $_->l2->print, "\n";
   print $_->l3->print, "\n";
   print $_->l4->print, "\n" if $_->l4;
   print $_->l7->print, "\n" if $_->l7;
}

exit(0);

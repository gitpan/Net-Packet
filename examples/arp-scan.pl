#!/usr/bin/perl

# $Date: 2004/10/03 18:32:30 $
# $Revision: 1.1.1.1.2.3 $

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:I:M:n:vt:kr:', \%opts);

die "Usage: arp-scan.pl [ -d device ] [ -I srcIp ] [ -M srcMac ] [ -v ] ".
    "[ -t timeout ] [ -k ] [ -r number ] -n C.SUB.NET\n"
   unless $opts{n};

die "Invalid C class: $opts{n}\n" unless $opts{n} =~ /^\d+\.\d+\.\d+/;
$opts{n} =~ s/^(\d+\.\d+\.\d+).*$/$1/;

use Net::Packet qw(:globals);

$Debug = 3 if $opts{v};

$Dev = $opts{d} if $opts{d};
$Ip  = $opts{I} if $opts{I};
$Mac = $opts{M} if $opts{M};

require Net::Packet::Simple;

my @frames;
for (1..254) {
   my $frame = Net::Packet::Simple->arpRequest(
      whoHas  => "$opts{n}.$_",
      tell    => $Ip,
      tellMac => $Mac,
      toMac   => 'broadcast',
   );
   push @frames, $frame;
}

my $times = $opts{r} ? $opts{r} : 3;
for (1..$times) {
   do { $_->send unless $_->reply } for @frames;

   sleep($opts{t} ? $opts{t} : 3);

   $Dump->analyze;

   for (@frames) {
      if ($_->recv) {
         print "Reply:\n";
         $_->reply->ethPrint;
         $_->reply->arpPrint;
      }
   }
}

do { print $_->reply->arpSrcIp, " => ", $_->reply->arpSrc, "\n" if $_->reply }
   for @frames;

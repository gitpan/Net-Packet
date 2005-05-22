#!/usr/bin/perl

#
# $Id: sniffer.pl,v 1.2.2.5 2005/05/22 19:07:56 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:f:v347khpA', \%opts);

die "Usage: sniffer.pl [-f filter] [-d device] [-v] [-3] [-4] [-7] [-p]\n".
    " -d:   device to sniff on\n".
    " -f:   filter to use\n".
    " -3:   print layer 3\n".
    " -4:   print layer 4\n".
    " -7:   print layer 7\n".
    " -v:   be verbose\n".
    " -k:   keep captured savefile\n".
    " -p:   use promiscuous mode\n".
    " -A:   print layer 7 as ASCII text\n".
    ""
   if $opts{h};

use Net::Pkt;

$Env->dev($opts{d}) if     $opts{d};
$Env->promisc(1)    if     $opts{p};
$opts{f} = ""       unless $opts{f};
$Env->debug(3)      if     $opts{v};

my $dump = Net::Packet::Dump->new(
   filter          => $opts{f},
   overwrite       => 1,
   unlinkOnDestroy => $opts{k} ? 0 : 1,
   noStore         => 1,
   callStart       => 1,
);

while (1) {
   if ($dump->next) {
      print($dump->nextFrame->l3->print, "\n")
         if ($opts{3} && $dump->nextFrame->l3);
      print($dump->nextFrame->l4->print, "\n")
         if ($opts{4} && $dump->nextFrame->l4);
      if ($opts{7} && $dump->nextFrame->l7) {
         if ($opts{A}) {
            my $str = $dump->nextFrame->l7->data;
            $str =~ s/[^[:print:]]//g;
            print $str, "\n";
         }
         else {
            print($dump->nextFrame->l7->print, "\n");
         }
      }
   }
}

#!/usr/bin/perl

#
# $Id: vlan-craft.pl,v 1.1.2.2 2006/03/12 11:09:10 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('I:i:m:', \%opts);

die("Usage: $0 -I srcIp -i dstIp -m dstMac\n")
   unless $opts{I} && $opts{i} && $opts{m};

use Net::Pkt;

$Env->debug(3);

Net::Packet::DescL2->new;
Net::Packet::Dump->new(filter => 'vlan');

# Another thing to note, do not send VLAN frames in a
# vlan interface, it would be encapsulated another time ;)
# Instead, send it to the parent interface

# So, we will play an echo-request inside a vlan
my $echo = Net::Packet::Frame->new(
   l3 => Net::Packet::IPv4->new(
      src      => $opts{I},
      dst      => $opts{i},
      protocol => NP_IPv4_PROTOCOL_ICMPv4,
      doChecksum => 1, # Because system will not do it,
                       # at least under FreeBSD
      noFixLen   => 1, # Well, FreeBSD needs fixing, but not
                       # when frames are injected into VLANs ;)
    ),
    l4 => Net::Packet::ICMPv4->new,
);

# Frame to inject is built, time to encapsulate it into a VLAN frame
my $frame = Net::Packet::Frame->new(
   l2 => Net::Packet::ETH->new(
      dst  => $opts{m},
      type => NP_ETH_TYPE_VLAN,
   ),
   l3 => Net::Packet::VLAN->new(
      id       => 123,
      priority => 0,
      frame    => $echo,
   ),
);

# Done !
print $frame->l3->print, "\n";
print $frame->l3->frame->l3->print, "\n";
print $frame->l3->frame->l4->print, "\n";
$frame->send;

exit(0);

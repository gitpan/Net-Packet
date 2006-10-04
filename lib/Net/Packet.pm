#
# $Id: Packet.pm,v 1.2.2.7 2006/10/04 21:18:37 gomor Exp $
#
package Net::Packet;
use strict;
use warnings;

require v5.6.1;

our $VERSION = '3.00_02';

require Exporter;
our @ISA = qw(Exporter);

use Net::Packet::Env    qw($Env);
use Net::Packet::Utils  qw(:all);
use Net::Packet::Consts qw(:desc :dump :layer :eth :arp :vlan :null :ipv4
   :ipv6 :tcp :udp :icmpv4);

require Net::Packet::Dump;

require Net::Packet::DescL2;
require Net::Packet::DescL3;
require Net::Packet::DescL4;

require Net::Packet::Frame;
require Net::Packet::ETH;
require Net::Packet::IPv4;
require Net::Packet::IPv6;
require Net::Packet::VLAN;
require Net::Packet::ARP;
require Net::Packet::TCP;
require Net::Packet::UDP;
require Net::Packet::ICMPv4;
require Net::Packet::NULL;
require Net::Packet::RAW;
require Net::Packet::SLL;

our @EXPORT = (
   @Net::Packet::Env::EXPORT_OK,
   @Net::Packet::Utils::EXPORT_OK,
   @Net::Packet::Consts::EXPORT_OK,
);

END {
   if ($Env->dump) {
      $Env->dump->stop if $Env->dump->isRunning;
      $Env->dump->clean;
   }
   1;
}

1;

__END__

=head1 NAME

Net::Packet - a framework to easily send and receive frames from layer 2 to layer 7

=head1 CLASS HIERARCHY

  Net::Packet

  Net::Packet::Env

  Net::Packet::Dump

  Net::Packet::Utils

  Net::Packet::Desc
     |
     +---Net::Packet::DescL2
     |
     +---Net::Packet::DescL3
     |
     +---Net::Packet::DescL4

  Net::Packet::Frame

  Net::Packet::Layer
     |
     +---Net::Packet::Layer2
     |      |
     |      +---Net::Packet::ETH
     |      |
     |      +---Net::Packet::NULL
     |      |
     |      +---Net::Packet::RAW
     |      |
     |      +---Net::Packet::SLL
     |
     +---Net::Packet::Layer3
     |      |
     |      +---Net::Packet::ARP
     |      |
     |      +---Net::Packet::IPv4
     |      |
     |      +---Net::Packet::IPv6
     |      |
     |      +---Net::Packet::VLAN
     |
     +---Net::Packet::Layer4
     |      |
     |      +---Net::Packet::TCP
     |      |
     |      +---Net::Packet::UDP
     |      |
     |      +---Net::Packet::ICMPv4
     |
     +---Net::Packet::Layer7

=head1 SYNOPSIS

   # Load all modules, it also initializes a Net::Packet::Env object, 
   # and imports all utility subs and constances in current namespace
   use Net::Packet;

   # Build IPv4 header
   my $ip = Net::Packet::IPv4->new(dst => '192.168.0.1');

   # Build TCP header
   my $tcp = Net::Packet::TCP->new(dst => 22);

   # Assemble frame
   # It will also open a Net::Packet::DescL3 descriptor
   # and a Net::Packet::Dump object
   my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $tcp);

   $frame->send;

   # Print the reply just when it has been received
   until ($Env->dump->timeout) {
      if ($frame->recv) {
         print $frame->reply->l3, "\n";
         print $frame->reply->l4, "\n";
         last;
      }
   }

=head1 DESCRIPTION

This module is a unified framework to craft, send and receive packets at layers 2, 3, 4 and 7.

Basically, you forge each layer of a frame (Net::Packet::IPv4 for layer 3, Net::Packet::TCP for layer 4 ; for example), and pack all of this into a Net::Packet::Frame object. Then, you can send the frame to the network, and receive it easily, since the response is automatically searched for and matched against the request.

If you want some layer 2, 3 or 4 protocol encoding/decoding to be added, just ask, and give a corresponding .pcap file ;)

You should study various pod found in all classes, example files found in B<examples> directory that come with this tarball, and also tests in B<t> directory.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=head1 RELATED MODULES  

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

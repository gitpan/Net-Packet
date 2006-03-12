#
# $Id: Pkt.pm,v 1.2.2.19 2006/03/11 16:32:50 gomor Exp $
#
package Net::Pkt;

require Exporter;
our @ISA = qw(Exporter);

use Net::Packet         qw($Env);
use Net::Packet::Utils  qw(:all);
use Net::Packet::Consts qw(:desc :dump :layer :eth :arp :vlan :null :ipv4
   :ipv6 :tcp :udp :icmpv4);

require Net::Packet::Env;
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
   @Net::Packet::EXPORT_OK,
   @Net::Packet::Utils::EXPORT_OK,
   @Net::Packet::Consts::EXPORT_OK,
);

1;

=head1 NAME
   
Net::Pkt - just loads all of Net::Packet classes and imports all subroutines, constants and globals

=head1 SYNOPSIS

  use Net::Pkt;

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret
   
=head1 COPYRIGHT AND LICENSE
 
Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.
   
=head1 RELATED MODULES
 
L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

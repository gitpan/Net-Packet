#
# $Id: ETH.pm,v 1.3.2.4 2006/06/04 13:22:08 gomor Exp $
#
package Net::Packet::ETH;
use strict;
use warnings;

require Net::Packet::Layer2;
our @ISA = qw(Net::Packet::Layer2);

BEGIN {
   *length = \&type;
}

use Net::Packet::Env qw($Env);
use Net::Packet::Utils qw(convertMac);
use Net::Packet::Consts qw(:eth :layer);

our @AS = qw(
   src
   dst
   type
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   my $self = shift->SUPER::new(
      src  => $Env->mac,
      dst  => NP_ETH_ADDR_BROADCAST,
      type => NP_ETH_TYPE_IPv4,
      @_,
   );

   $self->[$__src] = lc($self->[$__src]) if $self->[$__src];
   $self->[$__dst] = lc($self->[$__dst]) if $self->[$__dst];

   $self;
}

sub getLength { NP_ETH_HDR_LEN }

sub pack {
   my $self = shift;

   (my $dst = $self->[$__dst]) =~ s/://g;
   (my $src = $self->[$__src]) =~ s/://g;

   $self->[$__raw] = $self->SUPER::pack('H12H12n', $dst, $src, $self->[$__type])
      or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($dst, $src, $type, $payload) =
      $self->SUPER::unpack('H12H12n a*', $self->[$__raw])
         or return undef;

   $self->[$__dst] = convertMac($dst);
   $self->[$__src] = convertMac($src);

   $self->[$__type]    = $type;
   $self->[$__payload] = $payload;

   1;
}

sub encapsulate {
   my $types = {
      NP_ETH_TYPE_IPv4() => NP_LAYER_IPv4(),
      NP_ETH_TYPE_IPv6() => NP_LAYER_IPv6(),
      NP_ETH_TYPE_ARP()  => NP_LAYER_ARP(),
      NP_ETH_TYPE_VLAN() => NP_LAYER_VLAN(),
   };

   $types->{shift->type} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: type:0x%04x  [%s => %s]",
      $self->type, $self->src, $self->dst;
}

#
# Helpers
#

sub _isType    { shift->type == shift()                           }
sub isTypeArp  { shift->_isType(NP_ETH_TYPE_ARP)                  }
sub isTypeIpv4 { shift->_isType(NP_ETH_TYPE_IPv4)                 }
sub isTypeIpv6 { shift->_isType(NP_ETH_TYPE_IPv6)                 }
sub isTypeVlan { shift->_isType(NP_ETH_TYPE_VLAN)                 }
sub isTypeIp   { my $self = shift; $self->isIpv4 || $self->isIpv6 }

1;

__END__

=head1 NAME

Net::Packet::ETH - Ethernet/802.3 layer 2 object

=head1 SYNOPSIS

   use Net::Packet::ETH;

   use Net::Packet::Consts qw(:eth);

   # Build layer to inject to network
   my $eth1 = Net::Packet::ETH->new(
      type => NP_ETH_TYPE_IPv6,
      dst  => "00:11:22:33:44:55",
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $eth2 = Net::Packet::ETH->new(raw => $rawFromNetwork);

   print $eth1->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Ethernet/802.3 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc894.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination MAC addresses, in classical format (00:11:22:33:44:55).

=item B<type>

The encapsulated layer type (IPv4, IPv6 ...) for Ethernet. Values for Ethernet types are greater than 1500. If it is less than 1500, you should use the B<length> attribute (which is an alias of this one), because the layer is considered a 802.3 one. See http://www.iana.org/assignments/ethernet-numbers .

=item B<length>

The length of the payload when this layer is a 802.3 one. This is the same attribute as B<type>, but you cannot use it when calling B<new> (you can only use it as an accessor after that).

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones.
Default values:

src:         $Env->mac (see B<Net::Packet::Env>)

dst:         NP_ETH_ADDR_BROADCAST

type/length: NP_ETH_TYPE_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isTypeArp>

=item B<isTypeIpv4>

=item B<isTypeIpv6>

=item B<isTypeIp> - is type IPv4 or IPv6

=item B<isTypeVlan>

Helper methods. Return true is the encapsulated upper layer is of specified type, false otherwise. 

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:eth);

=over 4

=item B<NP_ETH_HDR_LEN>

Ethernet header length in bytes.

=item B<NP_ETH_ADDR_BROADCAST>

Ethernet broadcast address.

=item B<NP_ETH_TYPE_IPv4>

=item B<NP_ETH_TYPE_IPv6>

=item B<NP_ETH_TYPE_ARP>

Various supported Ethernet types.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

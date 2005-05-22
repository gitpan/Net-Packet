#
# $Id: SLL.pm,v 1.1.2.9 2005/05/22 19:47:48 gomor Exp $
#
package Net::Packet::SLL;

use strict;
use warnings;

require Net::Packet::Layer2;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer2 Class::Gomor::Hash);

use Net::Packet::Consts qw(:sll :layer);

our @AS = qw(
   packetType
   addressType
   addressLength
   source
   protocol
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      packetType    => NP_SLL_PACKET_TYPE_SENT_BY_US,
      addressType   => NP_SLL_ADDRESS_TYPE_512,
      addressLength => 0,
      source        => 0,
      protocol      => NP_SLL_PROTOCOL_IPv4,
      @_,
   );

   $self;
}

sub getLength { NP_SLL_HDR_LEN }

sub pack {
   my $self = shift;

   $self->raw(
      $self->SUPER::pack('nnnH16n',
         $self->packetType,
         $self->addressType,
         $self->addressLength,
         $self->source,
         $self->protocol,
      ),
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($pt, $at, $al, $s, $p, $payload) =
      $self->SUPER::unpack('nnnH16n a*', $self->raw)
         or return undef;

   $self->packetType($pt);
   $self->addressType($at);
   $self->addressLength($al);
   $self->source($s);
   $self->protocol($p);
   $self->payload($payload);

   1;
}

sub encapsulate {
   my $types = {
      NP_SLL_PROTOCOL_IPv4() => NP_LAYER_IPv4(),
      NP_SLL_PROTOCOL_IPv6() => NP_LAYER_IPv6(),
   };

   $types->{shift->protocol} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: packetType:0x%04x addressLength:0x%04x protocol:0x%04x\n".
           "$l: $i: source: %d",
      $self->packetType,
      $self->addressLength,
      $self->protocol,
      $self->source,
   ;
}

#
# Helpers
#

sub _isProtocol    { shift->protocol == shift()               }
sub isProtocolIpv4 { shift->_isProtocol(NP_SLL_PROTOCOL_IPv4) }
sub isProtocolIpv6 { shift->_isProtocol(NP_SLL_PROTOCOL_IPv6) }
sub isProtocolIp   {
   my $self = shift; $self->isProtocolIpv4 || $self->isProtocolIpv6;
}

1;

__END__

=head1 NAME

Net::Packet::SLL - Linux cooked capture layer 2 object

=head1 SYNOPSIS

   # Usually, you do not use this module directly

   use Net::Packet::SLL;

   # Build layer to inject to network
   my $sll1 = Net::Packet::SLL->new;

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $sll2 = Net::Packet::SLL->new(raw => $rawFromNetwork);

   print $sll1->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Linux cooked capture layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<packetType>

Stores the packet type (unicast to us, sent by us ...).

=item B<addressType>

The address type.

=item B<addressLength>

The length of the previously specified address.

=item B<source>

Source address.

=item B<protocol>

Encapsulated protocol.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

packetType:    NP_SLL_PACKET_TYPE_SENT_BY_US

addressType:   NP_SLL_ADDRESS_TYPE_512

addressLength: 0

source:        0

protocol:      NP_SLL_PROTOCOL_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isProtocolIpv4>

=item B<isProtocolIpv6>

=item B<isProtocolIp> - is type IPv4 or IPv6

Helper methods. Return true is the encapsulated upper layer is of specified type, false otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:sll);

=over 4

=item B<NP_SLL_PACKET_TYPE_SENT_BY_US>

=item B<NP_SLL_PACKET_TYPE_UNICAST_TO_US>

Various possible packet types.

=item B<NP_SLL_PROTOCOL_IPv4>

=item B<NP_SLL_PROTOCOL_IPv6>

Various supported encapsulated layer types.

=item B<NP_SLL_HDR_LEN>

=item B<NP_SLL_ADDRESS_TYPE_512>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

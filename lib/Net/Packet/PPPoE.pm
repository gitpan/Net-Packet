#
# $Id: PPPoE.pm,v 1.1.2.2 2006/11/12 16:53:22 gomor Exp $
#
package Net::Packet::PPPoE;
use strict;
use warnings;

require Net::Packet::Layer3;
our @ISA = qw(Net::Packet::Layer3);

use Net::Packet::Consts qw(:pppoe :layer);
require Bit::Vector;

our @AS = qw(
   version
   type
   code
   sessionId
   payloadLength
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   shift->SUPER::new(
      version       => 1,
      type          => 1,
      code          => 0,
      sessionId     => 1,
      payloadLength => 0,
      @_,
   );
}

sub getLength { NP_PPPoE_HDR_LEN }

sub getPayloadLength { shift->[$__payloadLength] }

sub pack {
   my $self = shift;

   my $version = Bit::Vector->new_Dec(4, $self->[$__version]);
   my $type    = Bit::Vector->new_Dec(4, $self->[$__type]);
   my $v8      = $version->Concat_List($type);

   $self->[$__raw] = $self->SUPER::pack('CCnn',
      $v8->to_Dec,
      $self->[$__code],
      $self->[$__sessionId],
      $self->[$__payloadLength],
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($versionType, $code, $sessionId, $payloadLength, $payload) =
      $self->SUPER::unpack('CCnn a*', $self->[$__raw]);

   my $v8 = Bit::Vector->new_Dec(8, $versionType);
   $self->version($v8->Chunk_Read(4, 0));
   $self->type($v8->Chunk_Read(4, 4));

   $self->[$__code]          = $code;
   $self->[$__sessionId]     = $sessionId;
   $self->[$__payloadLength] = $payloadLength;
   $self->[$__payload]       = $payload;

   1;
}

sub encapsulate {
   my $types = {
      NP_LAYER_PPP() => NP_LAYER_PPP(),
   };

   $types->{NP_LAYER_PPP()} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: version:%d  type:%d  code:0x%02x  sessionId:0x%04x\n".
           "$l: $i: payloadLength:%d",
      $self->[$__version], $self->[$__type], $self->[$__code],
      $self->[$__sessionId], $self->[$__payloadLength];
}

1;

__END__

=head1 NAME

Net::Packet::PPPoE - PPP-over-Ethernet layer 3 object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:pppoe);
   require Net::Packet::PPPoE;

   # Build a layer
   my $layer = Net::Packet::PPPoE->new(
      version       => 1,
      type          => 1,
      code          => 0,
      sessionId     => 1,
      payloadLength => 0,
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::PPPoE->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the PPP-over-Ethernet layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<version> - 4 bits

=item B<code> - 4 bits

=item B<type> - 8 bits

=item B<sessionId> - 16 bits

=item B<payloadLength> - 16 bits

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

version:       1

type:          1

code:          0

sessionId:     1

payloadLength: 0

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:pppoe);

=over 4

=item B<NP_PPPoE_HDR_LEN>

PPPoE header length.

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

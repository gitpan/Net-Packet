#
# $Id: CDP.pm,v 1.1.2.1 2006/11/12 18:11:56 gomor Exp $
#
package Net::Packet::CDP;
use strict;
use warnings;

require Net::Packet::Layer4;
our @ISA = qw(Net::Packet::Layer4);

use Net::Packet::Consts qw(:cdp :layer);

our @AS = qw(
   version
   ttl
   checksum
   typeDeviceId
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

require Net::Packet::CDP::TypeDeviceId;

sub new {
   shift->SUPER::new(
      version  => 2,
      ttl      => 180,
      checksum => 0,
      @_,
   );
}

sub getLength { NP_CDP_HDR_LEN }

sub pack {
   my $self = shift;

   $self->[$__raw] = $self->SUPER::pack('CCn',
      $self->[$__version],
      $self->[$__ttl],
      $self->[$__checksum],
   ) or return undef;

   if ($self->[$__typeDeviceId]) {
      $self->[$__raw] .= $self->[$__typeDeviceId]->pack or return undef;
   }

   1;
}

sub unpack {
   my $self = shift;

   my ($version, $ttl, $checksum, $payload) =
      $self->SUPER::unpack('CCn a*', $self->[$__raw]);

   $self->[$__version]  = $version;
   $self->[$__ttl]      = $ttl;
   $self->[$__checksum] = $checksum;

   my $tail = CORE::unpack('H*', $payload);

   if ($tail =~ /^0001/) {
      my $typeDeviceId = Net::Packet::CDP::TypeDeviceId->new(raw => $payload);
      $self->[$__typeDeviceId] = $typeDeviceId;
      $payload = $typeDeviceId->payload;
      $tail    = CORE::unpack('H*', $payload);
   }

   $self->[$__payload]  = $payload;

   1;
}

sub encapsulate {
   my $types = {
      NP_LAYER_NONE() => NP_LAYER_NONE(),
   };

   $types->{NP_LAYER_NONE()} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $buf = '';

   my $l = $self->layer;
   my $i = $self->is;
   $buf .= sprintf "$l:+$i: version:0x%02x  ttl:0x%02x  checksum:0x%04x\n",
      $self->[$__version], $self->[$__ttl], $self->[$__checksum];

   if ($self->[$__typeDeviceId]) {
      $buf .= $self->[$__typeDeviceId]->print;
   }

   $buf;
}

1;

__END__

=head1 NAME

Net::Packet::CDP - Cisco Discovery Protocol layer 4 object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:cdp);
   require Net::Packet::CDP;

   # Build a layer
   my $layer = Net::Packet::CDP->new(
      version  => 2,
      ttl      => 180,
      checksum => 0,
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::CDP->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Cisco Discovery Protocol layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<version> - 8 bits

=item B<ttl> - 8 bits

=item B<checksum> - 16 bits

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

version:  2

ttl:      180

checksum: 0

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:cdp);

=over 4

=item B<NP_CDP_HDR_LEN>

CDP header length.

=item B<NP_CDP_TYPE_DEVICE_ID>

=item B<NP_CDP_TYPE_ADDRESSES>

=item B<NP_CDP_TYPE_CAPABILITIES>

=item B<NP_CDP_TYPE_SOFTWARE_VERSION>

=item B<NP_CDP_TYPE_PLATFORM>

=item B<NP_CDP_TYPE_VTP_MANAGEMENT_DOMAIN>

=item B<NP_CDP_TYPE_DUPLEX>

=item B<NP_CDP_TYPE_VOIP_VLAN_REPLY>

=item B<NP_CDP_TYPE_TRUST_BITMAP>

=item B<NP_CDP_TYPE_UNTRUSTED_PORT_COS>

=item B<NP_CDP_TYPE_SYSTEM_NAME>

=item B<NP_CDP_TYPE_SYSTEM_OBJECT_ID>

=item B<NP_CDP_TYPE_LOCATION>

Various supported CDP types.

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

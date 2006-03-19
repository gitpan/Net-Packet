#
# $Id: RAW.pm,v 1.1.2.16 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::RAW;

use strict;
use warnings;

require Net::Packet::Layer2;
our @ISA = qw(Net::Packet::Layer2);

use Net::Packet::Consts qw(:layer);

sub new { shift->SUPER::new }

sub pack { shift->raw("") }

sub unpack {
   my $self = shift;
   my $payload = $self->SUPER::unpack('a*', $self->raw)
      or return undef;
   $self->payload($payload);
   1;
}

sub encapsulate { NP_LAYER_UNKNOWN }

1;

__END__

=head1 NAME

Net::Packet::RAW - empty layer 2 object

=head1 SYNOPSIS
  
   # Usually, you do not use this module directly

   use Net::Packet::RAW;

   # Build layer to inject to network
   my $raw1 = Net::Packet::RAW->new;

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $raw2 = Net::Packet::RAW->new(raw => $rawFromNetwork);

=head1 DESCRIPTION

This modules implements the encoding and decoding of the raw layer 2.
 
Because of the nature of this layer, it is not possible to know by asking it what the upper layer type is. We must do a special hack to detect it (done in B<Net::Packet::Frame>).

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 METHODS

=over 4

=item B<new>

Object constructor. No default values, since no attributes.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

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

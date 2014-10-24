#
# $Id: NULL.pm,v 1.1.2.20 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::NULL;

use strict;
use warnings;

require Net::Packet::Layer2;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer2 Class::Gomor::Hash);

use Net::Packet::Consts qw(:null :layer);

our @AS = qw(
   type
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      type => NP_NULL_TYPE_IPv4,
      @_,
   );

   $self;
}

sub getLength { NP_NULL_HDR_LEN }

sub pack {
   my $self = shift;
   $self->raw($self->SUPER::pack('N', $self->type))
      or return undef;
   1;
}

sub unpack {
   my $self = shift;

   my ($type, $payload) = $self->SUPER::unpack('N a*', $self->raw)
      or return undef;

   $self->type($type);
   $self->payload($payload);

   1;
}

sub encapsulate {
   my $types = {
      NP_NULL_TYPE_IPv4() => NP_LAYER_IPv4(),
      NP_NULL_TYPE_IPv6() => NP_LAYER_IPv6(),
   };

   $types->{shift->type} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: type:0x%04x", $self->type;
}

#
# Helpers
#

sub _isType    { shift->type == shift()                                   }
sub isTypeIpv4 { shift->_isType(NP_NULL_TYPE_IPv4)                        }
sub isTypeIpv6 { shift->_isType(NP_NULL_TYPE_IPv6)                        }
sub isTypeIp   { my $self = shift; $self->isTypeIpv4 || $self->isTypeIpv6 }

1;

__END__

=head1 NAME

Net::Packet::NULL - BSD loopback layer 2 object

=head1 SYNOPSIS

   # Usually, you do not use this module directly

   use Net::Packet::NULL;

   #�Build layer to inject to network
   my $null1 = Net::Packet::NULL->new;

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $null2 = Net::Packet::NULL->new(raw => $rawFromNetwork);

   print $null1->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the BSD loopback layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

Stores the type of encapsulated upper layer.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

type: NP_NULL_TYPE_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isTypeIpv4>

=item B<isTypeIpv6>

=item B<isTypeIp> - is type IPv4 or IPv6

Helper methods. Return true is the encapsulated upper layer is of specified type, false otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:null);

=over 4

=item B<NP_NULL_HDR_LEN>

NULL header length in bytes.

=item B<NP_NULL_TYPE_IPv4>

=item B<NP_NULL_TYPE_IPv6>

Various supported encapsulated layer types.

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

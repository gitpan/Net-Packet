#
# $Id: Layer.pm,v 1.2.2.25 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::Layer;

use strict;
use warnings;
use Carp;

require Class::Gomor::Hash;
our @ISA = qw(Class::Gomor::Hash);

use Net::Packet::Consts qw(:layer);

our @AS = qw(
   raw
   payload
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(@_);
   $self->unpack if $self->raw;
   $self;
}

sub is {
   my $layer = ref(shift);
   $layer =~ s/^Net::Packet:://;
   $layer;
}

sub pack {
   my $self = shift;
   my ($fmt, @args) = @_;
   my $res;
   eval { $res = CORE::pack($fmt, @args) };
   $@ ? do { carp("@{[ref($self)]}: unable to pack structure\n"); undef }
      : $res;
}

sub unpack {
   my $self = shift;
   my ($fmt, $arg) = @_;
   my @res;
   eval { @res = CORE::unpack($fmt, $arg) };
   $@ ? do { carp("@{[ref($self)]}: unable to unpack structure\n"); () }
      : @res;
}

sub layer            { NP_LAYER_N_UNKNOWN }
sub encapsulate      { NP_LAYER_NONE      }
sub getKey           { shift->is          }
sub getKeyReverse    { shift->is          }
sub computeLengths   { 1                  }
sub computeChecksums { 1                  }
sub print            { ""                 }
sub getLength        { 0                  }

sub dump {
   my $self = shift;

   my $hex = CORE::unpack('H*', $self->raw);
   $hex =~ s/(..)/\\x$1/g;
   $hex =~ s/\\x$//;
   sprintf "@{[$self->layer]}:+@{[$self->is]}: \"$hex\"";
}

1;

__END__

=head1 NAME

Net::Packet::Layer - base class for all layer modules

=head1 DESCRIPTION

This is the base class for B<Net::Packet::Layer2>, B<Net::Packet::Layer3>, B<Net::Packet::Layer4> and B<Net::Packet::Layer7> modules.

It just provides those layers with inheritable attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<raw>

Stores the raw layer (as captured from the network, or packed to send to network).

=item B<payload>

Stores what is not part of the layer, that is the encapsulated part to be decoded by upper layers.

=back

=head1 METHODS

=over 4

=item B<is>

Returns the string describing the layer type (example: 'IPv4').

=item B<layer>

Returns the string describing the layer number (example: 'L3' for IPv4).

=item B<encapsulate>

Returns the next layer type (parsed from payload). This is the same string as returned by B<is> method.

=item B<computeLengths>

=item B<computeChecksums>

Generally, when a layer is built, some attributes are not yet known until the full Net::Packet::Frame is assembled. Those methods computes various lengths and checksums attributes found in a specific layer. Return 1 on success, undef otherwise.

=item B<print>

Just returns a string in a human readable format describing attributes found in the layer.

=item B<dump>

Just returns a string in hexadecimal format which is how the layer appears on the network.

=item B<getLength>

Returns the layer length in bytes.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:layer);

=over 4

=item B<NP_LAYER>

Base layer string.

=item B<NP_LAYER_ETH>

=item B<NP_LAYER_NULL>

=item B<NP_LAYER_RAW>

=item B<NP_LAYER_SLL>

Layer 2 strings.

=item B<NP_LAYER_ARP>

=item B<NP_LAYER_IPv4>

=item B<NP_LAYER_IPv6>

Layer 3 strings.

=item B<NP_LAYER_TCP>

=item B<NP_LAYER_UDP>

=item B<NP_LAYER_ICMPv4>

Layer 4 strings.

=item B<NP_LAYER_7>

Layer 7 string.

=item B<NP_LAYER_NONE>

=item B<NP_LAYER_UNKNOWN>

Other strings.

=item B<NP_LAYER_N_2>

=item B<NP_LAYER_N_3>

=item B<NP_LAYER_N_4>

=item B<NP_LAYER_N_7>

=item B<NP_LAYER_N_UNKNOWN>

Layer number N strings.

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

package Net::Packet::Layer7;

# $Date: 2005/01/23 10:53:24 $
# $Revision: 1.1.1.1.4.19 $

use strict;
use warnings;

require Net::Packet::Layer;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer Class::Gomor::Hash);

use Net::Packet::Consts qw(:layer);

our @AS = qw(
   data
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new { shift->SUPER::new(@_) }

sub getLength {
   my $self = shift;
   $self->data ? length($self->data) : 0;
}

sub layer { NP_LAYER_N_7 }

sub pack {
   my $self = shift;
   $self->raw($self->SUPER::pack('a*', $self->data))
      or return undef;
   1;
}

sub unpack {
   my $self = shift;
   $self->data($self->SUPER::unpack('a*', $self->raw))
      or return undef;
   1;
}

sub dump {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: %s\n", $self->SUPER::unpack('H*', $self->data)
      or return undef;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: dataLength:%d\n".
           "$l: $i: data: %s",
      $self->getLength, $self->SUPER::unpack('H*', $self->data)
         or return undef;
}

1;

__END__

=head1 NAME

Net::Packet::Layer7 - application layer object

=head1 SYNOPSIS

   use Net::Packet::Layer7;

   # Build layer to inject to network
   my $l7a = Net::Packet::Layer7->new(data => "GET / HTTP/1.0\r\n\r\n");

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $l7b = Net::Packet::Layer7->new(raw => $rawFromNetwork);

   print $l7a->print, "\n";

=head1 DESCRIPTION

This class is different from B<Net::Packet::Layer2> to 4, since we do not decode application layers (Ethereal is good), so this is not a base class, but a final class.

See also B<Net::Packet::Layer> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<data>

Stores the raw data of the application layer.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. No default values.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object.

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

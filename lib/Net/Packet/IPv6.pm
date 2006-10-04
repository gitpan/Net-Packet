#
# $Id: IPv6.pm,v 1.3.2.4 2006/06/11 09:46:30 gomor Exp $
#
package Net::Packet::IPv6;
use strict;
use warnings;

require Net::Packet::Layer3;
our @ISA = qw(Net::Packet::Layer3);

use Net::Packet::Env qw($Env);
use Net::Packet::Utils qw(unpackIntFromNet packIntToNet
   inet6Aton inet6Ntoa);
use Net::Packet::Consts qw(:ipv6 :layer);

BEGIN {
   *protocol = \&nextHeader;
}

our @AS = qw(
   version
   trafficClass
   flowLabel
   nextHeader
   payloadLength
   hopLimit
   src
   dst
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   my $self = shift->SUPER::new(
      version      => 6,
      trafficClass => 0,
      flowLabel    => 0,
      nextHeader   => NP_IPv6_PROTOCOL_TCP,
      hopLimit     => 0xff,
      src          => $Env->ip6,
      dst          => '::1',
      @_,
   );

   $self;
}

sub getLength        { NP_IPv6_HDR_LEN           }
sub getPayloadLength { shift->[$__payloadLength] }

sub _computePayloadLength {
   my $self = shift;
   my ($frame) = @_;

   my $len = 0;
   $len += $frame->l4->getLength if $frame->l4;
   $len += $frame->l7->getLength if $frame->l7;
   $self->[$__payloadLength] = $len;
}

sub computeLengths {
   my $self = shift;
   my ($frame) = @_;

   $frame->l4->computeLengths($frame) or return undef;
   $self->_computePayloadLength($frame);
   1;
}

sub pack {
   my $self = shift;

   my $vtf1 = packIntToNet($self->[$__version],      'C',  0,  4);
   my $vtf2 = packIntToNet($self->[$__trafficClass], 'C',  4,  8);
   my $vtf3 = packIntToNet($self->[$__flowLabel],    'N', 12, 20);

   $self->[$__raw] = $self->SUPER::pack('B32nCCa*a*',
      $vtf1.$vtf2.$vtf3,
      $self->[$__payloadLength],
      $self->[$__nextHeader],
      $self->[$__hopLimit],
      inet6Aton($self->[$__src]),
      inet6Aton($self->[$__dst]),
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($vtf, $pl, $nh, $hl, $sa, $da, $payload) =
      $self->SUPER::unpack('B32nCCa16a16 a*', $self->[$__raw])
         or return undef;

   $self->[$__version]       = unpackIntFromNet($vtf, 'C',  0,  4,  4);
   $self->[$__trafficClass]  = unpackIntFromNet($vtf, 'C',  4,  0,  8);
   $self->[$__flowLabel]     = unpackIntFromNet($vtf, 'N', 12, 12, 20);
   $self->[$__payloadLength] = $pl;
   $self->[$__nextHeader]    = $nh;
   $self->[$__hopLimit]      = $hl;
   $self->[$__src]           = inet6Ntoa($sa);
   $self->[$__dst]           = inet6Ntoa($da);

   $self->[$__payload] = $payload;

   1;
}

sub encapsulate {
   my $types = {           
      NP_IPv6_PROTOCOL_TCP()    => NP_LAYER_TCP(),
      NP_IPv6_PROTOCOL_UDP()    => NP_LAYER_UDP(),
      #NP_IPv4_PROTOCOL_ICMPv6() => NP_LAYER_ICMPv6(),
   };

   $types->{shift->[$__nextHeader]} || NP_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;       
   
   my $i = $self->is;       
   my $l = $self->layer;    
   sprintf
      "$l:+$i: version:%d  trafficClass:%.2d  flowLabel:%.5d  nextHeader:%.2d\n".
      "$l: $i: [%s => %s]\n".
      "$l: $i: length:%d",
         $self->version,
         $self->trafficClass,
         $self->flowLabel,
         $self->nextHeader,
         $self->src,
         $self->dst,
         $self->getLength,
   ;
}

1;

=head1 NAME

Net::Packet::IPv6 - Internet Protocol v6 layer 3 object

=head1 SYNOPSIS

   use Net::Packet::IPv6;

   #�Build layer to inject to network
   my $ip6 = Net::Packet::IPv6->new(
      dst => $hostname6,
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $ip6Decoded = Net::Packet::IPv6->new(raw = $rawFromNetwork);

   print $ip6->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the IPv6 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc2460.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<version>

Version of Internet Protocol header.

=item B<trafficClass>

Traffic class field. Was Type of Service in IPv4.

=item B<flowLabel>

Flow label class field. Was IP ID in IPv4.

=item B<nextHeader>

The type of next header. Was protocol in IPv4.

=item B<payloadLength>

Length in bytes of encapsulated layers (that is, layer 4 + layer 7).

=item B<hopLimit>

Was TTL field in IPv4.

=item B<src>

=item B<dst>

Source and destination addresses.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

version:      6

trafficClass: 0

flowLabel:    0

nextHeader:   NP_IPv6_PROTOCOL_TCP

hopLimit:     0xff

src:          $Env->ip6

dst:          '::1'

=item B<getPayloadLength>

Returns the length in bytes of encapsulated layers (that is layer 4 + layer 7).

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:ipv6);

=over 4

=item B<NP_IPv6_PROTOCOL_TCP>

=item B<NP_IPv6_PROTOCOL_UDP>

Constants for B<nextHeader> attribute.

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
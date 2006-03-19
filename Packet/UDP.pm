#
# $Id: UDP.pm,v 1.2.2.36 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::UDP;

use strict;
use warnings;

require Net::Packet::Layer4;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer4 Class::Gomor::Hash);

use Net::Packet::Utils qw(inetChecksum getRandomHighPort inetAton inet6Aton);
use Net::Packet::Consts qw(:udp :layer);

our @AS = qw(
   src
   dst
   length
   checksum
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   shift->SUPER::new(
      src      => getRandomHighPort(),
      dst      => 0,
      length   => 0,
      checksum => 0,
      @_,
   );
}

sub recv {
   my $self  = shift;
   my $frame = shift;

   my $env = $frame->env;

   for ($env->dump->framesFor($frame)) {
      return $_ if $_->timestamp ge $frame->timestamp;
   }

   my $l2Key = 'all';
   $l2Key = $frame->l2->getKeyReverse($frame) if $frame->l2;

   my $l3Key = 'all';
   $l3Key = $frame->l3->is.':'.$frame->l3->src if $frame->l3;

   my $l4Key = 'all';
   $l4Key = 'ICMP' if $frame->l4;

   my $href = $env->dump->framesSorted;
   for (@{$href->{$l2Key}{$l3Key}{$l4Key}}) {
      if (($_->timestamp ge $frame->timestamp)
      &&   $_->l4->error
      &&  ($_->l4->error->l4->src == $self->src)
      &&  ($_->l4->error->l4->dst == $self->dst)) {
         return $_;
      }
   }

   undef;
}

sub pack {
   my $self = shift;

   $self->raw(
      $self->SUPER::pack('nnnn',
         $self->src,
         $self->dst,
         $self->length,
         $self->checksum,
      ),
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $len, $checksum, $payload) =
      $self->SUPER::unpack('nnnn a*', $self->raw)
         or return undef;

   $self->src($src);
   $self->dst($dst);
   $self->length($len);
   $self->checksum($checksum);
   $self->payload($payload);

   1;
}

sub getLength        { NP_UDP_HDR_LEN                 }
sub getPayloadLength {
   my $self = shift;
   $self->length > $self->getLength
      ? $self->length - $self->getLength
      : 0;
}

sub _computeTotalLength {
   my $self  = shift;
   my $frame = shift;

   # Autocompute header length if not user specified
   return if $self->length;

   my $totalLength = $self->getLength;
   $totalLength += $frame->l7->getLength if $frame->l7;
   $self->length($totalLength);
}

sub computeLengths {
   my $self  = shift;
   my $frame = shift;

   $self->_computeTotalLength($frame);
   1;
}

sub computeChecksums {
   my $self  = shift;
   my $frame = shift;

   my $env = $frame->env;

   my $phpkt;
   if ($frame->l3) {
      if ($frame->isIpv4) {
         $phpkt = $self->SUPER::pack('a4a4CCn',
            inetAton($frame->l3->src),
            inetAton($frame->l3->dst),
            0,
            $frame->l3->protocol,
            $self->length,
         ) or return undef;
      }
      elsif ($frame->isIpv6) {
         $phpkt = $self->SUPER::pack('a*a*NnCC',
            inet6Aton($frame->l3->src),
            inet6Aton($frame->l3->dst),
            $frame->l3->payloadLength,
            0,
            0,
            $frame->l3->nextHeader,
         ) or return undef;
      }
   }
   else {
      my $totalLength = $self->getLength;
      $totalLength += $frame->l7->getLength if $frame->l7;

      if ($env->desc->isFamilyIpv4) {
         $phpkt = $self->SUPER::pack('a4a4CCn',
            inetAton($env->ip),
            inetAton($env->desc->target),
            0,
            $env->desc->protocol,
            $totalLength,
         ) or return undef;
      }
      elsif ($env->desc->isFamilyIpv6) {
         $phpkt = $self->SUPER::pack('a*a*NnCC',
            inet6Aton($env->ip6),
            inet6Aton($env->desc->target),
            $totalLength,
            0,
            0,
            $env->desc->protocol,
         ) or return undef;
      }
   }

   $phpkt .= $self->SUPER::pack('nnnn',
      $self->src,
      $self->dst,
      $self->length,
      $self->checksum,
   ) or return undef;

   if ($frame->l7) {
      $phpkt .= $self->SUPER::pack('a*', $frame->l7->data)
         or return undef;
   }

   $self->checksum(inetChecksum($phpkt));

   1;
}

sub encapsulate { shift->payload ? NP_LAYER_7 : NP_LAYER_NONE }

sub getKey {
   my $self = shift;
   $self->is.':'.$self->src.'-'.$self->dst;
}

sub getKeyReverse {
   my $self = shift;
   $self->is.':'.$self->dst.'-'.$self->src;
}

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   sprintf
      "$l:+$i: checksum:0x%.4x  [%d => %d]\n".
      "$l: $i: size:%d  header:%d  payload:%d",
         $self->checksum,
         $self->src,
         $self->dst,
         $self->length,
         $self->getLength,
         $self->getPayloadLength,
   ;
}

1;

__END__

=head1 NAME

Net::Packet::UDP - User Datagram Protocol layer 4 object

=head1 SYNOPSIS

   use Net::Packet::UDP;

   # Build layer to inject to network
   my $udp = Net::Packet::UDP->new(
      dst => 31222,
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $udp2 = Net::Packet::UDP->new(raw = $rawFromNetwork);

   print $udp->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the UDP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc768.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination ports.

=item B<length>

The length in bytes of the datagram, including layer 7 payload (that is, layer 4 + layer 7).

=item B<checksum>

Checksum of the datagram.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

src:      getRandomHighPort()

dst:      0

length:   0

checksum: 0

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getPayloadLength>

Returns the length in bytes of payload (layer 7 object).

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

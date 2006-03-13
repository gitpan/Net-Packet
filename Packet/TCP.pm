#
# $Id: TCP.pm,v 1.2.2.42 2006/03/11 16:32:50 gomor Exp $
#
package Net::Packet::TCP;

use strict;
use warnings;

require Net::Packet::Layer4;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer4 Class::Gomor::Hash);

use Net::Packet::Utils qw(inetChecksum getRandomHighPort getRandom32bitsInt
   inetAton inet6Aton);
use Net::Packet::Consts qw(:tcp :layer);

our @AS = qw(
   src
   dst
   flags
   win
   seq
   ack
   off
   x2
   checksum
   urp
   options
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      src      => getRandomHighPort(),
      dst      => 0,
      seq      => getRandom32bitsInt(),
      ack      => 0,
      x2       => 0,
      off      => 0,
      flags    => NP_TCP_FLAG_SYN,
      win      => 0xffff,
      checksum => 0,
      urp      => 0,
      options  => "",
      @_,
   );

   unless ($self->raw) {
      #�Autocompute header length if not user specified
      unless ($self->off) {
         my $hLen = NP_TCP_HDR_LEN;
         $hLen   += length($self->options) if $self->options;
         $self->off($hLen / 4);
      }
   }

   $self;
}

sub recv {
   my $self  = shift;
   my $frame = shift;

   my $env = $frame->env;

   for ($env->dump->framesFor($frame)) {
      if (($_->l4->ack == $frame->l4->seq + 1 || $_->l4->haveFlagRst)
      &&  $_->timestamp ge $frame->timestamp) {
         return $_;
      }
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

   my $offX2Flags =
   ($self->off << 12) | (0x0f00 & ($self->x2 << 8)) | (0x00ff & $self->flags);

   $self->raw(
      $self->SUPER::pack('nnNNnnnn',
         $self->src,
         $self->dst,
         $self->seq,
         $self->ack,
         $offX2Flags,
         $self->win,
         $self->checksum,
         $self->urp,
      ),
   ) or return undef;

   if ($self->options) {
      $self->raw($self->raw. $self->SUPER::pack('a*', $self->options))
         or return undef;
   }

   1;
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $seq, $ack, $offX2Flags, $win, $checksum, $urp, $payload) =
      $self->SUPER::unpack('nnNNnnnn a*', $self->raw)
         or return undef;

   $self->src($src);
   $self->dst($dst);
   $self->seq($seq);
   $self->ack($ack);
   $self->off(($offX2Flags & 0xf000) >> 12);
   $self->x2(($offX2Flags & 0x0f00) >> 8);
   $self->flags($offX2Flags & 0x00ff);
   $self->win($win);
   $self->checksum($checksum);
   $self->urp($urp);
   $self->payload($payload);

   my ($options, $payload2) =
      $self->SUPER::unpack('a'. $self->getOptionsLength. 'a*', $self->payload)
         or return undef;

   $self->options($options);
   $self->payload($payload2);

   1;
}

sub getLength        { my $self = shift; $self->off ? $self->off * 4 : 0 }
sub getHeaderLength  { NP_TCP_HDR_LEN }
sub getOptionsLength {
   my $self = shift;
   $self->getLength > $self->getHeaderLength
      ? $self->getLength - $self->getHeaderLength
      : 0;
}

sub computeChecksums {
   my $self  = shift;
   my $frame = shift;

   my $env = $frame->env;

   my $offX2Flags = ($self->off << 12) | (0x0f00 & ($self->x2 << 8))
                  | (0x00ff & $self->flags);

   my $phpkt;
   # Handle checksumming with DescL2&3
   if ($frame->l3) {
      if ($frame->l3->isIpv4) {
         $phpkt = $self->SUPER::pack('a4a4CCn',
            inetAton($frame->l3->src),
            inetAton($frame->l3->dst),
            0,
            $frame->l3->protocol,
            $frame->l3->getPayloadLength,
         ) or return undef;
      }
      elsif ($frame->l3->isIpv6) {
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
   # Handle checksumming with DescL4
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

   $phpkt .= $self->SUPER::pack('nnNNnnnn',
      $self->src,
      $self->dst,
      $self->seq,
      $self->ack,
      $offX2Flags,
      $self->win,
      $self->checksum,
      $self->urp,
   ) or return undef;

   if ($self->options) {
      $phpkt .= $self->SUPER::pack('a*', $self->options)
         or return undef;
   }

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
   my $buf = sprintf
      "$l:+$i: seq:0x%.8x  win:%d  [%d => %d]\n".
      "$l: $i: ack:0x%.8x  flags:0x%.2x  urp:0x%.4x  checksum:0x%.4x\n".
      "$l: $i: length:%d  optionsLength:%d",
         $self->seq,
         $self->win,
         $self->src,
         $self->dst,
         $self->ack,
         $self->flags,
         $self->urp,
         $self->checksum,
         $self->getLength,
         $self->getOptionsLength,
   ;

   if ($self->options) {
      $buf .= sprintf("\n$l: $i: options:%s",
         $self->SUPER::unpack('H*', $self->options))
            or return undef;
   }

   $buf;
}

#
# Helpers
#

sub _haveFlag   { (shift->flags & shift) ? 1 : 0    }
sub haveFlagFin { shift->_haveFlag(NP_TCP_FLAG_FIN) }
sub haveFlagSyn { shift->_haveFlag(NP_TCP_FLAG_SYN) }
sub haveFlagRst { shift->_haveFlag(NP_TCP_FLAG_RST) }
sub haveFlagPsh { shift->_haveFlag(NP_TCP_FLAG_PSH) }
sub haveFlagAck { shift->_haveFlag(NP_TCP_FLAG_ACK) }
sub haveFlagUrg { shift->_haveFlag(NP_TCP_FLAG_URG) }
sub haveFlagEce { shift->_haveFlag(NP_TCP_FLAG_ECE) }
sub haveFlagCwr { shift->_haveFlag(NP_TCP_FLAG_CWR) }

1;

__END__

=head1 NAME

Net::Packet::TCP - Transmission Control Protocol layer 4 object

=head1 SYNOPSIS

   use Net::Packet::TCP;

   #�Build layer to inject to network
   my $tcp = Net::Packet::TCP->new(
      dst     => 22,
      options => "\x02\x04\x05\xb4", #�MSS=1460
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $tcp2 = Net::Packet::TCP->new(raw => $rawFromNetwork);

   print $tcp->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the TCP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc793.txt
      
See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination ports.

=item B<flags>

TCP flags, see CONSTANTS.

=item B<win>

The window size.

=item B<seq>

=item B<ack>

Sequence and acknowledgment numbers.

=item B<off>

The size in number of words of the TCP header.

=item B<x2>

Reserved field.

=item B<checksum>

The TCP header checksum.

=item B<urp>

Urgent pointer.

=item B<options>

TCP options, as a hexadecimal string.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

src:      getRandomHighPort()

dst:      0

seq:      getRandom32bitsInt()

ack:      0

x2:       0

off:      0

flags:    NP_TCP_FLAG_SYN

win:      0xffff

checksum: 0

urp:      0

options:  ""

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getHeaderLength>

Returns the header length in bytes, not including TCP options.

=item B<getOptionsLength>

Returns options length in bytes.

=item B<haveFlagFin>

=item B<haveFlagSyn>

=item B<haveFlagRst>

=item B<haveFlagPsh>

=item B<haveFlagAck>

=item B<haveFlagUrg>

=item B<haveFlagEce>

=item B<haveFlagCwr>

Returns 1 if the specified TCP flag is set in B<flags> attribute, 0 otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:tcp);

=over 4

=item B<NP_TCP_FLAG_FIN>

=item B<NP_TCP_FLAG_SYN>

=item B<NP_TCP_FLAG_RST>

=item B<NP_TCP_FLAG_PSH>

=item B<NP_TCP_FLAG_ACK>

=item B<NP_TCP_FLAG_URG>

=item B<NP_TCP_FLAG_ECE>

=item B<NP_TCP_FLAG_CWR>

TCP flag constants.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
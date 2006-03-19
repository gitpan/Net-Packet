#
# $Id: ARP.pm,v 1.2.2.35 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::ARP;

use strict;
use warnings;

require Net::Packet::Layer3;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer3 Class::Gomor::Hash);

use Net::Packet qw($Env);
use Net::Packet::Utils qw(getHostIpv4Addr convertMac inetAton inetNtoa);
use Net::Packet::Consts qw(:arp :layer);

our @AS = qw(
   hType
   pType
   hSize
   pSize
   opCode
   src
   dst
   srcIp
   dstIp
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      hType   => NP_ARP_HTYPE_ETH,
      pType   => NP_ARP_PTYPE_IPv4,
      hSize   => NP_ARP_HSIZE_ETH,
      pSize   => NP_ARP_PSIZE_IPv4,
      opCode  => NP_ARP_OPCODE_REQUEST,
      src     => $Env->mac,
      dst     => NP_ARP_ADDR_BROADCAST,
      srcIp   => $Env->ip,
      dstIp   => "127.0.0.1",
      @_,
   );

   $self->srcIp(getHostIpv4Addr($self->srcIp));
   $self->dstIp(getHostIpv4Addr($self->dstIp));

   $self->src(lc($self->src)) if $self->src;
   $self->dst(lc($self->dst)) if $self->dst;

   $self;
}

sub getLength { NP_ARP_HDR_LEN }

sub pack {
   my $self = shift;

   (my $srcMac = $self->src) =~ s/://g;
   (my $dstMac = $self->dst) =~ s/://g;

   $self->raw(
      $self->SUPER::pack('nnUUnH12a4H12a4',
         $self->hType,
         $self->pType,
         $self->hSize,
         $self->pSize,
         $self->opCode,
         $srcMac,
         inetAton($self->srcIp),
         $dstMac,
         inetAton($self->dstIp),
      ),
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($hType, $pType, $hSize, $pSize, $opCode, $srcMac, $srcIp, $dstMac,
      $dstIp) = $self->SUPER::unpack('nnUUnH12a4H12a4', $self->raw)
         or return undef;

   $self->hType($hType);
   $self->pType($pType);
   $self->hSize($hSize);
   $self->pSize($pSize);
   $self->opCode($opCode);
   $self->src(convertMac($srcMac));
   $self->srcIp(inetNtoa($srcIp));
   $self->dst(convertMac($dstMac));
   $self->dstIp(inetNtoa($dstIp));

   1;
}

sub recv {
   my $self  = shift;
   my $frame = shift;

   my $src    = $self->src;
   my $srcIp  = $self->srcIp;
   my $dstIp  = $self->dstIp;
   my $opCode = $self->opCode;

   for ($frame->env->dump->framesFor($frame)) {
      if ($opCode == NP_ARP_OPCODE_REQUEST) {
         if ($_->l3->opCode == NP_ARP_OPCODE_REPLY
         &&  $_->l3->dst    eq $src
         &&  $_->l3->srcIp  eq $dstIp
         &&  $_->l3->dstIp  eq $srcIp) {
            return $_ if $_->timestamp ge $frame->timestamp;
         }
      }
   }

   undef;
}

sub encapsulate { NP_LAYER_NONE }

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf
      "$l:+$i: hType:0x%.4x  hSize:0x%.2x  pType:0x%.4x  pSize:0x%.2x\n".
      "$l: $i: srcMac:%s => dstMac:%s\n".
      "$l: $i: srcIp:%s => dstIp:%s\n".
      "$l: $i: opCode:0x%.4x",
         $self->hType,  $self->hSize, $self->pType, $self->pSize,
         $self->src,    $self->dst,
         $self->srcIp,  $self->dstIp,
         $self->opCode,
   ;
}

#
# Helpers
#

sub _isOpCode { shift->opCode == shift                  }
sub isRequest { shift->_isOpCode(NP_ARP_OPCODE_REQUEST) }
sub isReply   { shift->_isOpCode(NP_ARP_OPCODE_REPLY)   }

1;

__END__

=head1 NAME

Net::Packet::ARP - Address Resolution Protocol layer 3 object

=head1 SYNOPSIS

   use Net::Packet::ARP;

   # Build layer to inject to network
   my $arpRequest = Net::Packet::ARP->new(
      dstIp => "192.168.0.1",
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $arp = Net::Packet::ARP->new(raw => $rawFromNetwork);

   print $arpRequest->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ARP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc826.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<hType>

=item B<pType>

Hardware and protocol address types.

=item B<hSize>

=item B<pSize>

Hardware and protocol address sizes in bytes.

=item B<opCode>

The operation code number to perform.

=item B<src>

=item B<dst>

Source and destination hardware addresses.

=item B<srcIp>

=item B<dstIp>

Source and destination IP addresses.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

hType:  NP_ARP_HTYPE_ETH

pType:  NP_ARP_PTYPE_IPv4

hSize:  NP_ARP_HSIZE_ETH

pSize:  NP_ARP_PSIZE_IPv4

opCode: NP_ARP_OPCODE_REQUEST

src:    $Env->mac

dst:    NP_ARP_ADDR_BROADCAST

srcIp:  $Env->ip

dstIp:  127.0.0.1

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<isRequest>

=item B<isReply>

Returns 1 if the B<opCode> attribute is of specified type.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:arp);

=over 4

=item B<NP_ARP_HTYPE_ETH>

=item B<NP_ARP_PTYPE_IPv4>

Hardware and protocol address types.

=item B<NP_ARP_HSIZE_ETH>

=item B<NP_ARP_PSIZE_IPv4>

Hardware and protocol address sizes.

=item B<NP_ARP_OPCODE_REQUEST>

=item B<NP_ARP_OPCODE_REPLY>

Operation code numbers.

=item B<NP_ARP_ADDR_BROADCAST>

Broadcast address for B<src> or B<dst> attributes.

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

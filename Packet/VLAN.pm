#
# $Id: VLAN.pm,v 1.1.2.6 2006/03/11 19:18:48 gomor Exp $
#
package Net::Packet::VLAN;

use strict;
use warnings;

require Net::Packet::Layer3;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer3 Class::Gomor::Hash);

use Net::Packet qw($Env);
use Net::Packet::Consts qw(:vlan :layer);
require Net::Packet::Frame;

our @AS = qw(
   priority
   cfi
   id
   type
   frame
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      priority => 0,
      cfi      => 0,
      id       => 0,
      type     => NP_VLAN_TYPE_IPv4,
      @_,
   );

   $self;
}

sub getLength {
   my $self = shift;
   do { return length($self->frame) + NP_VLAN_HDR_LEN } if $self->frame;
   NP_VLAN_HDR_LEN;
}

require Bit::Vector;

sub pack {
   my $self = shift;

   my $v3  = Bit::Vector->new_Dec(3,  $self->priority);
   my $v1  = Bit::Vector->new_Dec(1,  $self->cfi);
   my $v12 = Bit::Vector->new_Dec(12, $self->id);

   my $v16 = $v3->Concat_List($v1, $v12);

   $self->raw(
      $self->SUPER::pack('nna*',
         $v16->to_Dec,
         $self->type,
         $self->frame->raw,
      ),
   ) or return undef;

   1;
}

sub unpack {
   my $self = shift;

   my ($pCfiId, $type, $payload) =
      $self->SUPER::unpack('nn a*', $self->raw)
         or return undef;

   my $v16 = Bit::Vector->new_Dec(16, $pCfiId);

   $self->priority($v16->Chunk_Read(3, 13));
   $self->cfi     ($v16->Chunk_Read(1, 12));
   $self->id      ($v16->Chunk_Read(12, 0));
   $self->type    ($type);

   $self->frame(Net::Packet::Frame->new(raw => $payload));

   1;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   sprintf "$l:+$i: priority:%d  cfi:%d  id:%d  type:0x%04x",
      $self->priority, $self->cfi, $self->id, $self->type;
}

#
# Helpers
#

sub _isType    { shift->type == shift()                           }
sub isTypeArp  { shift->_isType(NP_VLAN_TYPE_ARP)                 }
sub isTypeIpv4 { shift->_isType(NP_VLAN_TYPE_IPv4)                }
sub isTypeIpv6 { shift->_isType(NP_VLAN_TYPE_IPv6)                }
sub isTypeIp   { my $self = shift; $self->isIpv4 || $self->isIpv6 }

1;

__END__

=head1 NAME

Net::Packet::VLAN - 802.1Q layer 3 object

=head1 SYNOPSIS

   use Net::Packet qw($Env);
   use Net::Packet::VLAN;

   # Load needed constants
   use Net::Packet::Consts qw(:ipv4 :eth);

   # In order to avoid autocreation of Desc and Dump objects
   # Because VLAN is particuliar, we must do it manually
   use Net::Packet::DescL2;
   use Net::Packet::Dump;

   Net::Packet::DescL2->new;
   Net::Packet::Dump->new(filter => 'vlan');

   # Another thing to note, do not send VLAN frames in a 
   # vlan interface, it would be encapsulated another time ;)
   # Instead, send it to the parent interface

   # So, we will play an echo-request inside a vlan
   use Net::Packet::Frame;
   use Net::Packet::IPv4;
   use Net::Packet::ICMPv4;
   my $echo = Net::Packet::Frame->new(
      l3 => Net::Packet::IPv4->new(
         src      => $vlanSrcIp,
         dst      => $vlanDstIp,
         protocol => NP_IPv4_PROTOCOL_ICMPv4,
         doChecksum => 1, # Because system will not do it,
                          # at least under FreeBSD
         noFixLen   => 1, # Well, FreeBSD needs fixing, but not 
                          # when frames are injected into VLANs ;)
      ),
      l4 => Net::Packet::ICMPv4->new,
   );

   # Frame to inject is built, time to encapsulate it into a VLAN frame
   use Net::Packet::ETH;
   my $frame = Net::Packet::Frame->new(
      l2 => Net::Packet::ETH->new(
         dst  => $vlanDstMac,
         type => NP_ETH_TYPE_VLAN,
      ),
      l3 => Net::Packet::VLAN->new(
         frame => $echo,
      ),
   );

   # Done !
   print $frame->l3->print, "\n";
   print $frame->l3->frame->l3->print, "\n";
   print $frame->l3->frame->l4->print, "\n";
   $frame->send;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Virtual LAN/802.1Q layer.

Details: http://standards.ieee.org/getieee802/802.1.html

See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<priority>

The priority field.

=item B<cfi>

The cfi field. It is only one bit long, so set it to 0 or 1.

=item B<id>

VLAN tag id. You'll love it.

=item B<type>

Which type the next encapsulated layer is.

=item B<frame>

This is a B<Net::Packet::Frame> object, built it like any other such frame. Just to mention that you should use B<doChecksum> attribute if you put in a B<Net::Packet::IPv4> layer, and maybe the B<noFixLen> attribute also.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

priority: 0

cfi:      0

id:       0

type:     NP_VLAN_TYPE_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:vlan);

=over 4

=item B<NP_VLAN_TYPE_ARP>

=item B<NP_VLAN_TYPE_IPv4>

=item B<NP_VLAN_TYPE_IPv6>

Various supported encapsulated frame types.

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

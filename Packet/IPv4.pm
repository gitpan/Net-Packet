package Net::Packet::IPv4;

# $Date: 2005/02/01 16:29:16 $
# $Revision: 1.2.2.31 $

use strict;
use warnings;

require Net::Packet::Layer3;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer3 Class::Gomor::Hash);

use Carp;
use Net::Packet qw($Env);
use Net::Packet::Utils qw(getHostIpv4Addr getRandom16bitsInt inetAton inetNtoa);
use Net::Packet::Consts qw(:ipv4 :layer);

our $VERSION = $Net::Packet::VERSION;

BEGIN {
   my $osname = {
      freebsd => \&_fixLenBsd,
      netbsd  => \&_fixLenBsd,
   };

   *_fixLen = $osname->{$^O} || \&_fixLenOther;
}

sub _fixLenBsd   { pack('v', shift) }
sub _fixLenOther { pack('n', shift) }

our @AS = qw(
   id
   ttl
   src
   dst
   protocol
   checksum
   flags
   version
   tos
   length
   hlen
   options
);

__PACKAGE__->buildAccessorsScalar(\@AS);      

sub new {
   my $self = shift->SUPER::new(
      version  => 4,
      tos      => 0,
      id       => getRandom16bitsInt(),
      length   => 0,
      hlen     => 0,
      flags    => 0,
      ttl      => 128,
      protocol => NP_IPv4_PROTOCOL_TCP,
      checksum => 0,
      src      => $Env->ip,
      dst      => "127.0.0.1",
      options  => "",
      @_,
   );

   $self->src(getHostIpv4Addr($self->src));
   $self->dst(getHostIpv4Addr($self->dst));

   unless ($self->raw) {
      # Autocompute header length if not user specified
      unless ($self->hlen) {
         my $hLen = NP_IPv4_HDR_LEN;
         $hLen   += length($self->options) if $self->options;
         $self->hlen($hLen / 4);
      }
   }

   $self;
}

sub pack {
   my $self = shift;

   # Thank you Stephanie Wehner
   my $hlenVer  = ($self->hlen & 0x0f) | (($self->version << 4) & 0xf0);
   my $flags    = ($self->flags << 13) | (($self->flags >> 3) & 0x1fff);

   $self->raw(
      $self->SUPER::pack('CCa*nnCCna4a4',
         $hlenVer,
         $self->tos,
         _fixLen($self->length),
         $self->id,
         $flags,
         $self->ttl,
         $self->protocol,
         $self->checksum,
         inetAton($self->src),
         inetAton($self->dst),
      ),
   ) or return undef;

   my $opt;
   if ($self->options) {
      $opt = $self->SUPER::pack('a*', $self->options)
         or return undef;
      $self->raw($self->raw. $opt);
   }

   1;
}

sub unpack {
   my $self = shift;

   my ($verHlen, $tos, $len, $id, $flags, $ttl, $proto, $cksum, $src, $dst,
      $payload) = $self->SUPER::unpack('CCnnnCCna4a4 a*', $self->raw)
         or return undef;

   $self->version(($verHlen & 0xf0) >> 4);
   $self->hlen($verHlen & 0x0f);
   $self->tos($tos);
   $self->length($len);
   $self->id($id);
   $self->flags($flags);
   $self->ttl($ttl);
   $self->protocol($proto);
   $self->checksum($cksum);
   $self->src(inetNtoa($src));
   $self->dst(inetNtoa($dst));
   $self->payload($payload);

   my ($options, $payload2) =
      $self->SUPER::unpack('a'. $self->getOptionsLength. 'a*', $self->payload)
         or return undef;

   $self->options($options);
   $self->payload($payload2);

   1;
}

sub getLength        { my $self = shift; $self->hlen > 0 ? $self->hlen * 4 : 0 }
sub getHeaderLength  { NP_IPv4_HDR_LEN                                         }
sub getPayloadLength {
   my $self = shift;
   $self->length > $self->getLength
      ? $self->length - $self->getLength
      : 0;
}
sub getOptionsLength {
   my $self = shift;
   $self->getLength > $self->getHeaderLength
      ? $self->getLength - $self->getHeaderLength
      : 0;
}

sub _computeTotalLength {
   my $self  = shift;
   my $frame = shift;

   # Do not compute if user specified
   return if $self->length;

   my $total = $self->getLength;
   $total += $frame->l4->getLength;
   $total += $frame->l7->getLength if $frame->l7;
   $self->length($total);
}

sub computeLengths {
   my $self  = shift;
   my $frame = shift;

   $frame->l4->computeLengths($frame) or return undef;
   $self->_computeTotalLength($frame);
   1;
}

sub encapsulate {
   my $types = {
      NP_IPv4_PROTOCOL_TCP()    => NP_LAYER_TCP(),
      NP_IPv4_PROTOCOL_UDP()    => NP_LAYER_UDP(),
      NP_IPv4_PROTOCOL_ICMPv4() => NP_LAYER_ICMPv4(),
   };

   $types->{shift->protocol} || NP_LAYER_UNKNOWN();
}

sub getKey {
   my $self  = shift;
   $self->is.':'.$self->src.'-'.$self->dst;
}

sub getKeyReverse {
   my $self  = shift;
   $self->is.':'.$self->dst.'-'.$self->src;
}

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   sprintf
      "$l:+$i: version:%d  id:%.4d  ttl:%d  [%s => %s]\n".
      "$l: $i: tos:0x%.2x  flags:0x%.4x  checksum:0x%.4x  protocol:0x%.2x\n".
      "$l: $i: size:%d  length:%d  optionsLength:%d  payload:%d",
         $self->version,
         $self->id,
         $self->ttl,
         $self->src,
         $self->dst,
         $self->tos,
         $self->flags,
         $self->checksum,
         $self->protocol,
         $self->length,
         $self->getLength,
         $self->getOptionsLength,
         $self->getPayloadLength,
   ;
}

#
# Helpers
#

sub _haveFlag  { (shift->flags & shift()) ? 1 : 0            }
sub haveFlagDf { shift->_haveFlag(NP_IPv4_DONT_FRAGMENT)     }
sub haveFlagMf { shift->_haveFlag(NP_IPv4_MORE_FRAGMENT)     }
sub haveFlagRf { shift->_haveFlag(NP_IPv4_RESERVED_FRAGMENT) }

sub _isProtocol      { shift->protocol == shift()                  }
sub isProtocolTcp    { shift->_isProtocol(NP_IPv4_PROTOCOL_TCP)    }
sub isProtocolUdp    { shift->_isProtocol(NP_IPv4_PROTOCOL_UDP)    }
sub isProtocolIcmpv4 { shift->_isProtocol(NP_IPv4_PROTOCOL_ICMPv4) }

1;

__END__
   
=head1 NAME

Net::Packet::IPv4 - Internet Protocol v4 layer 3 object

=head1 SYNOPSIS

   use Net::Packet::IPv4;
   use Net::Packet::Consts qw(:ipv4);

   # Build layer to inject to network
   my $ip = Net::Packet::IPv4->new(
      flags => NP_IPv4_DONT_FRAGMENT,
      dst   => "192.168.0.1",
   );

   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $ip2 = Net::Packet::IPv4->new(raw => $rawFromNetwork);

   print $ip->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the IPv4 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc791.txt
      
See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<id>

IP ID of the datagram.

=item B<ttl>

Time to live.

=item B<src>

=item B<dst>

Source and destination IP addresses.

=item B<protocol>

Of which type the layer 4 is.

=item B<checksum>

IP checksum.

=item B<flags>

IP Flags.

=item B<version>

IP version, here it is 4.

=item B<tos>

Type of service flag.

=item B<length>

Total length in bytes of the packet, including IP headers (that is, layer 3 + layer 4 + layer 7).

=item B<hlen>

Header length in number of words, including IP options.

=item B<options>

IP options, as a hexadecimal string.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

version:  4

tos:      0

id:       getRandom16bitsInt()

length:   0

hlen:     0

flags:    0

ttl:      128

protocol: NP_IPv4_PROTOCOL_TCP

checksum: 0

src:      $Env->ip

dst:      "127.0.0.1"

options:  ""

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1
 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getHeaderLength>

Returns the header length in bytes, not including IP options.

=item B<getPayloadLength>

Returns the length in bytes of encapsulated layers (that is, layer 4 + layer 7).

=item B<getOptionsLength>

Returns the length in bytes of IP options.

=item B<haveFlagDf>

=item B<haveFlagMf>

=item B<haveFlagRf>

Returns 1 if the specified flag is set in B<flags> attribute, 0 otherwise.

=item B<isProtocolTcp>

=item B<isProtocolUdp>

=item B<isProtocolIcmpv4>

Returns 1 if the specified protocol is used at layer 4, 0 otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:ipv4);

=over 4

=item B<NP_IPv4_PROTOCOL_TCP>

=item B<NP_IPv4_PROTOCOL_UDP>

=item B<NP_IPv4_PROTOCOL_ICMPv4>

Various protocol type constants.

=item B<NP_IPv4_MORE_FRAGMENT>

=item B<NP_IPv4_DONT_FRAGMENT>

=item B<NP_IPv4_RESERVED_FRAGMENT>

Various possible flags.

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

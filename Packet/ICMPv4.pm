package Net::Packet::ICMPv4;

# $Date: 2005/02/01 16:29:16 $
# $Revision: 1.2.2.26 $

use strict;
use warnings;

require Net::Packet::Layer4;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Layer4 Class::Gomor::Hash);

use Net::Packet::Utils qw(getRandom16bitsInt getRandom32bitsInt inetChecksum
   getHostIpv4Addr inetAton inetNtoa);
use Net::Packet::Consts qw(:icmpv4 :layer);
require Net::Packet::IPv4;
require Net::Packet::Frame;

require Net::Packet;
our $VERSION = $Net::Packet::VERSION;

our @AS = qw(
   type
   code
   checksum
   identifier
   sequenceNumber
   originateTimestamp
   receiveTimestamp
   transmitTimestamp
   addressMask
   gateway
   unused
   error
   data
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      type               => NP_ICMPv4_TYPE_ECHO_REQUEST,
      code               => NP_ICMPv4_CODE_ZERO,
      checksum           => 0,
      identifier         => getRandom16bitsInt(),
      sequenceNumber     => getRandom16bitsInt(),
      originateTimestamp => time(),
      receiveTimestamp   => 0,
      transmitTimestamp  => 0,
      addressMask        => 0,
      gateway            => "127.0.0.1",
      unused             => 0,
      data               => "",
      @_,
   );

   $self->gateway(getHostIpv4Addr($self->gateway));

   unless ($self->raw) {
      #�This line handles the packing of ICMPv4 Destination unreach IPv4 Frame
      $self->data($self->error->raw) if $self->error;
   }

   $self;
}

sub getKey        { 'ICMP' }
sub getKeyReverse { 'ICMP' }

sub recv {
   my $self  = shift;
   my $frame = shift;

   my $env = $frame->env;

   for ($env->dump->frames) {
      next unless $_->timestamp ge $frame->timestamp;

      if ($frame->l3) {
         if ($_->isIcmpv4 && $_->l3->src eq $frame->l3->dst) {
            if ($self->type  == NP_ICMPv4_TYPE_ECHO_REQUEST
            &&  $_->l4->type == NP_ICMPv4_TYPE_ECHO_REPLY) {
               return $_;
            }
            elsif ($self->type  == NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
               &&  $_->l4->type == NP_ICMPv4_TYPE_TIMESTAMP_REPLY) {
               return $_;
            }
            elsif ($self->type  == NP_ICMPv4_TYPE_INFORMATION_REQUEST
               &&  $_->l4->type == NP_ICMPv4_TYPE_INFORMATION_REPLY) {
               return $_;
            }
            elsif ($self->type  == NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
               &&  $_->l4->type == NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
               return $_;
            }
         }
      }
      # DescL4 recv, warning, ay receive a packet targetted at another
      #�host, since no L3 headers is kept at D4 for packet matching
      else {
         if ($self->type  == NP_ICMPv4_TYPE_ECHO_REQUEST
         &&  $_->l4->type == NP_ICMPv4_TYPE_ECHO_REPLY) {
               return $_;
         }
         elsif ($self->type  == NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
            &&  $_->l4->type == NP_ICMPv4_TYPE_TIMESTAMP_REPLY) {
            return $_;
         }
         elsif ($self->type  == NP_ICMPv4_TYPE_INFORMATION_REQUEST
            &&  $_->l4->type == NP_ICMPv4_TYPE_INFORMATION_REPLY) {
            return $_;
         }
         elsif ($self->type  == NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
            &&  $_->l4->type == NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
            return $_;
         }
      }
   }

   undef;
}

my $packTypes = {
   NP_ICMPv4_TYPE_ECHO_REQUEST()            => \&_packEcho,
   NP_ICMPv4_TYPE_ECHO_REPLY()              => \&_packEcho,
   NP_ICMPv4_TYPE_TIMESTAMP_REQUEST()       => \&_packTimestamp,
   NP_ICMPv4_TYPE_TIMESTAMP_REPLY()         => \&_packTimestamp,
   NP_ICMPv4_TYPE_INFORMATION_REQUEST()     => \&_packInformation,
   NP_ICMPv4_TYPE_INFORMATION_REPLY()       => \&_packInformation,
   NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST()    => \&_packAddressMask,
   NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY()      => \&_packAddressMask,
   NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE() => \&_packDestUnreach,
   NP_ICMPv4_TYPE_REDIRECT()                => \&_packRedirect,
   NP_ICMPv4_TYPE_TIME_EXCEEDED()           => \&_packTimeExceed,
};

my $unpackTypes = {
   NP_ICMPv4_TYPE_ECHO_REQUEST()            => \&_unpackEcho,
   NP_ICMPv4_TYPE_ECHO_REPLY()              => \&_unpackEcho,
   NP_ICMPv4_TYPE_TIMESTAMP_REQUEST()       => \&_unpackTimestamp,
   NP_ICMPv4_TYPE_TIMESTAMP_REPLY()         => \&_unpackTimestamp,
   NP_ICMPv4_TYPE_INFORMATION_REQUEST()     => \&_unpackInformation,
   NP_ICMPv4_TYPE_INFORMATION_REPLY()       => \&_unpackInformation,
   NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST()    => \&_unpackAddressMask,
   NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY()      => \&_unpackAddressMask,
   NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE() => \&_unpackDestUnreach,
   NP_ICMPv4_TYPE_REDIRECT()                => \&_unpackRedirect,
   NP_ICMPv4_TYPE_TIME_EXCEEDED()           => \&_unpackTimeExceed,
};

sub getDataLength { my $self = shift; $self->data ? length($self->data) : 0 }

sub getLength {
   my $self = shift;

   my $dataLength = $self->getDataLength;

   my $hdrLengths = {
      NP_ICMPv4_TYPE_ECHO_REQUEST()            => 8  + $dataLength,
      NP_ICMPv4_TYPE_ECHO_REPLY()              => 8  + $dataLength,
      NP_ICMPv4_TYPE_TIMESTAMP_REQUEST()       => 20 + $dataLength,
      NP_ICMPv4_TYPE_TIMESTAMP_REPLY()         => 20 + $dataLength,
      NP_ICMPv4_TYPE_INFORMATION_REQUEST()     => 8  + $dataLength,
      NP_ICMPv4_TYPE_INFORMATION_REPLY()       => 8  + $dataLength,
      NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST()    => 12 + $dataLength,
      NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY()      => 12 + $dataLength,
      NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE() => 8  + $dataLength,
      NP_ICMPv4_TYPE_REDIRECT()                => 8  + $dataLength,
      NP_ICMPv4_TYPE_TIME_EXCEEDED()           => 8  + $dataLength,
   };

   $hdrLengths->{$self->type} || 0;
}

sub _handleType {
   my $self = shift;
   my ($format, $fields, $values) = @_;

   if (@$values) {
      return ($self->SUPER::pack($format, @$values) or undef);
   }
   else {
      my @elts = $self->SUPER::unpack($format, $self->payload)
         or return undef;
      my $n = 0;
      return { map { $_ => $elts[$n++] } @$fields };
   }
}

sub _packEcho {
   my $self = shift;
   $self->_handleType('nn', [], [ $self->identifier, $self->sequenceNumber ]);
}

sub _unpackEcho {
   shift->_handleType('nn a*', [ qw(identifier sequenceNumber data) ], []);
}

sub _packTimestamp {
   my $self = shift;
   $self->_handleType(
      'nnNNN',
      [],
      [ $self->identifier, $self->sequenceNumber, $self->originateTimestamp,
        $self->receiveTimestamp, $self->transmitTimestamp ],
   );
}

sub _unpackTimestamp {
   shift->_handleType(
      'nnNNN a*',
      [ qw(identifier sequenceNumber originateTimestamp receiveTimestamp
           transmitTimestamp data) ],
      [],
   );
}

#�It has same fields as ICMP echo
sub _packInformation   { shift->_packEcho   }
sub _unpackInformation { shift->_unpackEcho }

sub _packAddressMask {
   my $self = shift;
   $self->_handleType(
      'nnN',
      [],
      [ $self->identifier, $self->sequenceNumber, $self->addressMask ],
   );
}

sub _unpackAddressMask {
   shift->_handleType(
      'nnN a*',
      [ qw(identifier sequenceNumber addressMask data) ],
      [],
   );
}

#�Pad ICMP error returned to achieve IP length (from IP request),
#�and put it as a Frame into error instance data
sub _dataToFrame {
   my $data  = shift;
   my $ip = Net::Packet::IPv4->new(raw => $data);
   $data .= "\x00" x $ip->length;
   Net::Packet::Frame->new(raw => $data) or return undef;
}

sub _packDestUnreach {
   my $self = shift;
   $self->_handleType(
      'N',
      [],
      [ $self->unused ],
   );
}

sub _unpackDestUnreach {
   my $href = shift->_handleType(
      'N a*',
      [ qw(unused data) ],
      [],
   );
   $href->{error} = _dataToFrame($href->{data}) if $href->{data};
   $href;
}

sub _packRedirect {
   my $self = shift;
   $self->_handleType(
      'a4',
      [],
      [ inetAton($self->gateway) ],
   );
}

sub _unpackRedirect {
   my $href = shift->_handleType(
      'a4 a*',
      [ qw(gateway data) ],
      [],
   );
   $href->{gateway} = inetNtoa($href->{gateway});
   $href->{error} = _dataToFrame($href->{data}) if $href->{data};
   $href;
}

sub _packTimeExceed {
   my $self = shift;
   $self->_handleType(
      'N',
      [],
      [ $self->unused ],
   );
}

sub _unpackTimeExceed {
   my $href = shift->_handleType(
      'N a*',
      [ qw(unused data) ],
      [],
   );
   $href->{error} = _dataToFrame($href->{data}) if $href->{data};
   $href;
}

sub _decodeError {
   my $self = shift;
   warn("@{[(caller(0))[3]]}: unknown ICMPv4: ".
        "type: @{[$self->type]}, code: @{[$self->code]}\n");
   undef;
}

sub pack {
   my $self = shift;

   $self->raw(
      $self->SUPER::pack('CCn',
         $self->type,
         $self->code,
         $self->checksum,
      ),
   ) or return undef;

   my $sub = $packTypes->{$self->type} || \&_decodeError;
   my $raw = $self->$sub or return undef;

   if ($self->data) {
      $raw .= $self->SUPER::pack('a*', $self->data)
         or return undef;
   }

   $self->raw($self->raw. $raw);

   1;
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) =
      $self->SUPER::unpack('CCS a*', $self->raw)
         or return undef;

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);
   $self->payload($payload);

   # unpack specific ICMPv4 types
   my $sub = $unpackTypes->{$self->type} || \&_decodeError;
   my $href = $self->$sub or return undef;

   $self->$_($href->{$_}) for keys %$href;

   #�payload has been handled by previous chunk of code
   $self->payload(undef);

   1;
}

sub computeChecksums {
   my $self = shift;

   my $sub = $packTypes->{$self->type} || \&_decodeError;
   my $raw = $self->$sub or return undef;

   if ($self->data) {
      $raw .= $self->SUPER::pack('a*', $self->data)
         or return undef;
   }

   my $packed = $self->SUPER::pack('CCn', $self->type, $self->code, 0)
      or return undef;

   $self->checksum(inetChecksum($packed. $raw));

   1;
}

sub encapsulate { NP_LAYER_NONE }

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   my $buf = sprintf
      "$l:+$i: type:%d  code:%d  checksum:0x%.4x  size:%d",
         $self->type,
         $self->code,
         $self->checksum,
         $self->getLength,
   ;

   if ($self->data) {
      $buf .= sprintf("\n$l: $i: dataLength:%d  data:%s",
                      $self->getDataLength,
                      $self->SUPER::unpack('H*', $self->data))
         or return undef;
   }

   $buf;
}

#
# Helpers
#

sub _isType                { shift->type == shift()                      }
sub isTypeEchoRequest      { shift->_isType(NP_ICMPv4_TYPE_ECHO_REQUEST) }
sub isTypeEchoReply        { shift->_isType(NP_ICMPv4_TYPE_ECHO_REPLY)   }
sub isTypeTimestampRequest {
   shift->_isType(NP_ICMPv4_TYPE_TIMESTAMP_REQUEST);
}
sub isTypeTimestampReply {
   shift->_isType(NP_ICMPv4_TYPE_TIMESTAMP_REPLY);
}
sub isTypeInformationRequest {
   shift->_isType(NP_ICMPv4_TYPE_INFORMATION_REQUEST);
}
sub isTypeInformationReply {
   shift->_isType(NP_ICMPv4_TYPE_INFORMATION_REPLY);
}
sub isTypeAddressMaskRequest {
   shift->_isType(NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST);
}
sub isTypeAddressMaskReply {
   shift->_isType(NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY);
}
sub isTypeDestinationUnreachable {
   shift->_isType(NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE);
}

1;

__END__

=head1 NAME

Net::Packet::ICMPv4 - Internet Control Message Protocol v4 layer 4 object

=head1 SYNOPSIS

   use Net::Packet::ICMPv4;
   use Net::Packet::Consts qw(:icmpv4);

   # Build echo-request header
   my $echo = Net::Packet::ICMPv4->new(data => '0123456789');

   # Build information-request header
   my $info = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_INFORMATION_REQUEST,
      data => '0123456789',
   );

   # Build address-mask request header
   my $mask = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST,
      data => '0123456789',
   );

   # Build timestamp request header
   my $timestamp = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_TIMESTAMP_REQUEST,
      data => '0123456789',
   );


   # Decode from network to create the object
   # Usually, you do not use this, it is used by Net::Packet::Frame
   my $decode = Net::Packet::ICMPv4->new(raw => $rawFromNetwork);

   print $echo->print, "\n";

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv4 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc792.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes a
nd methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

=item B<code>

Type and code fields. See B<CONSTANTS>.

=item B<checksum>

The checksum of ICMPv4 header.

=item B<identifier>

Identification number.

=item B<sequenceNumber>

Sequence number.

=item B<originateTimestamp>

=item B<receiveTimestamp>

=item B<transmitTimestamp>

Three timestamps used by the B<NP_ICMPv4_TYPE_TIMESTAMP_REQUEST> message.

=item B<addressMask>

Used by the B<NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST> message.

=item B<gateway>

Used by the B<NP_ICMPv4_TYPE_REDIRECT> message.

=item B<unused>

Zero value field used in various ICMP messages.

=item B<error>

A pointer to a B<Net::Packet::Frame> object, usually set when an ICMP error message has been returned.

=item B<data>

Additionnal data can be added to an ICMP message, traditionnaly used in B<NP_ICMPv4_TYPE_ECHO_REQUEST>.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

type:               NP_ICMPv4_TYPE_ECHO_REQUEST

code:               NP_ICMPv4_CODE_ZERO

checksum:           0

identifier:         getRandom16bitsInt()

sequenceNumber:     getRandom16bitsInt()

originateTimestamp: time()

receiveTimestamp:   0

transmitTimestamp:  0

addressMask:        0

gateway:            "127.0.0.1"

unused:             0

data:               ""

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<getDataLength>

Returns the length in bytes of B<data> attribute.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isTypeEchoRequest>

=item B<isTypeEchoReply>

=item B<isTypeTimestampRequest>

=item B<isTypeTimestampReply>

=item B<isTypeInformationRequest>

=item B<isTypeInformationReply>

=item B<isTypeAddressMaskRequest>

=item B<isTypeAddressMaskReply>

=item B<isTypeDestinationUnreachable>

Returns 1 if the B<type> attribute is of specified type.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:icmpv4);

=over 4

=item B<NP_ICMPv4_CODE_ZERO>

ICMP code zero, used by various ICMP messages.

=item B<NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE>

=item B<NP_ICMPv4_CODE_NETWORK>

=item B<NP_ICMPv4_CODE_HOST>

=item B<NP_ICMPv4_CODE_PROTOCOL>

=item B<NP_ICMPv4_CODE_PORT>

=item B<NP_ICMPv4_CODE_FRAGMENTATION_NEEDED>

=item B<NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED>

Destination unreachable type, with possible code numbers.

=item B<NP_ICMPv4_TYPE_REDIRECT>

=item B<NP_ICMPv4_CODE_FOR_NETWORK>

=item B<NP_ICMPv4_CODE_FOR_HOST>

=item B<NP_ICMPv4_CODE_FOR_TOS_AND_NETWORK>

=item B<NP_ICMPv4_CODE_FOR_TOS_AND_HOST>

Redirect type message, with possible code numbers.

=item B<NP_ICMPv4_TYPE_TIME_EXCEEDED>

=item B<NP_ICMPv4_CODE_TTL_IN_TRANSIT>

=item B<NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY>

Time exceeded message, with possible code numbers.

=item B<NP_ICMPv4_TYPE_ECHO_REQUEST>

=item B<NP_ICMPv4_TYPE_ECHO_REPLY>

=item B<NP_ICMPv4_TYPE_TIMESTAMP_REQUEST>

=item B<NP_ICMPv4_TYPE_TIMESTAMP_REPLY>

=item B<NP_ICMPv4_TYPE_INFORMATION_REQUEST>

=item B<NP_ICMPv4_TYPE_INFORMATION_REPLY>

=item B<NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST>

=item B<NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY>

Other request/reply ICMP messages types.

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

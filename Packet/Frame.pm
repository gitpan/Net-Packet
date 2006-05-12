#
# $Id: Frame.pm,v 1.2.2.58 2006/04/25 20:56:19 gomor Exp $
#
package Net::Packet::Frame;

use warnings;
use strict;
use Carp;

require Class::Gomor::Hash;
our @ISA = qw(Class::Gomor::Hash);

require Net::Packet;
require Net::Packet::Dump;
require Net::Packet::ETH;
require Net::Packet::ARP;
require Net::Packet::IPv4;
require Net::Packet::IPv6;
require Net::Packet::TCP;
require Net::Packet::UDP;
require Net::Packet::ICMPv4;
require Net::Packet::Layer7;
require Net::Packet::NULL;
require Net::Packet::RAW;
require Net::Packet::SLL;

use Time::HiRes qw(time);
use Net::Packet qw($Env);
use Net::Packet::Consts qw(:dump :layer :arp);

our @AS = qw(
   env
   raw
   padding
   l2
   l3
   l4
   l7
   reply
   timestamp
   noPadding
);

__PACKAGE__->cgBuildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      timestamp => time(),
      env       => $Env,
      noPadding => 0,
      @_,
   );

   my $env = $self->env;

   unless ($env->desc) {
      if ($self->l2) {
         require Net::Packet::DescL2;
         $env->desc(Net::Packet::DescL2->new);
         $self->cgDebugPrint(1, "DescL2 object created");
      }
      elsif ($self->l3) {
         require Net::Packet::DescL3;
         $env->desc(Net::Packet::DescL3->new(target => $self->l3->dst));
         $self->cgDebugPrint(1, "DescL3 object created");
      }
      elsif ($self->l4) {
         croak("You must manually create a DescL4 object\n");
      }
   }

   unless ($env->dump) {
      require Net::Packet::Dump;
      $env->dump(
         Net::Packet::Dump->new(
            filter    => $Env->filter || $self->getFilter,
            callStart => 0,
         ),
      );
      $self->cgDebugPrint(1, "Dump object created");
   }

   $self->raw ? $self->unpack : $self->pack;
}

sub getLengthFromL7 { my $self = shift; $self->l7 ? $self->l7->getLength : 0 }
sub getLengthFromL4 {
   my $self = shift;
   my $len  = 0;
   $len    += $self->l4->getLength if $self->l4;
   $len    += $self->getLengthFromL7;
   $len || 0;
}
sub getLengthFromL3 {
   my $self = shift;
   my $len  = 0;
   $len    += $self->l3->getLength if $self->l3;
   $len    += $self->getLengthFromL4;
   $len || 0;
}
sub getLengthFromL2 {
   my $self = shift;
   my $len  = 0;
   $len    += $self->l2->getLength if $self->l2;
   $len    += $self->getLengthFromL3;
   $len || 0;
}
sub getLength { shift->getLengthFromL3 }

sub _unpackFromL3 {
   my $self = shift;

   my $nextLayer;
   while (1) {
      my $l3;

      # First, try IPv4
      $l3 = Net::Packet::IPv4->new(raw => $self->raw) or return undef;
      unless ($l3->version == 4) {
         # Then IPv6
         $l3 = Net::Packet::IPv6->new(raw => $self->raw) or return undef;
         unless ($l3->version == 6) {
            # Then ARP
            $l3 = Net::Packet::ARP->new(raw => $self->raw) or return undef;
            unless ($l3->hType eq NP_ARP_HTYPE_ETH) {
               carp("@{[(caller(0))[3]]}: unknown frame, unable to unpack\n");
               return undef;
            }
         }
      }

      if ($l3->encapsulate eq NP_LAYER_UNKNOWN) {
         carp("@{[(caller(0))[3]]}: unknown Layer4 protocol\n");
         last;
      }

      $self->l3($l3);

      last if $self->l3->encapsulate eq NP_LAYER_NONE;
      $nextLayer = NP_LAYER. $self->l3->encapsulate;

      $self->l4($nextLayer->new(raw => $self->l3->payload))
         or return undef;

      # Here, no check; it is just raw layer 7 application data
      last if $self->l4->encapsulate eq NP_LAYER_NONE;
      $nextLayer = NP_LAYER. $self->l4->encapsulate;

      $self->l7($nextLayer->new(raw => $self->l4->payload))
         or return undef;
   
      last;
   }

   $self;
}

sub unpack {
   my $self = shift;

   my $whichLink = {
      NP_DUMP_LINK_NULL()   =>
         sub { Net::Packet::NULL->new(raw => $self->raw) },
      NP_DUMP_LINK_EN10MB() =>
         sub { Net::Packet::ETH->new(raw => $self->raw)  },
      NP_DUMP_LINK_RAW()    =>
         sub { Net::Packet::RAW->new(raw => $self->raw)  },
      NP_DUMP_LINK_SLL()    =>
         sub { Net::Packet::SLL->new(raw => $self->raw)  },
   };

   my $nextLayer;
   while (1) {
      unless (exists $whichLink->{$self->env->link}) {
         carp("Unable to unpack Frame for this datalink type: ".
              "@{[$self->env->link]}\n");
         last;
      }

      my $l2 = $whichLink->{$self->env->link}() or return undef;

      $self->l2($l2);

      # For example, with a raw Datalink type (RAW.pm),
      # we don't know what is encapsulated
      if ($self->l2->encapsulate eq NP_LAYER_UNKNOWN) {
         return $self->_unpackFromL3;
      }

      last if $self->l2->encapsulate eq NP_LAYER_NONE;
      $nextLayer = NP_LAYER. $self->l2->encapsulate;

      $self->l3($nextLayer->new(raw => $l2->payload))
         or return undef;

      if ($self->l3->encapsulate eq NP_LAYER_UNKNOWN) {
         carp("@{[(caller(0))[3]]}: unknown Layer4 protocol\n");
         last;
      }

      $self->_fixWithIpLen  if $self->isIpv4;
      $self->_getArpPadding if $self->isArp;

      last if $self->l3->encapsulate eq NP_LAYER_NONE;
      $nextLayer = NP_LAYER. $self->l3->encapsulate;

      $self->l4($nextLayer->new(raw => $self->l3->payload))
         or return undef;

      last if $self->l4->encapsulate eq NP_LAYER_NONE;
      $nextLayer = NP_LAYER. $self->l4->encapsulate;

      $self->l7($nextLayer->new(raw => $self->l4->payload))
         or return undef;

      last;
   }

   $self;
}

sub pack {
   my $self = shift;

   # They all need info about other layers, to do their work
   if ($self->l2) {
      $self->l2->computeLengths($self)   or return undef;
      $self->l2->computeChecksums($self) or return undef;
      $self->l2->pack                    or return undef;
   }
   if ($self->l3) {
      $self->l3->computeLengths($self)   or return undef;
      $self->l3->computeChecksums($self) or return undef;
      $self->l3->pack                    or return undef;
   }
   if ($self->l4) {
      $self->l4->computeLengths($self)   or return undef;
      $self->l4->computeChecksums($self) or return undef;
      $self->l4->pack                    or return undef;
   }
   if ($self->l7) {
      $self->l7->computeLengths($self)   or return undef;
      $self->l7->computeChecksums($self) or return undef;
      $self->l7->pack                    or return undef;
   }

   my $raw;
   $raw .= $self->l2->raw if $self->l2;
   $raw .= $self->l3->raw if $self->l3;
   $raw .= $self->l4->raw if $self->l4;
   $raw .= $self->l7->raw if $self->l7;

   if ($raw) {
      $self->raw($raw);

      $self->_padFrame unless $self->noPadding;
   }

   $self;
}

sub _padFrame {
   my $self = shift;

   # Pad this frame, this we send at layer 2
   if ($self->l2 && $self->env->desc->isDescL2) {
      my $rawLength = length($self->raw);
      if ($rawLength < 60) {
         $self->padding("G" x (60 - $rawLength));
         $self->raw($self->raw. $self->padding);
      }
   }
}

# Will wipe out the trailing memory disclosure found in the packet
# and put it into padding instance data
sub _fixWithIpLen {
   my $self   = shift;
   my $oldLen = length($self->l3->payload);

   my $truncated = substr($self->l3->payload, 0, $self->l3->getPayloadLength);
   my $truncLen  = length($truncated);
   my $padding   = substr($self->l3->payload, $truncLen, $oldLen - $truncLen);

   $self->l3->payload($truncated);
   $self->padding($padding);
}

# Same as previous, but ARP version
sub _getArpPadding {
   my $self = shift;

   if (length($self->raw) > 42) {
      $self->padding(substr($self->raw, 42, length($self->raw) - 42));
   }
}

sub send {
   my $self = shift;

   my $env = $self->env;

   if ($env->dump && ! $env->dump->isRunning) {
      $env->dump->start;
      $self->cgDebugPrint(1, "Dump object started");
   }

   if ($env->debug >= 3) {
      if ($self->isEth) {
         $self->cgDebugPrint(3,
            "send: l2: type:". sprintf("0x%x", $self->l2->type). ", ".
            "@{[$self->l2->src]} => @{[$self->l2->dst]}"
         );
      }

      if ($self->isIp) {
         $self->cgDebugPrint(3,
            "send: l3: protocol:@{[$self->l3->protocol]}, ".
            "size:@{[$self->getLength]}, ".
            "@{[$self->l3->src]} => @{[$self->l3->dst]}"
         );
      }
      elsif ($self->isArp) {
         $self->cgDebugPrint(3,
            "send: l3: @{[$self->l3->src]} => @{[$self->l3->dst]}"
         );
      }

      if ($self->isTcp || $self->isUdp) {
         $self->cgDebugPrint(3,
            "send: l4: @{[$self->l4->is]}, ".
            "@{[$self->l4->src]} => @{[$self->l4->dst]}"
         );
      }
   }

   $self->timestamp(time());
   $env->desc->send($self->raw);
}

sub reSend { my $self = shift; $self->send unless $self->reply }

sub getFilter {
   my $self = shift;

   my $filter;

   # L4 filtering
   if ($self->l4) {
      if ($self->isTcp) {
         $filter .= "(tcp and".
                    " src port @{[$self->l4->dst]}".
                    " and dst port @{[$self->l4->src]})";
      }
      elsif ($self->isUdp) {
         $filter .= "(udp and".
                    " src port @{[$self->l4->dst]}".
                    " and dst port @{[$self->l4->src]})";
      }
      elsif ($self->isIcmpv4) {
         $filter .= "(icmp)";
      }
      $filter .= " or icmp";
   }

   # L3 filtering
   if ($self->l3) {
      $filter .= " and " if $filter;

      if ($self->isIpv4) {
         $filter .= "(src host @{[$self->l3->dst]}".
                    " and dst host @{[$self->l3->src]}) ".
                    " or ".
                    "(icmp and dst host @{[$self->l3->src]})";
      }
      elsif ($self->isIpv6) {
         $filter .= "(ip6 and src host @{[$self->l3->dst]}".
                    " and dst host @{[$self->l3->src]})";
      }
      elsif ($self->isArp) {
         $filter .= "(arp and src host @{[$self->l3->dstIp]}".
                    " and dst host @{[$self->l3->srcIp]})";
      }
   }
    
   $filter;
}

sub recv {
   my $self = shift;

   $self->env->dump->nextAll if $self->env->dump->isRunning;

   # We already have the reply
   return undef if $self->reply;

   croak("@{[(caller(0))[3]]}: \$self->env->dump variable not set\n")
      unless $self->env->dump;

   if ($self->l4 && $self->l4->can('recv')) {
      $self->reply($self->l4->recv($self));
   }
   elsif ($self->l3 && $self->l3->can('recv')) {
      $self->reply($self->l3->recv($self));
   }
   else {
      carp("@{[(caller(0))[3]]}: not implemented for this Layer\n");
   }

   $self->reply
      ? do { $self->cgDebugPrint(1, "Reply received"); return $self->reply }
      : return undef;
}

#
# Helpers
#

sub _isL2 { my $self = shift; $self->l2 && $self->l2->is eq shift() }
sub _isL3 { my $self = shift; $self->l3 && $self->l3->is eq shift() }
sub _isL4 { my $self = shift; $self->l4 && $self->l4->is eq shift() }
sub _isL7 { my $self = shift; $self->l7 && $self->l7->is eq shift() }
sub isEth    { shift->_isL2(NP_LAYER_ETH)    }
sub isRaw    { shift->_isL2(NP_LAYER_RAW)    }
sub isNull   { shift->_isL2(NP_LAYER_NULL)   }
sub isSll    { shift->_isL2(NP_LAYER_SLL)    }
sub isArp    { shift->_isL3(NP_LAYER_ARP)    }
sub isIpv4   { shift->_isL3(NP_LAYER_IPv4)   }
sub isIpv6   { shift->_isL3(NP_LAYER_IPv6)   }
sub isVlan   { shift->_isL3(NP_LAYER_VLAN)   }
sub isTcp    { shift->_isL4(NP_LAYER_TCP)    }
sub isUdp    { shift->_isL4(NP_LAYER_UDP)    }
sub isIcmpv4 { shift->_isL4(NP_LAYER_ICMPv4) }
sub is7      { shift->_isL7(NP_LAYER_7)      }
sub isIp     { my $self = shift; $self->isIpv4 || $self->isIpv6 }
sub isIcmp   { my $self = shift; $self->isIcmpv4 } # XXX: || v6

1;

__END__

=head1 NAME

Net::Packet::Frame - the core of Net::Packet framework

=head1 SYNOPSIS

   use Net::Packet::Frame;

   # Since we passed a layer 3 object, a Net::Packet::DescL3 object 
   # will be created
   my $frame = Net::Packet::Frame->new(
      l3 => $ipv4,  # Net::Packet::IPv4 object
      l4 => $tcp,   # Net::Packet::TCP object
                    # (here, a SYN request, for example)
   );

   # Without retries
   $frame->send;
   sleep(3);
   if ($frame->recv) {
      print $frame->reply->l3, "\n";
      print $frame->reply->l4, "\n";
   }

   # Or with retries
   for (1..3) {
      $frame->reSend;

      until ($Env->dump->timeout) {
         if ($frame->recv) {
            print $frame->reply->l3, "\n";
            print $frame->reply->l4, "\n";
            last;
         }
      }
   }

=head1 DESCRIPTION

In B<Net::Packet>, each sent and/or received frame is parsed and converted into a B<Net::Packet::Frame> object. Basically, it encapsulates various layers (2, 3, 4 and 7) into an object, making it easy to get or set information about it.

When you create a frame object, a B<Net::Packet::Desc> object is created if none is found in the default B<$Env> object (from B<Net::Packet> module), and a B<Net::Packet::Dump> object is also created if none is found in this same B<$Env> object.

Two B<new> invocation method exist, one with attributes passing, another with B<raw> attribute. This second method is usually used internally, in order to unpack received frame into all corresponding layers.

=head1 ATTRIBUTES

=over 4

=item B<env>

Stores the B<Net::Packet::Env> object. The default is to use B<$Env> from B<Net::Packet>. So, you can send/recv frames to/from different environements.

=item B<raw>

Pass this attribute when you want to decode a raw string captured from network. Usually used internally.

=item B<padding>

In Ethernet world, a frame should be at least 60 bytes in length. So when you send frames at layer 2, a padding is added in order to achieve this length, avoiding a local memory leak to network. Also, when you receive a frame from network, this attribute is filled with what have been used to pad it. This padding feature currently works for IPv4 and ARP frames.

=item B<l2>

Stores a layer 2 object. See B<Net::Packet> for layer 2 classes hierarchy.

=item B<l3>

Stores a layer 3 object. See B<Net::Packet> for layer 3 classes hierarchy.

=item B<l4>

Stores a layer 4 object. See B<Net::Packet> for layer 4 classes hierarchy.

=item B<l7>

Stores a layer 7 object. See B<Net::Packet::Layer7>.

=item B<reply>

When B<recv> method has been called on a frame object, and a corresponding reply has been catched, a pointer is stored in this attribute.

=item B<timestamp>

When a frame is packed/unpacked, the happening time is stored here.

=item B<noPadding>

Frames are normally automatically padded to achieve the minimum required length. Set it to 1 to avoid padding. Default is to pad the frame.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. If a B<$Env->desc> object does not exists, one is created by analyzing attributes (so, either one of B<Net::Packet::DescL2>, B<Net::Packet::DescL3>. B<Net::Packet::DescL4> cannot be created automatically for now). The same behavious is true for B<$Env->dump> object. Default values:

timestamp: time(),

env:       $Env

=item B<getLengthFromL7>

=item B<getLengthFromL4>

=item B<getLengthFromL3>

=item B<getLengthFromL2>

Returns the raw length in bytes from specified layer.

=item B<getLength>

Alias for B<getLengthFromL3>.

=item B<unpack>

Unpacks the raw string from network into various layers. Returns 1 on success, undef on failure.

=item B<pack>

Packs various layers into the raw string to send to network. Returns 1 on success, undef on failure.

=item B<send>

On the first send invocation in your program, the previously created B<Net::Packet::Dump> object is started (if available). That is, packet capturing is run. The B<timestamp> attribute is set to the sending time. The B<env> attribute is used to know where to send this frame.

=item B<reSend>

Will call B<send> method if no frame has been B<recv>'d, that is the B<reply> attribute is undef.

=item B<getFilter>

Will return a string which is a pcap filter, and corresponding to what you should receive compared with the frame request.

=item B<recv>

Searches B<framesSorted> or B<frames> from B<Net::Packet::Dump> for a matching response. If a reply has already been received (that is B<reply> attribute is already set), undef is returned. It no reply is received, return undef, else the B<Net::Packet::Frame> response.

=item B<isEth>

=item B<isRaw>

=item B<isNull>

=item B<isSll>

=item B<isArp>

=item B<isIpv4>

=item B<isIpv6>

=item B<isIp> - either IPv4 or IPv6

=item B<isVlan>

=item B<isTcp>

=item B<isUdp>

=item B<isIcmpv4>

=item B<isIcmp> - currently only ICMPv4

=item B<is7>

Returns 1 if the B<Net::Packet::Frame> is of specified layer, 0 otherwise.

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

package Net::Packet::Simple;

# $Date: 2004/09/29 16:42:48 $
# $Revision: 1.1.1.1 $

use strict;
use warnings;
use Carp;

use Net::Packet::ETH qw(/NETPKT_*/);
use Net::Packet::ARP qw(/NETPKT_*/);
use Net::Packet::IPv4 qw(/NETPKT_*/);
use Net::Packet::TCP qw(/NETPKT_*/);
use Net::Packet::Layer7 qw(/NETPKT_*/);
use Net::Packet::Frame;

sub tcpSyn {
   my $self = shift;
   my $args = { @_ };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         " [ ipSrc   => IP, ]\n".
         "   ipDst   => IP,\n".
         "   dstPort => PORT,\n".
         ");\n".
         "")
      unless $args->{ipDst}
          && $args->{dstPort}
   ;

   my $ip = Net::Packet::IPv4->new(
      src => $args->{ipSrc},
      dst => $args->{ipDst},
   );

   my $tcp = Net::Packet::TCP->new(
      dst   => $args->{dstPort},
      flags => NETPKT_TCP_FLAG_SYN,
   );

   Net::Packet::Frame->new(l3 => $ip, l4 => $tcp);
}

sub arpRequest {
   my $self = shift;
   my $args = {
      broadcast => undef,
      @_,
   };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         "   tellMac => MAC,\n".
         "   toMac   => MAC or 'broadcast',\n".
         "   tell    => IP,\n".
         "   whoHas  => IP,\n".
         ");\n".
         "")
      unless $args->{tellMac}
          && $args->{toMac}
          && $args->{tell}
          && $args->{whoHas}
   ;

   my $eth = Net::Packet::ETH->new(
      src => $args->{tellMac},
      dst => $args->{toMac} =~ /broadcast/i ? NETPKT_ETH_ADDR_BROADCAST
                                            : $args->{toMac},
      type => NETPKT_ETH_TYPE_ARP,
   );

   my $arp = Net::Packet::ARP->new(   
      hType  => NETPKT_ARP_HTYPE_ETH,
      pType  => NETPKT_ARP_PTYPE_IPv4,
      hSize  => NETPKT_ARP_HSIZE_ETH,
      pSize  => NETPKT_ARP_PSIZE_IPv4,
      opCode => NETPKT_ARP_OPCODE_REQUEST,
      src    => $args->{tellMac},
      srcIp  => $args->{tell},
      dst    => $args->{toMac} =~ /broadcast/i ? NETPKT_ARP_ADDR_BROADCAST
                                               : $args->{toMac},
      dstIp => $args->{whoHas},
   );

   Net::Packet::Frame->new(l2 => $eth, l3 => $arp);
}

sub arpReply {
   my $self = shift;
   my $args = { @_ };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         "   srcMac => SRC_MAC (ETH layer),\n".
         "   isAt   => MAC,\n".
         "   toMac  => MAC or 'broadcast',\n".
         "   ip     => IP,\n".
         ");\n".
         "")
      unless $args->{srcMac}
          && $args->{isAt}
          && $args->{toMac}
          && $args->{ip}
   ;

   my $eth = Net::Packet::ETH->new(
      src  => $args->{srcMac},
      dst  => $args->{toMac} =~ /broadcast/i ? NETPKT_ETH_ADDR_BROADCAST
                                             : $args->{toMac},
      type => NETPKT_ETH_TYPE_ARP,
   );

   my $arp = Net::Packet::ARP->new(
      hType  => NETPKT_ARP_HTYPE_ETH,
      pType  => NETPKT_ARP_PTYPE_IPv4,
      hSize  => NETPKT_ARP_HSIZE_ETH,
      pSize  => NETPKT_ARP_PSIZE_IPv4,
      opCode => NETPKT_ARP_OPCODE_REPLY,
      src    => $args->{isAt},
      srcIp  => $args->{ip},
      dst    => $args->{toMac} =~ /broadcast/i ? NETPKT_ARP_ADDR_BROADCAST
                                               : $args->{toMac},
      dstIp  => $args->{ip},
   );

   Net::Packet::Frame->new(l2 => $eth, l3 => $arp);
}

1;

__END__

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

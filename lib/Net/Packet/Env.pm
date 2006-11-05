#
# $Id: Env.pm,v 1.2.2.13 2006/11/05 15:28:28 gomor Exp $
#
package Net::Packet::Env;
use strict;
use warnings;

require Exporter;
require Class::Gomor::Array;
our @ISA = qw(Exporter Class::Gomor::Array);
our @EXPORT_OK = qw($Env);

use Carp qw(croak);
require Net::Libdnet;
require Net::IPv6Addr;

our @AS = qw(
   dev
   ip
   ip6
   mac
   subnet
   gatewayIp
   gatewayMac
   desc
   dump
   err
   errString
   noFrameAutoDesc
   noFrameAutoDump
   noDescAutoSet
   noDumpAutoSet
   _dnet
);
our @AO = qw(
   debug
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

BEGIN {
   my $osname = {
      cygwin  => [ \&_getDevWin32, ],
      MSWin32 => [ \&_getDevWin32, ],
   };

   *getDev = $osname->{$^O}->[0] || \&_getDevOther;
}

use Net::Packet::Utils qw(getGatewayIp);

our $Env = __PACKAGE__->new;

sub new {
   my $self = shift->SUPER::new(
      debug           => 0,
      noFrameAutoDesc => 0,
      noFrameAutoDump => 0,
      noDescAutoSet   => 0,
      noDumpAutoSet   => 0,
      err             => 0,
      errString       => '',
      @_,
   );

   $self->[$__dev]
      ? do { $self->[$__dev] = $self->getDevInfoFor($self->[$__dev]) }
      : do { $self->[$__dev] = $self->getDevInfo                     };

   $self->[$__mac]        = $self->getMac    unless $self->[$__mac];
   $self->[$__subnet]     = $self->getSubnet unless $self->[$__subnet];
   $self->[$__ip]         = $self->getIp     unless $self->[$__ip];
   $self->[$__ip6]        = $self->getIp6    unless $self->[$__ip6];
   $self->[$__gatewayIp]  = getGatewayIp()   unless $self->[$__gatewayIp];

   $self;
}

sub getDevInfo {
   my $self = shift;
   # By default, we take outgoing device to Internet
   $self->[$___dnet] = Net::Libdnet::intf_get_dst(shift() || '1.1.1.1');
   $self->getDev;
}

sub getDevInfoFor {
   my $self = shift;
   $self->[$___dnet] = Net::Libdnet::intf_get(shift());
   $self->getDev;
}

sub updateDevInfo {
   my $self = shift;
   my ($ip) = @_;
   $self->getDevInfo($ip);
   $self->[$__dev]       = $self->getDev;
   $self->[$__ip]        = $self->getIp;
   $self->[$__ip6]       = $self->getIp6;
   $self->[$__mac]       = $self->getMac;
   $self->[$__subnet]    = $self->getSubnet;
   $self->[$__gatewayIp] = getGatewayIp($ip);
}

sub _getDevWin32 {
   my $self = shift;
   croak("@{[(caller(0))[3]]}: unable to find a suitable device\n")
      unless $self->[$___dnet]->{name};
   my %dev;
   my $err;
   require Net::Pcap;
   Net::Pcap::findalldevs(\%dev, \$err);
   croak("@{[(caller(0))[3]]}: Net::Pcap::findalldevs() error: $err\n")
      if $err;
   my $n;
   for (reverse sort keys %dev) {
      next if /GenericDialupAdapter/i;
      s/\\/\\\\/g;
      $dev{$_} = 'eth'.$n++;
   }
   %dev = map { $dev{$_} => $_ } sort keys %dev;
   my $eth = $self->[$___dnet]->{name};
   $dev{$eth};
}

sub _getDevOther {
   shift->[$___dnet]->{name} || (($^O eq 'linux') ? 'lo' : 'lo0');
}

sub getSubnet { shift->[$___dnet]->{addr} || '127.0.0.1/8'            }

sub getMac    { shift->[$___dnet]->{link_addr} || 'ff:ff:ff:ff:ff:ff' }

sub getIp {
   my $ip = shift->[$___dnet]->{addr} || '127.0.0.1';
   $ip =~ s/\/\d+$//;
   $ip;
}

sub _getIp6 {
   my $self = shift;
   my $dev = $self->[$__dev];
   my $mac = $self->[$__mac];
   my $buf = `/sbin/ifconfig $dev 2> /dev/null`;
   $buf =~ s/$dev//;
   $buf =~ s/$mac//i;
   my ($ip6) = ($buf =~ /((?:[a-f0-9]{1,4}(?::|%|\/){1,2})+)/i); # XXX: better
   if ($ip6) {
      $ip6 =~ s/%|\///g;
      $ip6 = lc($ip6);
   }
   ($ip6 && Net::IPv6Addr::ipv6_chkip($ip6) && $ip6) || '::1';
}

sub getIp6 {
   my $self = shift;
   $self->_getIp6($self->[$__dev]);
}

sub debug {
   my $self = shift;
   @_ ? do { $self->[$__debug] = $Class::Gomor::Debug = shift }
      : $self->[$__debug];
}

1;

=head1 NAME

Net::Packet::Env - environment object used for frame capture/injection

=head1 SYNOPSIS

   use Net::Packet::Env qw($Env);

   # Get default values from system
   my $env = Net::Packet::Env->new;

   # Get values from a specific device
   my $env2 = Net::Packet::Env->new(dev => 'vmnet1');

   print "dev: ", $env->dev, "\n";
   print "mac: ", $env->mac, "\n";
   print "ip : ", $env->ip,  "\n" if $env->ip;
   print "ip6: ", $env->ip6, "\n" if $env->ip6;

=head1 DESCRIPTION

Basically, this module is used to tell where to inject a frame, and B<Net::Packet::Frame> default behaviour regarding auto creation of B<Net::Packet::Desc> and B<Net::Packet::Dump> objects.

=head1 ATTRIBUTES

=over 4

=item B<dev>

The device on which frames will be injected.

=item B<ip>

The IPv4 address of B<dev>. It will be used by default for all created frames.

=item B<ip6>

The IPv6 address of B<dev>. It will be used by default for all created frames.

=item B<mac>

The MAC address of B<dev>. It will be used by default for all created frames.

=item B<subnet>

The subnet address of B<dev>. It will be set automatically.

=item B<gatewayIp>

The gateway IP address of B<dev>. It is set automatically under all platforms.

=item B<gatewayMac>

The gateway MAC address of B<dev>. It will not be set automatically. Due to the implementation of ARP lookup within B<Net::Packet>, we can't do it within this module. It is done within B<Net::Packet::DescL3> under Windows, to automatically build the layer 2 header.

=item B<desc>

The B<Net::Packet::Desc> object used to inject frames to network.

=item B<dump>

The B<Net::Packet::Dump> object used to receive frames from network.

=item B<noFrameAutoDesc>

This attribute controls B<Net::Packet::Frame> behaviour regarding B<Net::Packet::Desc> autocreation. If set to 0, when a B<Net::Packet::Frame> is created for the first time, a B<Net::Packet::Desc> object will be created if none has been set in B<desc> attribute for default B<$Env> object. Setting it to 1 avoids this behaviour.

=item B<noFrameAutoDump>

Same as above, but for B<Net::Packet::Dump> object.

=item B<noDescAutoSet>

This attribute controls B<Net::Packet::Desc> behaviour regarding global B<$Env> autosetting behaviour. If set to 0, when a B<Net::Packet::Desc> is created for the first time, the created B<Net::Packet::Desc> object will have a pointer to it stored in B<desc> attribute of B<$Env> default object. Setting it to 1 avoids this behaviour.

=item B<noDumpAutoSet>

Same as abose, but for B<Net::Packet::Dump> object.

=item B<debug>

The environment debug directive. Set it to a number greater than 0 to increase the level of debug messages. Up to 3, default 0.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

debug:           0

noFrameAutoDesc: 0

noFrameAutoDump: 0

noDescAutoSet:   0

noDumpAutoSet:   0

dev:             if not user provided, default interface is used, by calling B<getDevInfo> method. If user provided, all B<ip>, B<ip6> and B<mac> attributes will be used for that B<dev>.

ip:              if not user provided, default interface IP is used, by calling B<getIp> method. If user provided, it is overwritten by the user.

ip6:             if not user provided, default interface IPv6 is used, by calling B<getIp6> method. If user provided, it is overwritten by the user.

mac:             if not user provided, default interface MAC is used, by calling B<getMac> method. If user provided, it is overwritten by the user.

=item B<getDevInfo> [ (scalar) ]

By default, network device to use is the one used by default gateway. If you provide an IP address as a parameter, the interface used will be the one which have direct access to this IP address.

=item B<getDevInfoFor> (scalar)

Will set internal attributes for network interface passed as a parameter. Those internal attributes are used to get IP, IPv6 and MAC attributes.

=item B<updateDevInfo> (scalar)

This is a helper method. You pass an IP address as a parameter, and all attributes for elected network interface will be updated (B<dev>, B<ip>, B<ip6>, B<mac>, B<subnet>, B<gatewayIp>).

=item B<getDev>

Returns network interface, by looking at internal attribute.

=item B<getMac>

Returns MAC address, by looking at internal attribute.

=item B<getSubnet>

Returns subnet address, by looking at internal attribute.

=item B<getIp>

Returns IP address, by looking at internal attribute.

=item B<getIp6>

Returns IPv6 address, by looking at internal attribute.

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

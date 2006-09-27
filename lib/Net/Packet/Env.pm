#
# $Id: Env.pm,v 1.2.2.8 2006/06/04 13:45:18 gomor Exp $
#
package Net::Packet::Env;
use strict;
use warnings;

require Exporter;
require Class::Gomor::Array;
our @ISA = qw(Exporter Class::Gomor::Array);
our @EXPORT_OK = qw($Env);

use Net::Libdnet;
require Net::IPv6Addr;

our @AS = qw(
   dev
   ip
   ip6
   mac
   desc
   dump
   err
   errString
   noFrameAutoDesc
   noFrameAutoDump
   noDumpAutoSet
   noDescAutoSet
   _dnet
);
our @AO = qw(
   debug
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

our $Env = __PACKAGE__->new;

sub new {
   my $self = shift->SUPER::new(
      debug           => 0,
      noFrameAutoDesc => 0,
      noFrameAutoDump => 0,
      noDumpAutoSet   => 0,
      noDescAutoSet   => 0,
      err             => 0,
      errString       => '',
      @_,
   );

   $self->[$__dev]
      ? do { $self->[$__dev] = $self->getDevInfoFor($self->[$__dev]) }
      : do { $self->[$__dev] = $self->getDevInfo                     };

   $self->[$__mac] = $self->getMac unless $self->[$__mac];
   $self->[$__ip]  = $self->getIp  unless $self->[$__ip];
   $self->[$__ip6] = $self->getIp6 unless $self->[$__ip6];

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
   $self->getDevInfo(shift());
   $self->[$__dev] = $self->getDev;
   $self->[$__ip]  = $self->getIp;
   $self->[$__ip6] = $self->getIp6;
   $self->[$__mac] = $self->getMac;
}

sub getDev { shift->[$___dnet]->{name} || (($^O eq 'linux') ? 'lo' : 'lo0') }

sub getMac { shift->[$___dnet]->{link_addr} || 'ff:ff:ff:ff:ff:ff' }

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

   use Net::Packet::Env;

   # Get default values from system
   my $env = Net::Packet::Env->new;

   # Get values from a specific device
   my $env2 = Net::Packet::Env->new(dev => 'vmnet1');

   print "dev: ", $env->dev, "\n";
   print "mac: ", $env->mac, "\n";
   print "ip : ", $env->ip,  "\n" if $env->ip;
   print "ip6: ", $env->ip6, "\n" if $env->ip6;
   print "promisc: ", $env->promisc, "\n";

=head1 DESCRIPTION

Basically, this module is used to tell where to inject a frame, and how to capture a frame.

=head1 ATTRIBUTES

=over 4

=item B<dev>

The device on which frames will be injected/captured.

=item B<mac>

The MAC address used to build injected frames.

=item B<ip>

The IPv4 address used to build injected frames.

=item B<ip6>

The IPv6 address used to build injected frames.

=item B<link>

The link type of the capturing process (see B<Net::Packet::Dump>). It will be set automatically when a capturing device is open. Usually used internally.

=item B<desc>

The B<Net::Packet::Desc> object used to inject frames to network.

=item B<dump>

The B<Net::Packet::Dump> object used to receive frames from network.

=item B<promisc>

This one is used to tell the tcpdump-like process (see B<Net::Packet::Dump>) to go into promiscuous mode or not. Note: the device may be already in promiscuous mode, so even when you set it to 0, you may be in the situation to capture in promiscuous mode.

=item B<filter>

When set, the pcap filter that'll be used for packet captures will be this one. It must be manually set if you want this feature. Default is to capture all traffic.

=item B<debug>

The environment debug directive. Set it to a number greater than 0 to increase the level of debug messages. Up to 3, default 0.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

dev: autoDev() - the one tcpdump get without -i parameter.

mac: autoMac() - from dev, MAC address the default device has.

ip: autoIp() - from dev, IPv4 address the default device has.

ip6: autoIp6() - from dev, IPv6 address the default device has.

promisc: 0

link: undef

See B<Net::Packet::Utils> for more about auto* sub routines.

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

#
# $Id: Env.pm,v 1.1.2.15 2005/05/22 19:47:48 gomor Exp $
#
package Net::Packet::Env;

use strict;
use warnings;

require Class::Gomor::Hash;
our @ISA = qw(Class::Gomor::Hash);

use Net::Packet::Utils qw(autoDev autoMac autoIp autoIp6 getHostIpv4Addr
   getHostIpv6Addr);

our @AS = qw(
   dev
   mac
   link
   desc
   dump
   promisc
   filter
   err
   errString
);

our @AO = qw(
   ip
   ip6
   debug
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      promisc   => 0,
      link      => undef,
      debug     => 0,
      err       => 0,
      errString => "",
      @_,
   );

   $self->dev(autoDev())           unless $self->dev;
   $self->mac(autoMac($self->dev)) unless $self->mac;
   $self->ip(autoIp($self->dev))   unless $self->ip;
   $self->ip6(autoIp6($self->dev)) unless $self->ip6;

   $self;
}

sub debug {
   my $self = shift;
   @_ ? $self->{debug} = $Class::Gomor::Hash::Debug = shift
      : $self->{debug};
}

sub ip {
   my $self = shift;
   @_ ? $self->{ip} = getHostIpv4Addr(shift)
      : $self->{ip};
}

sub ip6 {
   my $self = shift;
   my $ip6 = shift;
   $ip6 ? $self->{ip6} = getHostIpv6Addr($ip6)
        : $self->{ip6};
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
   
Copyright (c) 2004-2005, Patrice E<lt>GomoRE<gt> Auffret
   
You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.
      
=head1 RELATED MODULES
         
L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>
      
=cut

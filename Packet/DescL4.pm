package Net::Packet::DescL4;

# $Date: 2005/01/27 21:26:24 $
# $Revision: 1.2.2.19 $

use strict;
use warnings;

require Net::Packet::Desc;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Desc Class::Gomor::Hash);

use Carp;
use Socket;
use Socket6;
use IO::Socket;
use Net::Packet::Consts qw(:desc :layer);
use Net::Packet::Utils qw(getHostIpv4Addr getHostIpv6Addr);

our @AS = qw(
   target
   protocol
   family
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      protocol => NP_DESC_IPPROTO_TCP,
      family   => NP_LAYER_IPv4,
      @_,
   );

   croak("Must be EUID 0 to create a DescL4 object") if $>;

   croak("@{[(caller(0))[3]]}: you must pass at least `target' parameter")
      unless $self->target;

   my $families = {
      NP_LAYER_IPv4() => AF_INET(),
      NP_LAYER_IPv6() => AF_INET6(),
   };

   my @res = getaddrinfo(
      $self->target, 0, $families->{$self->family}, SOCK_STREAM,
   );

   my ($family, $saddr) = @res[0, 3] if @res >= 5;

   $self->_sockaddr($saddr);

   socket(S, $family, SOCK_RAW, $self->protocol)
      or croak("@{[(caller(0))[3]]}: socket: $!");

   my $fd = fileno(S) or croak("@{[(caller(0))[3]]}: fileno: $!");

   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_io($io);

   if ($self->isFamilyIpv4) {
      $self->target(getHostIpv4Addr($self->target));
   }
   elsif ($self->isFamilyIpv6) {
      $self->target(getHostIpv6Addr($self->target));
   }

   $self;
}

#
# Helpers
#

sub _isFamily    { shift->family eq shift          }
sub isFamilyIpv4 { shift->_isFamily(NP_LAYER_IPv4) }
sub isFamilyIpv6 { shift->_isFamily(NP_LAYER_IPv6) }

sub _isProtocol      { shift->protocol eq shift                   }
sub isProtocolTcp    { shift->_isProtocol(NP_DESC_IPPROTO_TCP)    }
sub isProtocolUdp    { shift->_isProtocol(NP_DESC_IPPROTO_UDP)    }
sub isProtocolIcmpv4 { shift->_isProtocol(NP_DESC_IPPROTO_ICMPv4) }

1;

__END__

=head1 NAME

Net::Packet::DescL4 - object for a transport layer (layer 4) descriptor

=head1 SYNOPSIS

   use Net::Packet::DescL4;

   # Get NP_DESC_* constants
   use Net::Packet::Consts qw(:desc);

   # Usually, you use it to send TCP and UDP frames over IPv4
   my $d4 = Net::Packet::DescL4->new(
      target   => '192.168.0.1',
      protocol => NP_DESC_IPPROTO_TCP,
   );

   $d4->send($rawStringToNetwork);

=head1 DESCRIPTION

See also B<Net::Packet::Desc> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<target>

IPv4 address of the target host. You must set it to be able to send frames.

=item B<protocol>

Transport protocol to use, see NP_DESC_IPPROTO_* constants in B<Net::Packet::Desc>. You must set it to be able to send frames.

=item B<family>

The family address of B<target> attribute. It is either B<NP_LAYER_IPv4> or B<NP_LAYER_IPv6>.

=back

=head1 METHODS

=over 4

=item B<new>

Create the object. When the object is created, the $Net::Packet::Env object as its B<desc> attributes set to it. Use B<noEnvSet> to avoid that. Default values:

protocol: NP_DESC_IPPROTO_TCP

family  : NP_LAYER_IPv4

=item B<isFamilyIpv4>

=item B<isFamilyIpv6>

=item B<isFamilyIp> - either one of two previous

Helper method to know about the layer 3 type.

=item B<isProtocolTcp>

=item B<isProtocolUdp>

=item B<isProtocolIcmpv4>

Returns if the protocol attribute is of specified type.

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

package Net::Packet::DescL3;

# $Date: 2005/01/27 21:26:24 $
# $Revision: 1.2.2.16 $

use strict;
use warnings;

require Net::Packet::Desc;
require Class::Gomor::Hash;
our @ISA = qw(Net::Packet::Desc Class::Gomor::Hash);

use Carp;
use Socket;
use Socket6;
use IO::Socket;
use Net::Packet::Consts qw(:desc);

our @AS = qw(
   target
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(@_);

   croak("Must be EUID 0 to create a DescL3 object") if $>;

   croak("@{[(caller(0))[3]]}: you must pass `target' parameter")
      unless $self->target;

   my @res = getaddrinfo($self->target, 0, AF_UNSPEC, SOCK_STREAM);
   my ($family, $saddr) = @res[0, 3] if @res >= 5;

   $self->_sockaddr($saddr);

   socket(S, $family, SOCK_RAW, NP_DESC_IPPROTO_RAW)
      or croak("@{[(caller(0))[3]]}: socket: $!");

   if ($family == AF_INET) {
      setsockopt(S, NP_DESC_IPPROTO_IP, NP_DESC_IP_HDRINCL, 1)
         or croak("@{[(caller(0))[3]]}: setsockopt: $!");
   }

   my $fd = fileno(S) or croak("@{[(caller(0))[3]]}: fileno: $!");

   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_io($io);

   $self;
}

1;

__END__

=head1 NAME

Net::Packet::DescL3 - object for a network layer (layer 3) descriptor

=head1 SYNOPSIS

   use Net::Packet::DescL3;

   # Usually, you use it to send IPv4 frames
   my $d3 = Net::Packet::DescL3->new(target => '192.168.0.1');

   $d3->send($rawStringToNetwork);

=head1 DESCRIPTION

See also B<Net::Packet::Desc> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<target>

IPv4 address of the target host. You must set it to be able to send frames.

=back

=head1 METHODS

=over 4

=item B<new>

Create the object, using default $Net::Packet::Env object to choose which device and source address to use (see B<Net::Packet::Env>). When the object is created, the $Net::Packet::Env object as its B<desc> attributes set to it. Use B<noEnvSet> to avoid that.

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

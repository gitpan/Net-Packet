package Net::Packet::Desc;

# $Date: 2005/01/23 15:48:12 $
# $Revision: 1.2.2.20 $

use strict;
use warnings;
use Carp;

require Exporter;
require Class::Gomor::Hash;
our @ISA = qw(Exporter Class::Gomor::Hash);

use Net::Packet qw($Env);
use Net::Packet::Consts qw(:desc);

our @AS = qw(
   env
   noEnvSet
   _io
   _sockaddr
);

__PACKAGE__->buildAccessorsScalar(\@AS);

sub new {
   my $self = shift->SUPER::new(
      env      => $Env,
      noEnvSet => 0,
      @_,
   );

   my $env = $self->env;

   $self->debugPrint(1, "Dev: [@{[$env->dev]}]\n".
                        "Ip:  [@{[$env->ip]}]\n".
                        "Mac: [@{[$env->mac]}]");
   $self->debugPrint(1, "Ip6: [@{[$env->ip6]}]")
      if $env->ip6;

   $env->desc($self) unless $self->noEnvSet;

   $self;
}

sub send {
   my $self = shift;
   my $raw  = shift;

   while (1) {
      my $ret = send($self->_io, $raw, 0, $self->_sockaddr);
      unless ($ret) {
         if ($!{ENOBUFS}) {
            $self->debugPrint(
               2, "send: ENOBUFS returned, sleeping for 1 second"
            );
            sleep 1;
            next;
         }
         elsif ($!{EHOSTDOWN}) {
            $self->debugPrint(2, "send: host is down");
            last;
         }
         carp("@{[(caller(0))[3]]}: send: $!");
      }
      last;
   }
}

sub close { shift->_io->close }

sub DESTROY {
   my $self = shift;

   do { $self->_io->close; $self->_io(undef) } if $self->_io;
   $self->SUPER::DESTROY if $self->can('SUPER::DESTROY');
}

#
# Helpers
#

sub _isDesc  { ref(shift) =~ /@{[shift()]}/ }
sub isDescL2 { shift->_isDesc(NP_DESC_L2)   }
sub isDescL3 { shift->_isDesc(NP_DESC_L3)   }
sub isDescL4 { shift->_isDesc(NP_DESC_L4)   }

1;

__END__

=head1 NAME

Net::Packet::Desc - base class for all desc modules

=head1 DESCRIPTION

This is the base class for B<Net::Packet::DescL2>, B<Net::Packet::DescL3> and B<Net::Packet::DescL4> modules.

It just provides those layers with inheritable attributes and methods.

A descriptor is required when you want to send frames over network.

=head1 ATTRIBUTES

=over 4

=item B<env>

A reference to a B<Net::Packet::Env> object. By default, initialized to $Net::Packet::Env variable.

=item B<noEnvSet>

When a new object is created, the B<Net::Packet> global B<$Env> object as its B<desc> attribute set to this newly created B<Desc> object. Setting it to 1 avoids this. Default is 0.

=back

=head1 METHODS

=over 4

=item B<send> (scalar)

Send the raw data passed as parameter to the B<env> object.

=item B<close>

Close the descriptor.

=item B<isDescL2>

=item B<isDescL3>

=item B<isDescL4>

Returns true if Desc is of specified type, false otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:desc);

=over 4

=item B<NP_DESC_IPPROTO_TCP>

=item B<NP_DESC_IPPROTO_UDP>

=item B<NP_DESC_IPPROTO_ICMPv4>

=item B<NP_DESC_L2>

=item B<NP_DESC_L3>

=item B<NP_DESC_L4>

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

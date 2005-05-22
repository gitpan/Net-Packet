#
# $Id: DescL2.pm,v 1.2.2.14 2005/05/22 19:47:48 gomor Exp $
#
package Net::Packet::DescL2;

use strict;
use warnings;
use Carp;

require Net::Packet::Desc;
our @ISA = qw(Net::Packet::Desc);

use IO::Socket;

BEGIN {
   my $osname = {
      linux => \&_sendLinux,
   };

   *send = $osname->{$^O} || \&_sendOther;
}

sub new {
   my $self = shift->SUPER::new(@_);

   croak("Must be EUID 0 to create a DescL2 object") if $>;

   my $fd = Net::Packet::netpacket_open_l2($self->env->dev)
      or croak("@{[(caller(0))[3]]}: netpacket_open_l2: ".
               "@{[$self->env->dev]}: $!");

   # XXX: implement dropping user priv. Does not work now, since 
   # Net::Packet::Dump also requires privs to open bpf: race condition
   # ???: maybe we do not need to drop privs here, but only in Dump
   #$< = $> = getpwnam($ENV{USER}) if $>;

   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_io($io);

   $self;
}

sub _sendLinux {
   my $self = shift;
   my $raw  = shift;

   # Here is the Linux dirty hack (to choose outgoing device, surely)
   my $sin = pack('S a14', 0, $self->env->dev);

   while (1) {
      my $ret = CORE::send($self->_io, $raw, 0, $sin);
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

sub _sendOther {
   my $self = shift;
   my $raw  = shift;

   while (1) {
      my $ret = $self->_io->syswrite($raw, length $raw);
      unless ($ret) {
         if ($!{ENOBUFS}) {  
            $self->debugPrint(
               2, "syswrite: ENOBUFS returned, sleeping for 1 second"
            );
            sleep 1;
            next;
         }
         elsif ($!{EHOSTDOWN}) {
            $self->debugPrint(2, "syswrite: host is down");
            last;
         }
         carp("@{[(caller(0))[3]]}: syswrite: $!") unless $ret;
      }
      last;
   }
}

1;

__END__
   
=head1 NAME

Net::Packet::DescL2 - object for a link layer (layer 2) descriptor

=head1 SYNOPSIS

   use Net::Packet::DescL2;

   # Usually, you use it to send ARP frames, that is crafted from ETH layer
   my $d2 = Net::Packet::DescL2->new;

   $d2->send($rawStringToNetwork);

=head1 DESCRIPTION

See also B<Net::Packet::Desc> for other attributes and methods.

=head1 METHODS

=over 4

=item B<new>

Create the object, using default $Net::Packet::Env object to choose which device to use (see B<Net::Packet::Env>). When the object is created, the $Net::Packet::Env object as its B<desc> attributes set to it. Use B<noEnvSet> to avoid that.

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

package Net::Packet::DescL2;

# $Date: 2004/10/03 18:30:23 $
# $Revision: 1.1.1.1.2.1 $

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

   croak("@{[(caller(0))[3]]}: \$Net::Packet::Dev variable not set")
      unless $Net::Packet::Dev;

   my $fd = Net::Packet::netpacket_open_l2($Net::Packet::Dev)
      or croak("@{[(caller(0))[3]]}: netpacket_open_l2: $Net::Packet::Dev: $!");

   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_Io($io);

   return $self;
}

sub _sendLinux {
   my ($self, $raw) = @_;

   # Here is the Linux dirty hack (to choose outgoing device, surely)
   my $sin = pack('S a14', 0, $Net::Packet::Dev);
   CORE::send($self->_Io, $raw, 0, $sin)
      or croak("@{[(caller(0))[3]]}: send: $!");
}

sub _sendOther {
   my ($self, $raw) = @_;

   $self->_Io->syswrite($raw, length $raw)
      or croak("@{[(caller(0))[3]]}: syswrite: $!");
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

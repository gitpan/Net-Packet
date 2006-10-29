#
# $Id: DescL3.pm,v 1.3.2.4 2006/10/29 14:25:54 gomor Exp $
#
package Net::Packet::DescL3;
use strict;
use warnings;
use Carp;

require Net::Packet::Desc;
our @ISA = qw(Net::Packet::Desc);
__PACKAGE__->cgBuildIndices;

no strict 'vars';

require Net::Write::Layer3;

sub new {
   my $self = shift->SUPER::new(@_);

   confess("@{[(caller(0))[3]]}: you must pass `target' parameter\n")
      unless $self->[$__target];

   my $nwrite = Net::Write::Layer3->new(
      dev => $self->[$__dev],
      dst => $self->[$__target],
   );
   $nwrite->open;

   $self->[$___io] = $nwrite;

   $self;
}

1;

__END__

=head1 NAME

Net::Packet::DescL3 - object for a network layer (layer 3) descriptor

=head1 SYNOPSIS

   require Net::Packet::DescL3;

   # Usually, you use it to send IPv4 frames
   my $d3 = Net::Packet::DescL3->new(
      dev    => 'eth0',
      target => '192.168.0.1',
   );

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

Create the object, using default B<$Env> object values for B<dev>, B<ip>, B<ip6>
 and B<mac> (see B<Net::Packet::Env>). When the object is created, the B<$Env> g
lobal object has its B<desc> attributes set to it. You can avoid this behaviour 
by setting B<noDescAutoSet> in B<$Env> object (see B<Net::Packet::Env>).

Default values for attributes:

dev: $Env->dev

ip:  $Env->ip

ip6: $Env->ip6

mac: $Env->mac

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

#
# $Id: DescL3.pm,v 1.2.2.23 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::DescL3;

use strict;
use warnings;
use Carp;

require Net::Packet::Desc;
our @ISA = qw(Net::Packet::Desc);

require Net::Write::Layer3;

sub new {
   my $self = shift->SUPER::new(@_);

   croak("@{[(caller(0))[3]]}: you must pass `target' parameter\n")
      unless $self->target;

   my $nwrite = Net::Write::Layer3->new(
      dev => $self->env->dev,
      dst => $self->target,
   );
   $nwrite->open;

   $self->_io($nwrite);

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

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

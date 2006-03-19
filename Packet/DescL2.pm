#
# $Id: DescL2.pm,v 1.2.2.19 2006/03/19 17:17:01 gomor Exp $
#
package Net::Packet::DescL2;

use strict;
use warnings;
use Carp;

require Net::Packet::Desc;
our @ISA = qw(Net::Packet::Desc);

require Net::Write::Layer2;

sub new {
   my $self = shift->SUPER::new(@_);

   my $nwrite = Net::Write::Layer2->new(
      dev => $self->env->dev,
   );
   $nwrite->open;

   $self->_io($nwrite);

   $self;
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

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret
      
You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=head1 RELATED MODULES
 
L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

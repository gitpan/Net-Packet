#
# $Id: DescL2.pm,v 1.3.2.1 2006/04/25 21:39:52 gomor Exp $
#
package Net::Packet::DescL2;
use strict;
use warnings;

require Net::Packet::Desc;
our @ISA = qw(Net::Packet::Desc);
__PACKAGE__->cgBuildIndices;

no strict 'vars';

require Net::Write::Layer2;

sub new {
   my $self = shift->SUPER::new(@_);

   my $nwrite = Net::Write::Layer2->new(
      dev => $self->[$__dev],
   );
   $nwrite->open;

   $self->[$___io] = $nwrite;

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

package Net::Packet::Layer4;

# $Date: 2004/09/29 16:42:48 $
# $Revision: 1.1.1.1 $

require Net::Packet::Layer;
our @ISA = qw(Net::Packet::Layer);

sub layer { Net::Packet::Frame::NETPKT_L_4() }

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

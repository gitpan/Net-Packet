#
# $Id: Layer4.pm,v 1.1.1.1.4.12 2006/03/11 16:32:50 gomor Exp $
#
package Net::Packet::Layer4;

require Net::Packet::Layer;
our @ISA = qw(Net::Packet::Layer);

use Net::Packet::Consts qw(:layer);

sub layer { NP_LAYER_N_4 }

sub _is      { (shift->is eq shift()) ? 1 : 0 }
sub isTcp    { shift->_is(NP_LAYER_TCP)       }
sub isUdp    { shift->_is(NP_LAYER_UDP)       }
sub isIcmpv4 { shift->_is(NP_LAYER_ICMPv4)    }

1;

__END__

=head1 NAME

Net::Packet::Layer4 - base class for all layer 4 modules

=head1 DESCRIPTION

This is the base class for B<Net::Packet::Layer4> subclasses.

It just provides those layers with inheritable attributes and methods.

=head1 METHODS

=over 4

=item B<isTcp>

=item B<isUdp>

=item B<isIcmpv4>

Returns true if Layer4 is of specified type, false otherwise.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

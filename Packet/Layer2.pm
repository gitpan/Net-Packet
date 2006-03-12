#
# $Id: Layer2.pm,v 1.1.1.1.4.13 2006/03/11 16:32:50 gomor Exp $
#
package Net::Packet::Layer2;

require Net::Packet::Layer;
our @ISA = qw(Net::Packet::Layer);

use Net::Packet::Consts qw(:layer);

sub layer { NP_LAYER_N_2 }

sub _is    { (shift->is eq shift()) ? 1 : 0 }
sub isEth  { shift->_is(NP_LAYER_ETH)       }
sub isNull { shift->_is(NP_LAYER_NULL)      }
sub isRaw  { shift->_is(NP_LAYER_RAW)       }
sub isSll  { shift->_is(NP_LAYER_SLL)       }

1;

__END__

=head1 NAME

Net::Packet::Layer2 - base class for all layer 2 modules

=head1 DESCRIPTION

This is the base class for B<Net::Packet::Layer2> subclasses.

It just provides those layers with inheritable attributes and methods.

=head1 METHODS

=over 4

=item B<isEth>

=item B<isNull>

=item B<isRaw>

=item B<isSll>

Returns true if Layer2 is of specified type, false otherwise.

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

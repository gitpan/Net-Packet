#
# $Id: Packet.pm,v 1.1.2.19 2006/03/13 12:56:18 gomor Exp $
#
package Net::Packet;

require v5.6.1;

use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

our @ISA = qw(Exporter DynaLoader);

our @EXPORT_OK = qw($Env);

our $VERSION = '2.06';

our $Env;
require Net::Packet::Env;
$Env = Net::Packet::Env->new unless $Env;

sub AUTOLOAD {
   # This AUTOLOAD is used to 'autoload' constants from the constant()
   # XS function.  If a constant is not found then control is passed
   # to the AUTOLOAD in AutoLoader.

   our $AUTOLOAD;
   (my $constname = $AUTOLOAD) =~ s/.*:://;

   # Autoload only for libnetpacket C functions
   return unless $constname =~ /^netpacket/;

   croak("& not defined") if $constname eq 'constant';

   my $val = constant($constname, @_ ? $_[0] : 0);
   if ($! != 0) {
      if ($! =~ /Invalid/ || $!{EINVAL}) {
         $AutoLoader::AUTOLOAD = $AUTOLOAD;
         goto &AutoLoader::AUTOLOAD;
      }
      else {
         croak "Your vendor has not defined Net::Packet macro $constname";
      }
   }
   {
      no strict 'refs';
      *$AUTOLOAD = sub () { $val };
   }
   goto &$AUTOLOAD;
}

bootstrap Net::Packet $VERSION;

1;

__END__

=head1 NAME

Net::Packet - a framework to easily send and receive frames from layer 2 to layer 7

=head1 CLASS HIERARCHY

  Net::Packet

  Net::Packet::Env

  Net::Packet::Dump

  Net::Packet::Utils

  Net::Packet::Desc
     |
     +---Net::Packet::DescL2
     |
     +---Net::Packet::DescL3
     |
     +---Net::Packet::DescL4

  Net::Packet::Frame

  Net::Packet::Layer
     |
     +---Net::Packet::Layer2
     |      |
     |      +---Net::Packet::ETH
     |      |
     |      +---Net::Packet::NULL
     |      |
     |      +---Net::Packet::RAW
     |      |
     |      +---Net::Packet::SLL
     |
     +---Net::Packet::Layer3
     |      |
     |      +---Net::Packet::ARP
     |      |
     |      +---Net::Packet::IPv4
     |      |
     |      +---Net::Packet::IPv6
     |      |
     |      +---Net::Packet::VLAN
     |
     +---Net::Packet::Layer4
     |      |
     |      +---Net::Packet::TCP
     |      |
     |      +---Net::Packet::UDP
     |      |
     |      +---Net::Packet::ICMPv4
     |
     +---Net::Packet::Layer7

=head1 SYNOPSIS

   # Load main module, it also initializes a Net::Packet::Env object
   use Net::Packet qw($Env);

   # Build IPv4 header
   use Net::Packet::IPv4;
   my $ip = Net::Packet::IPv4->new(dst => '192.168.0.1');

   # Build TCP header
   use Net::Packet::TCP;
   my $tcp = Net::Packet::TCP->new(dst => 22);

   # Assemble frame
   # It will also open a Net::Packet::DescL3 descriptor
   # and a Net::Packet::Dump object
   use Net::Packet::Frame;
   my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $tcp);

   $frame->send;

   # Print the reply just when it has been received
   until ($Env->dump->timeout) {
      if ($frame->recv) {
         print $frame->reply->l3, "\n";
         print $frame->reply->l4, "\n";
         last;
      }
   }

=head1 DESCRIPTION

This module is a unified framework to craft, send and receive packets at layers 2, 3, 4 and 7.

Basically, you forge each layer of a frame (Net::Packet::IPv4 for layer 3, Net::Packet::TCP for layer 4 ; for example), and pack all of this into a Net::Packet::Frame object. Then, you can send the frame to the network, and receive it easily, since the response is automatically searched for and matched against the request.

If you want some layer 2, 3 or 4 protocol encoding/decoding to be added, just ask, and give a corresponding .pcap file ;)

You should study various pod found in all classes, example files found in B<examples> directory that come with this tarball, and also tests in B<t> directory.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES  

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

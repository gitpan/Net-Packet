#
# $Id: Utils.pm,v 1.2.2.2 2006/05/31 16:43:41 gomor Exp $
#
package Net::Packet::Utils;
use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(
   getHostIpv4Addr
   getHostIpv4Addrs
   getHostIpv6Addr
   getRandomHighPort
   getRandom32bitsInt
   getRandom16bitsInt
   convertMac
   unpackIntFromNet
   packIntToNet
   inetChecksum
   inetAton
   inetNtoa
   inet6Aton
   inet6Ntoa
   explodeIps
   explodePorts
);

our %EXPORT_TAGS = (
   all => [ @EXPORT_OK ],
);

use Socket;
use Socket6;
require Net::IPv6Addr;

sub getHostIpv4Addr {
   my $name  = shift;

   return undef unless $name;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

   my @addrs = (gethostbyname($name))[4];
   @addrs ? return join('.', unpack('C4', $addrs[0]))
          : carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   return undef;
}

sub getHostIpv4Addrs {
   my $name  = shift;

   return undef unless $name;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

   my @addrs = (gethostbyname($name))[4];
   @addrs ? return @addrs
          : carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   return ();
}

sub getHostIpv6Addr {
   my $name = shift;

   return undef unless $name;
   return $name if Net::IPv6Addr::is_ipv6($name);

   my @res = getaddrinfo($name, 'ssh', AF_INET6, SOCK_STREAM);
   if (@res >= 5) {
      my ($ipv6) = getnameinfo($res[3], NI_NUMERICHOST | NI_NUMERICSERV);
      $ipv6 =~ s/%.*$//;
      return $ipv6;
   }
   else {
      carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   }
   return undef;
}

sub inetAton  { inet_aton(shift())           }
sub inetNtoa  { inet_ntoa(shift())           }
sub inet6Aton { inet_pton(AF_INET6, shift()) }
sub inet6Ntoa { inet_ntop(AF_INET6, shift()) }

sub getRandomHighPort {
   my $highPort = int rand 0xffff;
   $highPort += 1024 if $highPort < 1025;
   return $highPort;
}

sub getRandom32bitsInt { int rand 0xffffffff }
sub getRandom16bitsInt { int rand 0xffff     }

sub convertMac {
   my $mac = shift;
   $mac =~ s/(..)/$1:/g;
   $mac =~ s/:$//;
   return lc $mac;
}

sub unpackIntFromNet {
   my ($net, $format, $offset, $pad, $bit) = @_;
   unpack($format, pack('B*', 0 x $pad . substr($net, $offset, $bit)));
}

sub packIntToNet {
   my ($int, $format, $offset, $bit) = @_;
   substr(unpack('B*', pack($format, $int << $bit)), $offset, $bit);
}

sub inetChecksum {
   my $phpkt = shift;

   $phpkt      .= "\x00" if length($phpkt) % 2;
   my $len      = length $phpkt;
   my $nshort   = $len / 2;
   my $checksum = 0;
   $checksum   += $_ for unpack("S$nshort", $phpkt);
   $checksum   += unpack('C', substr($phpkt, $len - 1, 1)) if $len % 2;
   $checksum    = ($checksum >> 16) + ($checksum & 0xffff);

   unpack('n', pack('S', ~(($checksum >> 16) + $checksum) & 0xffff));
}

sub explodePorts {
   my @ports;
   do { s/-/../g; push @ports, $_ for eval } for split /,/, shift();
   @ports;
}

sub explodeIps {
   my @ips;
   for (split(/,/, shift())) {
      my @bytes;
      do { s/-/../g; push @bytes, $_ } for split(/\./);
      for my $b1 (eval($bytes[0])) {
         for my $b2 (eval($bytes[1])) {
            for my $b3 (eval($bytes[2])) {
               for my $b4 (eval($bytes[3])) {
                  push @ips, "$b1.$b2.$b3.$b4";
               }
            }
         }
      }
   }
   @ips;
}

1;

=head1 NAME

Net::Packet::Utils - useful subroutines used in Net::Packet

=head1 SYNOPSIS

   # Load all subroutines
   use Net::Packet::Utils qw(:all);

   # Load only specific subroutines
   use Net::Packet::Utils qw(explodeIps explodePorts);

   my @ips   = explodeIps('192.168.0.1-254,192.168.1.1');
   my @ports = explodePorts('1-1024,6000');

   print "@ips\n";
   print "@ports\n";

=head1 DESCRIPTION

This module is not object oriented, it just implements some utilities used accros Net::Packet framework. They may be useful in other modules too, so here lies their descriptions.

=head1 SUBROUTINES

=over 4

=item B<getHostIpv4Addr> (scalar)

Tries to resolve hostname passed as an argument. Returns its IP address.

=item B<getHostIpv4Addrs> (scalar)

Tries to resolve hostname passed as an argument. Returns an array of IP addresses.

=item B<getHostIpv6Addr> (scalar)

Tries to resolve hostname passed as an argument. Returns its IPv6 address.

=item B<inetAton> (scalar)

Returns numeric value of IP address passed as an argument.

=item B<inetNtoa> (scalar)

Returns IP address of numeric value passed as an argument.

=item B<inet6Aton> (scalar)

Returns numeric value of IPv6 address passed as an argument.

=item B<inet6Ntoa> (scalar)

Returns IPv6 address of numeric value passed as an argument.

=item B<getRandomHighPort>

Returns a port number for direct use as source in a TCP or UDP header (that is a port between 1025 and 65535).

=item B<getRandom32bitsInt>

Returns a random integer of 32 bits in length.

=item B<getRandom16bitsInt>

Returns a random integer of 16 bits in length.

=item B<convertMac> (scalar)

Converts a MAC address from network format to human format.

=item B<unpackIntFromNet> (scalar, scalar, scalar, scalar, scalar)

Almost used internally, to convert network bits to integers. First argument is what to convert, second is an unpack format, third the offset of first argument where bits to get begins, the fourth are padding bits to achieve the length we need, and the last is the number of bits to get from offset argument.

=item B<packIntToNet> (scalar, scalar, scalar, scalar)

Almost used internally, to convert integers to network bits. First argument is what to convert, second is a pack format, third the offset where to store the first argument, and the last the number of bits the integer will be once packed.

=item B<inetChecksum> (scalar)

Compute the INET checksum used in various layers.

=item B<explodePorts>

=item B<explodeIps>

See B<SYNOPSIS>.

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
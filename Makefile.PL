#
# $Id: Makefile.PL,v 1.3.2.6 2006/11/18 12:49:06 gomor Exp $
#
use ExtUtils::MakeMaker;

die("*** Big endian architectures not supported yet\n")
   if unpack("h*", pack("s", 1)) =~ /01/;

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'lib/Net/Packet.pm',
   LICENSE       => 'Artistic',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Net::Pcap     => '0.12',
      Net::Write    => '0.83',
      Net::Libdnet  => 0,
      Time::HiRes   => 0,
      Net::IPv6Addr => 0,
      Socket6       => 0,
      Bit::Vector   => 0,
      Storable      => 0,
   },
   ABSTRACT_FROM => 'lib/Net/Packet.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
);

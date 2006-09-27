#
# $Id: Makefile.PL,v 1.3.2.4 2006/09/27 14:12:48 gomor Exp $
#
use ExtUtils::MakeMaker;

die("*** Big endian architectures not supported yet\n")
   if unpack("h*", pack("s", 1)) =~ /01/;

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'lib/Net/Packet.pm',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Net::Pcap     => '0.12',
      Net::Write    => '0.82',
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

#
# $Id: Makefile.PL,v 1.3.2.7 2006/12/16 15:26:26 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'lib/Net/Packet.pm',
   LICENSE       => 'Artistic',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Net::Pcap     => '0.12',
      Net::Write    => '1.00',
      Net::Libdnet  => 0,
      Time::HiRes   => 0,
      Net::IPv6Addr => 0,
      Socket6       => 0,
      Bit::Vector   => 0,
   },
   ABSTRACT_FROM => 'lib/Net/Packet.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
);

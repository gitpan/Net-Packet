#
# $Id: Makefile.PL 1640 2009-11-09 17:58:27Z gomor $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'lib/Net/Packet.pm',
   LICENSE       => 'artistic',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Net::Pcap     => '0.12',
      Net::Write    => '1.00',
      Net::Libdnet  => 0,
      Time::HiRes   => 0,
      Net::IPv6Addr => 0,
      Net::IPv4Addr => 0,
      Socket6       => 0,
      Bit::Vector   => 0,
   },
   ABSTRACT_FROM => 'lib/Net/Packet.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
);

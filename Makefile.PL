use ExtUtils::MakeMaker;

die("*** Big endian architectures not supported yet\n")
   if unpack("h*", pack("s", 1)) =~ /01/;

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'Packet.pm',
   PREREQ_PM     => {
      Time::HiRes   => 0,
      Net::Pcap     => '0.12',
      Net::IPv6Addr => 0,
      Socket6       => 0,
      Class::Gomor  => 0,
      Bit::Vector   => 0,
      Net::Write    => 0,
   },
   ABSTRACT_FROM => 'Packet.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
);

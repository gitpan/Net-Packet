use ExtUtils::MakeMaker;

WriteMakefile (
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'Packet.pm',
   PREREQ_PM     => {
      Time::HiRes   => 0,
      IO::Interface => 0,
      Net::Pcap     => 0.04,
   },
   ABSTRACT_FROM => 'Packet.pm',
   AUTHOR        => 'GomoR <netpkt@gomor.org>',
   LIBS          => ['-lpcap'],                # e.g., '-lm'
   DEFINE        => '',                        # e.g., '-DHAVE_SOMETHING'
   INC           => '-I. -I/usr/include/pcap', # e.g., '-I/usr/local/include'
   OBJECT        => '$(O_FILES)',
);

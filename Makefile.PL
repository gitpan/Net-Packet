use ExtUtils::MakeMaker;

require DynaLoader;

my $file = DynaLoader::dl_findfile('-lpcap')
   or die "*** Cannot find libpcap, try setting LD_LIBRARY_PATH\n";

my ($lib) = $file =~ /^(.*)\//;
(my $inc  = $lib) =~ s/lib/include/;
$inc = "-I$inc -I$inc/pcap";
$lib = "-L$lib";

print "Found libpcap:    [$file]\n";
print "Will use lib:     [$lib]\n";
print "Will use include: [$inc]\n";

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'Packet.pm',
   PREREQ_PM     => {
      Time::HiRes   => 0,
      IO::Interface => 0,
      Net::Pcap     => 0.04,
   },
   ABSTRACT_FROM => 'Packet.pm',
   AUTHOR        => 'GomoR <netpkt@gomor.org>',
   LIBS          => [ "$lib -lpcap" ],
   DEFINE        => '',
   INC           => "-I. $inc",
   OBJECT        => '$(O_FILES)',
);

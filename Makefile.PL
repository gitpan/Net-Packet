use ExtUtils::MakeMaker;

die("*** Microsoft Windows not supported\n")
   if $^O =~ /windows|win32/i;
die("*** Big endian architectures not supported yet\n")
   if unpack("h*", pack("s", 1)) =~ /01/;

require DynaLoader;

my $file = DynaLoader::dl_findfile('-lpcap')
   or die("*** Cannot find libpcap, try setting LD_LIBRARY_PATH\n");

my ($lib) = $file =~ /^(.*)\//;
(my $inc  = $lib) =~ s/lib/include/;

sub _getPcapHPath { (-d "$inc/pcap") ? "[$inc/pcap]" : "[$inc]" }

unless (-f "$inc/pcap-int.h" || -f "$inc/pcap/pcap-int.h") {
   die("*** Cannot find pcap-int.h . Get it from your installed libpcap ".
       "source distribution and copy it to: ". _getPcapHPath().
       " (near pcap.h)\n");
}

$inc = "-I$inc -I$inc/pcap";
$lib = "-L$lib";

print "Found libpcap:    [$file]\n";
print "Will use lib:     [$lib]\n";
print "Will use include: [$inc]\n";

WriteMakefile(
   NAME          => 'Net::Packet',
   VERSION_FROM  => 'Packet.pm',
   PREREQ_PM     => {
      Time::HiRes        => 0,
      IO::Interface      => 0,
      Net::Pcap          => '0.04',
      Net::IPv6Addr      => 0,
      Socket6            => 0,
      Class::Gomor::Hash => '0.20',
   },
   ABSTRACT_FROM => 'Packet.pm',
   AUTHOR        => 'GomoR <netpkt@gomor.org>',
   LIBS          => [ "$lib -lpcap" ],
   DEFINE        => '',
   INC           => "-I. $inc",
   OBJECT        => '$(O_FILES)',
);

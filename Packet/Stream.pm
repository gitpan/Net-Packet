package Net::Packet::Stream;

use strict;
use warnings;
use Carp;

require Net::Packet;
our @ISA = qw(Net::Packet);

sub new {
   my $invocant = shift;
   my $class = ref($invocant) || $invocant;

   my $self = {
      file => '',
      @_,
   };
   bless($self, $class);

   confess
      "Usage: $class->new(\n".
      "          file => PCAP_FILE,\n".
      ")\n"
         unless
            $self->file
   ;

   return $self;
}

require Net::Packet::Dump;
require Net::Packet::Frame;

sub countTcpStreams {
   my $self = shift;

   my $dump = Net::Packet::Dump->new(file => $self->file);
   # XXX: should implement analyzeTcp
   # XXX: should implement analyzeWithFilter
   $dump->analyze;

   my $streams;
   # Match streams
   for ($dump->frames) {
      if ($_->isFrameTcp) {
         my $ipSrc = $_->ipSrc;
         my $ipDst = $_->ipDst;
         my $tcpSrc = $_->tcpSrc;
         my $tcpDst = $_->tcpDst;
         my $stream1 = "$ipSrc:$tcpSrc";
         my $stream2 = "$ipDst:$tcpDst";

         if (exists $streams->{"$stream2-$stream1"}) {
            push @{$streams->{"$stream2-$stream1"}}, $_;
         }
         else {
            push @{$streams->{"$stream1-$stream2"}}, $_;
         }
      }
   }

   for my $s (keys %$streams) {
      print "$s\n";
      for (@{$streams->{$s}}) {
         next unless $_->l7 && $_->l7->data;
         my $data = $_->l7->data;
         chomp ($data);
         print "> $data\n";
      }
      print "\n";
   }

   # Analyze tcpStream
}

sub count {
   my $self = shift;
   #return $self->tcpStreams->count + $self->udpStreams->count;
   return 0; # XXX: To implement
}

#
# Accessors
#

my @AccessorsScalar = qw(
   file
);
my @AccessorsArray = qw(
   tcpStreams
   udpStreams
);

for my $a (@AccessorsScalar) {
   no strict 'refs';
   *$a = sub { shift->_AccessorScalar($a, @_) }
}
for my $a (@AccessorsArray) {
   no strict 'refs';
   *$a = sub { shift->_AccessorArray($a, @_) }
}

1;

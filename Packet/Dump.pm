package Net::Packet::Dump;

# $Date: 2004/09/29 21:25:49 $
# $Revision: 1.1.1.1.2.4 $

use strict;
use warnings;
use Carp;

require Net::Packet;
our @ISA = qw(Net::Packet);

use Net::Packet::Frame;
use Net::Pcap;
use IO::File;
use Time::HiRes qw(gettimeofday);

BEGIN {
   $SIG{INT} = sub {
      $Net::Packet::Dump->DESTROY if $Net::Packet::Dump;
      exit 0;
   }
}

our @AccessorsScalar = qw(
   file
   filter
   overwrite
   waitOnStop
   timeoutOnNext
   nextFrame
   callStart
   isRunning
   unlinkOnDestroy
   noStore
   _pid
   _pcapd
   _pcapio
   _fpos
   _firstTime
);
our @AccessorsArray = qw(
   frames
);

sub new {
   my $self = shift->SUPER::new(
      file       => "netpkt-tmp-$$.@{[Net::Packet::getRandom32bitsInt]}.pcap",
      filter     => "",
      overwrite  => 0,
      waitOnStop => 3,
      timeoutOnNext   => 3,
      callStart       => 1,
      isRunning       => 0,
      unlinkOnDestroy => 1,
      noStore         => 0,
      frames          => [],
      @_,
   );

   $self->start if $self->callStart;

   return $Net::Packet::Dump = $self;
}

sub start {
   my $self = shift;

   if ($self->file && -f $self->file
   && ! $self->overwrite) {
      $self->debugPrint("`overwrite' parameter is undef, and file exists, ".
                        "we will only analyze it.");
      return 1;
   }
   else {
      croak("@{[(caller(0))[3]]}: \$Net::Packet::Dev variable not set")
         unless $Net::Packet::Dev;

      my $child = fork;
      croak("@{[(caller(0))[3]]}: fork: $!") unless defined $child;

      if ($child) {
         # Waiting child process to create pcap file
         my $count; # Just to avoid an infinite loop and report an error
         while (! -f $self->file) { last if ++$count == 100_000_000 };
         croak("@{[(caller(0))[3]]}: too long for netpacket_tcpdump to start")
            if $count && $count == 100_000_000;

         sleep(1); # Be sure the packet capture is ready

         $self->_pid($child);
         $SIG{CHLD} = 'IGNORE';
         $self->isRunning(1);
         return 1;
      }
      else {
         $self->debugPrint("dev:    [$Net::Packet::Dev]\n".
                           "file:   [@{[$self->file]}]\n".
                           "filter: [@{[$self->filter]}]");

         Net::Packet::netpacket_tcpdump(
            $Net::Packet::Dev,
            $self->file,
            $self->filter,
            1514,
            $Net::Packet::Promisc,
         ) or croak("@{[(caller(0))[3]]}: netpacket_tcpdump: $!");
      }
   }
}

sub stop {
   my $self = shift;

   if ($self->_pid) {
      sleep $self->waitOnStop if $self->waitOnStop;

      kill('TERM', $self->_pid);
      $self->_pid(undef);
   }

   if ($self->_pcapd) {
      Net::Pcap::close($self->_pcapd);
      $self->_pcapd(undef);
      $self->_pcapio(undef);
   }

   $self->isRunning(0);
}

sub _openFile {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: @{[$self->file]}: file not found")
      unless $self->file && -f $self->file;
         
   # Do not try to open if nothing is waiting
   return undef unless (stat($self->file))[7];

   my $err;
   $self->_pcapd(Net::Pcap::open_offline($self->file, \$err));
   unless ($self->_pcapd) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: @{[$self->file]}: ".
            "$err");
   }
}

sub _loopAnalyze {
   my ($userData, $hdr, $pkt) = @_;

   my $frame = Net::Packet::Frame->new(raw => $pkt);
   defined $frame
      ? push @$userData, $frame
      : carp("@{[(caller(0))[3]]}: unknown frame (number ",
             scalar @$userData, ")\n");
}

sub analyze {
   my $self = shift;

   unless ($self->_pcapd) {
      $self->_openFile || return ();
   }

   my @frames;
   Net::Pcap::loop($self->_pcapd, -1, \&_loopAnalyze, \@frames);
   $self->frames(\@frames);

   Net::Pcap::close($self->_pcapd);
   $self->_pcapd(undef);

   return @frames;
}

sub _addFrame {
   my $self = shift;

   my %hdr;
   my $frame;
   if (my $raw = Net::Pcap::next($self->_pcapd, \%hdr)) {
      $frame = Net::Packet::Frame->new(raw => $raw);
      unless ($self->noStore) {
         my @frames = $self->frames;
         push @frames, $frame;
         $self->frames(\@frames);
      }
   }

   return $frame;
}

sub next {
   my $self = shift;

   # Handle timeout
   my $thisTime = gettimeofday() if     $self->timeoutOnNext;
   $self->_firstTime($thisTime)  unless $self->_firstTime;

   if ($self->timeoutOnNext && $self->_firstTime) {
      if (($thisTime - $self->_firstTime) > $self->timeoutOnNext) {
         $Net::Packet::Timeout = 1;
         $self->_firstTime(0);
         $self->debugPrint("Timeout occured");
         return undef;
      }
   }

   # Open the savefile and bless it to IO::File the first time method is used
   unless ($self->_pcapd) {
      $self->_openFile || return undef;
      $self->_pcapio(
         bless(Net::Packet::netpacket_pcap_fp($self->_pcapd), 'IO::File')
      );
   }

   # If it is not the first time the function is called, we setpos
   $self->_pcapio->setpos($self->_fpos) if $self->_fpos;

   my $frame = $self->_addFrame;
   $self->_fpos($self->_pcapio->getpos);
   $self->_firstTime(0) if $frame; # Frame received, so reset timeout var

   return $self->nextFrame($frame);
}

sub DESTROY {
   my $self = shift;

   $self->waitOnStop(0);
   $self->stop;

   if ($self->unlinkOnDestroy
   &&  $self->unlinkOnDestroy && -f $self->file) {
      unlink $self->file;
      $self->debugPrint("@{[$self->file]} removed");
   }

   $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}

#
# Accessors
#

for my $a (@AccessorsScalar) {
   no strict 'refs';
   *$a = sub { shift->_AccessorScalar($a, @_) }
}
for my $a (@AccessorsArray) {
   no strict 'refs';
   *$a = sub { shift->_AccessorArray($a, @_) }
}

1;

__END__

=head1 NAME

Net::Packet::Dump - an interface for a tcpdump-like process and a frame analyzer

=head1 SYNOPSIS

   #
   # Example offline analysis
   #

   use Net::Packet::Dump;
   my $dump = Net::Packet::Dump->new(filter => "tcp and dst host $Net::Packet::Ip");

   # Code sending packets
   ...
   sleep(5);

   for ($dump->analyze) {
      # Play with what have been captured
      # See Net::Packet::Frame for packet format
   }


   #
   # Example live analysis
   #

   use Net::Packet::Dump;
   my $dump =  Net::Packet::Dump->new(
      filter        => "tcp and dst host $Net::Packet::Ip",
      timeoutOnNext => 5,
   );

   until ($Net::Packet::Timeout) {
      # Code sending packets here

      if ($dump->next) {
         $dump->nextFrame->l3->print;
         # Code analyzing reply here
      }
   }

=head1 DESCRIPTION

This module provides an interface for a tcpdump-like process creator and a frame analyzer. When you call the new method, an object is returned with some default values set, and the global $Net::Packet::Dump is set with it.

=head1 OPTIONS

=over 4

=item B<callStart> < BOOL >

If set to a true value, the start method will be called on the new object creation. It is the default.

=item B<file> < SCALAR >

This specifies in which file to store the captured frames, stored in a .pcap format file. The default is to create a randomly named file (like netpkt-tmp-PID-RANDOM32BITSINT.pcap).

=item B<unlinkOnDestroy> < SCALAR >

When set to 1, the file used to capture frames will be deleted after it has become out of scope (from a Perl perspective). The default is 1, so if you want to keep the file, set it to 0.

=item B<filter> < SCALAR >

This sets the filter used to capture frames, in a pcap filter format. You can use the method Net::Packet::Frame::getFilter to automatically set it from a Net::Packet::Frame object. See Net::Packet::Frame. The default is to set an empty filter, in order to capture all frames.

=item B<overwrite> < SCALAR >

When set to 1, will overwrite an existing file. If not, it will only analyze an existing one, or create a new file if it does not exist. The default is to not overwrite.

=item B<waitOnStop> < SCALAR >

When you call the stop method, you can specify a timeout before stopping the capture. The default is to sleep for 3 seconds.

=item B<noStore> < SCALAR >

When set to 1, the method next will not add the analyzed frame into the frames array, in order to avoid memory exhaustion. The default is to store frames (so to perform memory exhaustion ;) ).

=item B<timeoutOnNext> < SCALAR >

When set to a value, a timeout will occur if no new frame is received within the SCALAR value seconds. The default is 3 seconds. A 0 value means no timeout at all. If a timeout occur, the global $Net::Packet::Timeout is set to a true value.

=back

=head1 METHODS

=over 4

=item B<new> ( OPTIONS )

Create an object. The global $Net::Packet::Dump variable will be set to the newly created object. The default is to auto-call the start method, to override this set the callStart option to 0. Also the file created will be deleted after the object goes out of scope, use unlinkOnDestroy option to change this behaviour.

=item B<start>

Start packet capture, the file specified is created, unless it exists and the overwrite option is not set. The instance date isRunning is set to 1.

=item B<isRunning>

Returns 1 or 0 respectively if the process is running or not.

=item B<stop>

Stop packet capture. isRunning is set to 0, and the file is not touched, only when the object goes out of scope does this.

=item B<analyze>

Parse captured packets (from a .pcap file) and return an array of Net::Packet::Frame objects.

=item B<frames>

Returns the analyzed frames as an array of Net::Packet::Frame objects, or an empty array if none have been analyzed.

=item B<next>

Returns the next captured frame as a Net::Packet::Frame object. Returns undef if no frame is waiting to be analyzed. By default, all new captured frames are stored into the frames array (accessed through frames method). The noStore option avoids this. If you have used the timeoutOnNext option, the global $Net::Packet::Timeout will be set to a true value, and undef value returned. Also, when the next awaiting frame is captured, it is stored in the nextFrame object data.

=item B<nextFrame>

When the method next is called, and a frame was found and analyzed, it is stored here, and can be accessed by calling this method.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

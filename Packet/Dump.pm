#
# $Id: Dump.pm,v 1.2.2.45 2006/05/13 09:53:59 gomor Exp $
#
package Net::Packet::Dump;
use strict;
use warnings;
use Carp;

require Class::Gomor::Hash;
our @ISA = qw(Class::Gomor::Hash);

use Net::Packet qw($Env);
require Net::Packet::Frame;
use Net::Packet::Utils qw(getRandom32bitsInt getPcapLink);

use Net::Pcap;
use IO::File;
use Time::HiRes qw(gettimeofday);

our @AS = qw(
   env
   file
   filter
   overwrite
   waitOnStop
   timeoutOnNext
   timeout
   nextFrame
   callStart
   isRunning
   unlinkOnDestroy
   noStore
   noLayerWipe
   noEnvSet
   _offlineMode
   _pid
   _pcapd
   _stats
   _firstTime
);
our @AA = qw(
   frames
);
our @AO = qw(
   framesSorted
);

__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray(\@AA);

BEGIN {
   my $osname = {
      cygwin  => \&_killTcpdumpWin32,
      MSWin32 => \&_killTcpdumpWin32,
   };

   *killTcpdump = $osname->{$^O} || \&_killTcpdumpOther;
}

our @dumpList = ();
$SIG{INT} = sub { $_->DESTROY for @dumpList; exit 0 };

sub new {
   my $self = shift->SUPER::new(
      env        => $Env,
      file       => "netpacket-tmp-$$.@{[getRandom32bitsInt()]}.pcap",
      filter     => "",
      overwrite  => 0,
      waitOnStop => 3,
      timeout    => 0,
      timeoutOnNext   => 3,
      callStart       => 1,
      isRunning       => 0,
      unlinkOnDestroy => 1,
      noStore         => 0,
      noLayerWipe     => 0,
      noEnvSet        => 0,
      framesSorted    => {},
      frames          => [],
      _offlineMode    => 0,
      @_,
   );

   push @dumpList, $self;

   (! $self->overwrite && $self->file && -f $self->file)
      ? $self->_offlineMode(1)
      : $self->_offlineMode(0);

   $self->start if $self->callStart;

   $self->env->dump($self) unless $self->noEnvSet;

   $self;
}

sub start {
   my $self = shift;

   if ($self->file && -f $self->file
   && ! $self->overwrite) {
      $self->cgDebugPrint(1, "`overwrite' parameter is 0, and file exists, ".
                             "we will only analyze it.");
      return 1;
   }
   else {
      my $child = fork;
      croak("@{[(caller(0))[3]]}: fork: $!\n") unless defined $child;

      if ($child) {
         # Waiting child process to create pcap file
         my $count; # Just to avoid an infinite loop and report an error
         while (! -f $self->file) { last if ++$count == 100_000_000 };
         croak("@{[(caller(0))[3]]}: too long for tcpdump process to start\n")
            if $count && $count == 100_000_000;

         sleep(1); # Be sure the packet capture is ready

         $self->_pid($child);
         $SIG{CHLD} = 'IGNORE';
         $self->isRunning(1);
         return 1;
      }
      else {
         $self->cgDebugPrint(1, "dev:    [@{[$self->env->dev]}]\n".
                                "file:   [@{[$self->file]}]\n".
                                "filter: [@{[$self->filter]}]");

         $< = $>; # Gives full root here, cause of file creation.
                  # For setuid programs to work.

         $SIG{TERM} = sub { $self->DESTROY };
         $SIG{INT}  = sub { $self->DESTROY };

         $self->isRunning(1);
         $self->_startTcpdump;
         exit(0);
      }
   }
}

sub _startTcpdump {
   my $self = shift;

   my $err;
   my $pd = Net::Pcap::open_live(
      $self->env->dev,
      1514,
      $self->env->promisc,
      1000,
      \$err,
   );
   unless ($pd) {
      croak("@{[(caller(0))[3]]}: open_live: $err\n");
   }

   my $net;
   my $mask;
   Net::Pcap::lookupnet($self->env->dev, \$net, \$mask, \$err);
   if ($err) {
      croak("@{[(caller(0))[3]]}: lookupnet: $err\n");
   }

   my $fcode;
   if (Net::Pcap::compile($pd, \$fcode, $self->filter, 0, $mask) < 0) {
      croak("@{[(caller(0))[3]]}: compile: ". Net::Pcap::geterr($pd). "\n");
   }

   if (Net::Pcap::setfilter($pd, $fcode) < 0) {
      croak("@{[(caller(0))[3]]}: setfilter: ". Net::Pcap::geterr($pd). "\n");
   }

   my $p = Net::Pcap::dump_open($pd, $self->file);
   unless ($p) {
      croak("@{[(caller(0))[3]]}: dump_open: ". Net::Pcap::geterr($pd). "\n");
   }

   $self->_pcapd($pd);

   Net::Pcap::loop($pd, -1, \&_tcpdumpCallback, $p);
   Net::Pcap::close($pd);
}

sub _tcpdumpCallback {
   my ($p, $hdr, $pkt) = @_;

   Net::Pcap::dump($p, $hdr, $pkt);
   Net::Pcap::dump_flush($p);
}

sub _killTcpdumpWin32 { kill('KILL', shift->_pid) }
sub _killTcpdumpOther { kill('TERM', shift->_pid) }

sub stop {
   my $self = shift;

   # Father part, it kills its son
   if ($self->_pid) {
      sleep $self->waitOnStop if $self->waitOnStop;

      $self->killTcpdump;
      $self->_pid(undef);

      $self->isRunning(0);
      return;
   }

   # Son part, it prints pcap stats.
   # Currently, on Windows, it does not work, because 
   # Windows cannot receive signals
   if ($self->isRunning && $self->_pcapd) {
      $self->getStats;
      Net::Pcap::close($self->_pcapd);

      $self->cgDebugPrint(1, 'Frames received  : '. $self->_stats->{ps_recv});
      $self->cgDebugPrint(1, 'Frames dropped   : '. $self->_stats->{ps_drop});
      $self->cgDebugPrint(1, 'Frames if dropped: '. $self->_stats->{ps_ifdrop});

      $self->env && $self->env->link(undef);
      $self->_pcapd(undef);

      $self->isRunning(0);
      exit(0);
   }
}

sub getStats {
   my $self = shift;

   carp("@{[(caller(0))[3]]}: unable to get stats, no pcap descriptor open\n")
      unless $self->_pcapd;
   
   my %stats;
   Net::Pcap::stats($self->_pcapd, \%stats);
   $self->_stats(\%stats);
}

sub flush {
   my $self = shift;
   $self->frames([]);
   $self->{framesSorted} = {};
}

sub _setFilter {
   my $self = shift;

   return unless $self->filter;

   my ($net, $mask, $err);
   Net::Pcap::lookupnet($self->env->dev, \$net, \$mask, \$err);
   if ($err) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::lookupnet: @{[$self->env->dev]}: ".
            "$err\n");
   }

   my $filter;
   Net::Pcap::compile($self->_pcapd, \$filter, $self->filter, 0, $mask);
   croak("@{[(caller(0))[3]]}: Net::Pcap::compile: error\n") unless $filter;

   Net::Pcap::setfilter($self->_pcapd, $filter);
}

sub _openFile {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: @{[$self->file]}: file not found\n")
      unless $self->file && -f $self->file;
         
   # Do not try to open if nothing is waiting
   return undef unless (stat($self->file))[7];

   my $err;
   $self->_pcapd(Net::Pcap::open_offline($self->file, \$err));
   unless ($self->_pcapd) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: @{[$self->file]}: ".
            "$err\n");
   }

   $self->_setFilter if $self->_offlineMode;
   $self->env->link(getPcapLink($self->_pcapd));
}

sub _loopAnalyze {
   my ($userData, $hdr, $pkt) = @_;

   my $frame = Net::Packet::Frame->new(raw => $pkt) or return undef;
   defined $frame
      ? push @$userData, $frame
      : carp("@{[(caller(0))[3]]}: unknown frame (number ".
             scalar(@$userData). ")\n");
}

sub _addFrame {
   my $self = shift;

   my %hdr;
   my $frame;
   if (my $raw = Net::Pcap::next($self->_pcapd, \%hdr)) {
      $frame = Net::Packet::Frame->new(raw => $raw) or return undef;
      unless ($self->noStore) {
         $self->framesSorted($frame);
         my @frames = $self->frames;
         push @frames, $frame;
         $self->frames(\@frames);
      }
      return $frame;
   }

   undef;
}

sub next {
   my $self = shift;

   # Handle timeout
   my $thisTime = gettimeofday() if     $self->timeoutOnNext;
   $self->_firstTime($thisTime)  unless $self->_firstTime;

   if ($self->timeoutOnNext && $self->_firstTime) {
      if (($thisTime - $self->_firstTime) > $self->timeoutOnNext) {
         $self->timeout(1);
         $self->_firstTime(0);
         $self->cgDebugPrint(1, "Timeout occured");
         return undef;
      }
   }

   # Open the savefile
   unless ($self->_pcapd) {
      $self->_openFile || return undef;
   }

   my $frame = $self->_addFrame;
   $self->_firstTime(0) if $frame; # Frame received, reset

   $frame ? $self->nextFrame($frame) : undef;
}

sub nextAll {
   my $self = shift;
   while ($self->next) {}
}

sub analyze { shift->nextAll }

sub framesFor {
   my $self  = shift;
   my $frame = shift;

   my $l2Key = "all";
   $l2Key = $frame->l2->getKeyReverse($frame) if $frame->l2;

   my $l3Key = "all";
   $l3Key = $frame->l3->getKeyReverse($frame) if $frame->l3;

   my $l4Key = "all";
   $l4Key = $frame->l4->getKeyReverse($frame) if $frame->l4;

   $self->{framesSorted}{$l2Key}{$l3Key}{$l4Key}
      ? @{$self->{framesSorted}{$l2Key}{$l3Key}{$l4Key}}
      : ();
}

sub DESTROY {
   my $self = shift;

   $self->waitOnStop(0);
   $self->stop;

   if ($self->unlinkOnDestroy && -f $self->file) {
      unlink($self->file);
      $self->cgDebugPrint(1, "@{[$self->file]} removed");
   }
}

#
# Other accessors
#

sub framesSorted {
   my ($self, $frame) = (shift, shift);

   my $env = $self->env;

   if ($frame) {
      # Wipe headers, since if not, framesFor() will not be able to find them.
      # Because if you create a Frame from L3, no headers are set for L2, but 
      # the Dump will have them and store them into the l2Key.
      if ($env->desc && ! $self->noLayerWipe) {
         $frame->l2(undef) if ref($env->desc) =~ /L3|L4/;
         $frame->l3(undef) if ref($env->desc) =~ /L4/;
      }

      my $l2Key = "all";
      $l2Key = $frame->l2->getKey($frame) if $frame->l2;

      my $l3Key = "all";
      $l3Key = $frame->l3->getKey($frame) if $frame->l3;

      my $l4Key = "all";
      $l4Key = $frame->l4->getKey($frame) if $frame->l4;

      push @{$self->{framesSorted}{$l2Key}{$l3Key}{$l4Key}}, $frame;

      # We store a second time for ICMP messages
      if ($frame->isIcmp) {
         $l3Key = 'all';
         $l3Key = $frame->l3->is.':'.$frame->l3->dst if $frame->l3;
         push @{$self->{framesSorted}{$l2Key}{$l3Key}{$l4Key}}, $frame;
      }
   }

   $self->{framesSorted};
}

1;

__END__

=head1 NAME

Net::Packet::Dump - a tcpdump-like object providing frame capturing

=head1 SYNOPSIS

   use Net::Packet::Dump;

   #
   # Example live capture (sniffer like)
   #

   # Instanciate object, will start capturing from network
   my $dump = Net::Packet::Dump->new(
      filter  => 'tcp',
      noStore => 1,
   );

   while (1) {
      if (my $frame = $dump->next) {
         print $frame->l2->print, "\n" if $frame->l2;
         print $frame->l3->print, "\n" if $frame->l3;
         print $frame->l4->print, "\n" if $frame->l4;
         print $frame->l7->print, "\n" if $frame->l7;
      }
   }

   #
   # Example offline analysis
   #

   my $dump2 = Net::Packet::Dump->new(
      unlinkOnDestroy => 0,
      file            => 'existant-file.pcap',
      callStart       => 0,
   );

   # Analyze the .pcap file, build an array of Net::Packet::Frame's
   $dump->analyze;

   # Browses captured frames
   for ($dump->frames) {
      # Do what you want
      print $_->l2->print, "\n" if $_->l2;
      print $_->l3->print, "\n" if $_->l3;
      print $_->l4->print, "\n" if $_->l4;
      print $_->l7->print, "\n" if $_->l7;
   }

=head1 DESCRIPTION

This module is the capturing part of Net::Packet framework. It is basically a tcpdump process. When a capture starts, the tcpdump process is forked, and saves all traffic to a .pcap file. The parent process can call B<next>, B<nextAll> or B<analyze> to convert captured frames from .pcap file to B<Net::Packet::Frame>s.

Then, you can call B<recv> method on your sent frames to see if a corresponding reply is waiting in the B<frames> array attribute of B<Net::Packet::Dump>.

By default, if you use this module to analyze frames you've sent (very likely ;)), and you've sent those frames at layer 4 (using B<Net::Packet::DescL4>) (for example), lower layers will be wiped on storing in B<frames> array. This behaviour can be disabled using B<noLayerWipe> attribute.

=head1 ATTRIBUTES

=over 4

=item B<env>

Stores a B<Net::Packet::Env> object. It is used in B<start> method, for example. The default is to use the global B<$Env> object created when using B<Net::Packet>.

=item B<file>

Where to save captured frames. By default, a random name file is chosen, named like `netpacket-tmp-$$.@{[getRandom32bitsInt()]}.pcap'.

=item B<filter>

A pcap filter to restrain what to capture. It also works in offline mode, to analyze only what you want, and not all traffic. Default to capture all traffic. WARNING: every time a packet passes this filter, and the B<next> method is called, the internal counter used by b<timeoutOnNext> is reset. So the B<timeout> attribute can only be used if you now exactly that the filter will only catch what you want and not perturbating traffic.

=item B<overwrite>

If the B<file> exists, setting this to 1 will overwrite it. Default to not overwrite it.

=item B<waitOnStop>

When the B<stop> method is called, you should wait a few seconds before stopping the capture. The default is to wait for 3 seconds.

=item B<timeout>

Is auto set to 1 when a timeout has occured. It is not set to 0 automatically, you need to do it yourself.

=item B<timeoutOnNext>

Each time B<next> method is called, an internal counter is incremented if no frame has been capture. When a frame is captured (that is, a frame passed the pcap filter), the B<timeout> attribute is reset to 0. When the counter reaches the value of B<timeoutOnNext>, the B<timeout> attribute is set to 1, meaning no frames have been captured during the specified amount of time. Default to 3 seconds.

=item B<nextFrame>

This one stores the latest received frame after a call to B<next> method. If a B<next> call is done, and no frame is received, this attribute is set to undef.

=item B<callStart>

When set to 1, the capturing process starts right after B<new> method has finished executing. When set to 0, you must call B<start> method to start capturing. Default to 1.

=item B<isRunning>

When the capturing process is running, this is set to 1. So, when B<start> method has been called, it is set to 1, and when B<stop> method is called, set to 0.

=item B<unlinkOnDestroy>

When the B<Net::Packet::Dump> object goes out of scope, the B<DESTROY> method is called, and if this attribute is set to 1, the B<file> is removed. BEWARE: default to 1.

=item B<noStore>

If you set this attribute to 1, frames will not be stored in B<frames> array. It is used in sniffer-like programs, in order to avoid memory exhaustion by keeping all captured B<Net::Packet::Frame> into memory. Default is to store frames.

=item B<noLayerWipe>

As explained in DESCRIPTION, if you send packets at layer 4, layer 2 and 3 are not keeped when stored in B<frames>. The same is true when sending at layer 3 (layer 2 is not kept). Default to wipe those layers. WARNING: if you set it to 1, and you need the B<recv> method from B<Net::Packet::Frame>, it will fail. In fact, this is a speed improvements, that is in order to find matching frame for your request, they are stored in a hash, using layer as keys (B<getKey> and B<getKeyReverse> are used to get keys from each layer. So, if you do not wipe layers, a key will be used to store the frame, but another will be used to search for it, and no match will be found. This is a current limitation I'm working on to remove.

=item B<noEnvSet>

By default, when a B<Net::Packet::Dump> object is created, the default B<$Env> object has its B<dump> attribute pointing to it. If you do not want this behaviour, you can disable it by setting it to 1. Default to 0.

=item B<frames>

Stores all analyzed frames found in a pcap file in this array.

=item B<framesSorted>

Stores all analyzed frames found in a pcap file in this hash, using keys to store and search related packet request/replies.

=back

=head1 METHODS

=over 4

=item B<new>

Object contructor. Default values for attributes:

env:             $Env

file:            "netpacket-tmp-$$.@{[getRandom32bitsInt()]}.pcap"

filter:          ""

overwrite:       0

waitOnStop:      3

timeout:         0

timeoutOnNext:   3

callStart:       1

isRunning:       0

unlinkOnDestroy: 1

noStore:         0

noLayerWipe:     0

noEnvSet:        0

=item B<start>

Forks the tcpdump-like process that do frame capturing saved to a file. It does not forks a new process if the specified B<file> attribute exists, and B<overwrite> attributes is set to 0. It also sets B<isRunning> to 1 if a process is forked.

=item B<getStats>

Tries to get packet statistics on an open descriptor. It returns a reference to a hash that has to following fields: B<ps_recv>, B<ps_drop>, B<ps_ifdrop>.

=item B<stop>

Kills the tcpdump-like process, and sets B<isRunning> to 0. It first waits B<waitOnStop> seconds before killing it.

=item B<flush>

Will removed all analyzed frames from B<frames> array and B<framesSorted> hash. Use it with caution, because B<recv> from B<Net::Packet::Frame> relies on those.

=item B<next>

Returns the next captured frames; undef if none found in .pcap file. In all cases, B<nextFrame> attribute is set (either to the captured frame or undef). Each time this method is run, a comparison is done to see if no frame has been captured during B<timeoutOnNext> amount of seconds. If so, B<timeout> attribute is set to 1 to reflect the pending timeout. When a frame is received, it is stored in B<frames> array, and in B<framesSorted> hash, used to quickly B<recv> it (see B<Net::Packet::Frame>), and internal counter for time elapsed since last received packet is reset.

=item B<nextAll>

=item B<analyze>

Calls B<next> method until it returns undef (meaning no new frame waiting to be analyzed from pcap file).

=item B<framesFor> (scalar)

You pass a B<Net::Packet::Frame> has parameter, and it returns an array of all frames relating to the connection. For example, when you send a TCP SYN packet, this method will return TCP packets relating to the used source/destination IP, source/destination port, and also related ICMP packets.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

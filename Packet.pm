package Net::Packet;

# $Date: 2004/12/02 19:40:20 $
# $Revision: 1.1.1.1.2.7.2.1 $

require v5.6.1;

use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT_OK = qw(
   &autoDev
   &autoIp
   &autoMac
   &getHostIpv4Addr
   &getHostIpv4Addrs
   &getRandom16bitsInt
   &getRandom32bitsInt
   &inetChecksum
   &convertMac
   $Err
   $Debug
   $Dev
   $Ip
   $Mac
   $Dump
   $Desc
   $Promisc
   $Timeout
);
our %EXPORT_TAGS = (
   globals => [ qw( $Err $Debug $Dev $Ip $Mac $Dump $Desc $Promisc $Timeout ) ],
   subs    => [ qw( autoDev autoIp autoMac getHostIpv4Addr getHostIpv4Addrs getRandom16bitsInt getRandom32bitsInt inetChecksum convertMac ) ],
);

our $VERSION = '1.28';

use Net::Pcap;
use IO::Socket::INET;
use IO::Interface;

our $_UdpSocket;

BEGIN {
   die("Must be EUID 0 to use Net::Packet") if $>;

   die("Big endian architectures not supported yet")
      if unpack("h*", pack("s", 1)) =~ /01/;

   $_UdpSocket = IO::Socket::INET->new(Proto => 'udp')
      or die("@{[(caller(0))[3]]}: IO::Socket::INET->new: $!\n");
}

CHECK {
   autoDev();
   autoIp();
   autoMac();
}

sub AUTOLOAD {
   # This AUTOLOAD is used to 'autoload' constants from the constant()
   # XS function.  If a constant is not found then control is passed
   # to the AUTOLOAD in AutoLoader.

   my $constname;
   our $AUTOLOAD;
   ($constname = $AUTOLOAD) =~ s/.*:://;
   croak "& not defined" if $constname eq 'constant';
   my $val = constant($constname, @_ ? $_[0] : 0);
   if ($! != 0) {
      if ($! =~ /Invalid/ || $!{EINVAL}) {
         $AutoLoader::AUTOLOAD = $AUTOLOAD;
         goto &AutoLoader::AUTOLOAD;
      }
      else {
         croak "Your vendor has not defined Net::Packet macro $constname";
      }
   }
   {
      no strict 'refs';
      # Fixed between 5.005_53 and 5.005_61
      if ($] >= 5.00561) {
         *$AUTOLOAD = sub () { $val };
      }
      else {
         *$AUTOLOAD = sub { $val };
      }
   }
   goto &$AUTOLOAD;
}

bootstrap Net::Packet $VERSION;

our $Err;
our $Debug;

our $Dev;
our $Ip;
our $Mac;
our $Desc;
our $Dump;
our $Promisc = 0;
our $Timeout = 0;

sub new {
   my $invocant = shift;
   my $class = ref($invocant) || $invocant;

   $class->checkParams({ @_ }, [ $class->getAccessors ])
      or croak($Err);

   return bless({ @_ }, $class);
}

sub autoDev {
   return $Dev if $Dev;

   my $err;
   $Dev = Net::Pcap::lookupdev(\$err);
   if (defined $err) {
      warn("@{[(caller(0))[3]]}: Net::Pcap::lookupdev: $err ; ".
           "unable to autochoose Dev");
   }

   return $Dev;
}

sub autoIp {
   return $Ip if $Ip;

   $Ip = $_UdpSocket->if_addr($Dev)
      or warn("@{[(caller(0))[3]]}: unable to autochoose IP from $Dev");

   return $Ip;
}

sub _ifconfigGetMac {
   return undef unless $Dev =~ /^[a-z]+[0-9]+$/;
   my $buf = `/sbin/ifconfig $Dev 2> /dev/null`;
   $buf =~ /([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i;
   $1 ? return lc($1)
      : return 'ff:ff:ff:ff:ff:ff';
}

sub autoMac {
   return $Mac if $Mac;

   # On some systems, if_hwaddr simply does not work, we try to get MAC from 
   # `ifconfig $Dev`
   unless ($Mac = $_UdpSocket->if_hwaddr($Dev) || _ifconfigGetMac()) {
      warn("@{[(caller(0))[3]]}: unable to autochoose Mac from $Dev");
   }

   return $Mac;
}

sub getHostIpv4Addr {
   my $name  = shift;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
   my @addrs = (gethostbyname($name))[4];
   @addrs
      ? return join('.', unpack('C4', $addrs[0]))
      : warn("@{[(caller(0))[3]]}: unable to resolv $name");
   return undef;
}

sub getHostIpv4Addrs {
   my $name  = shift;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
   my @addrs = (gethostbyname($name))[4];
   @addrs
      ? return @addrs
      : warn("@{[(caller(0))[3]]}: unable to resolv $name");
   return ();
}

sub getRandomHighPort {
   my $highPort = int rand 0xffff;
   $highPort += 1024 if $highPort < 1025;
   return $highPort;
}

sub getRandom32bitsInt { return int rand 0xffffffff }
sub getRandom16bitsInt { return int rand 0xffff }

sub convertMac {
   my $mac = shift;
   $mac =~ s/(..)/$1:/g;
   $mac =~ s/:$//;
   return lc $mac;
}

sub inetChecksum {
   my $phpkt = shift;

   $phpkt      .= "\x00" if length($phpkt) % 2;
   my $len      = length $phpkt;
   my $nshort   = $len / 2;
   my $checksum = 0;
   $checksum   += $_ for unpack("S$nshort", $phpkt);
   $checksum   += unpack('C', substr($phpkt, $len - 1, 1)) if $len % 2;
   $checksum    = ($checksum >> 16) + ($checksum & 0xffff);

   return ~(($checksum >> 16) + $checksum) & 0xffff;
}

sub debugPrint {
   return unless $Debug;

   my ($invocant, $msg) = @_;
   (my $pm = ref($invocant) || $invocant) =~ s/^Net::Packet:://;
   $msg =~ s/^/DEBUG: $pm: /gm;
   print STDERR "$msg\n";
}

sub checkParams {
   my ($invocant, $userParams, $accessors) = @_;
   my $class = ref($invocant) || $invocant;

   for my $u (keys %$userParams) {
      my $valid;
      my $defined;
      for (@$accessors) {
         $u eq $_ ? $valid++ : next;
         do { $defined++; last; } if defined $userParams->{$u};
      }
      unless ($valid) {
         $Err = "$class: invalid parameter: `$u'";
         return undef;
      }
      unless ($defined) {
         $Err = "$class: parameter is undef: `$u'";
         return undef;
      }
   }

   return 1;
}

sub getAccessors {
   my $self = shift;

   no strict 'refs';

   my @accessors;
   @accessors = ( @{$self. '::AccessorsScalar'} )
      if @{$self. '::AccessorsScalar'};
   @accessors = ( @accessors, @{$self. '::AccessorsArray'})
      if @{$self. '::AccessorsArray'};

   return @accessors;
}

sub _AccessorScalar {
   my ($self, $sca) = (shift, shift);
   @_ ? $self->{$sca} = shift
      : $self->{$sca};
}

sub _AccessorArray {
   my ($self, $ary) = (shift, shift);
   @_ ? $self->{$ary} = shift
      : @{$self->{$ary}};
}

1;

__END__

=head1 NAME

Net::Packet - a unified framework to read and write packets over networks from layer 2 to layer 7

=head1 CLASS HIERARCHY

  Net::Packet
     |
     +---Net::Packet::Dump
     |
     +---Net::Packet::Desc
     |      |
     |      +---Net::Packet::DescL2
     |      |
     |      +---Net::Packet::DescL3
     |      |
     |      +---Net::Packet::DescL4
     |      |
     |      +---Net::Packet::DescL7
     |
     +---Net::Packet::Frame
            |
            +---Net::Packet::Layer
                   |
                   +---Net::Packet::Layer2
                   |      |
                   |      +---Net::Packet::ETH
                   |
                   +---Net::Packet::Layer3
                   |      |
                   |      +---Net::Packet::ARP
                   |      |
                   |      +---Net::Packet::IPv4
                   |
                   +---Net::Packet::Layer4
                   |      |
                   |      +---Net::Packet::TCP
                   |      |
                   |      +---Net::Packet::UDP
                   |      |
                   |      +---Net::Packet::ICMPv4
                   |
                   +---Net::Packet::Layer7
   
  Net::Packet::Simple

=head1 DESCRIPTION

This module is a unified framework to craft, send and receive packets at layers 2, 3, 4 and 7 (but 4 and 7 are just here for completeness, they have not been thoroughly tested. And you should use IO::Socket for layer 7, anyway).

Basically, you forge each layer of a frame (Net::Packet::IPv4 for layer 3, Net::Packet::TCP for layer 4 ; for example), and pack all of this into a Net::Packet::Frame object. Then, you can write it to the network, and use Net::Packet::Dump to receive responses.

=head1 GETTING STARED

When you use Net::Packet for the first time in a program, three package variables are automatically set in Net::Packet module: $Net::Packet::Dev, $Net::Packet::Ip, and $Net::Packet::Mac. They are taken from the default interface on your machine, the one taken by tcpdump when not user specified. I recommand you to set the package variable $Net::Packet::Debug to 3 when you are a beginner with this module.

   use Net::Packet;
   $Net::Packet::Debug = 3;

Let's create your first Net::Packet::Frame. We will build a TCP packet and send it at layer 3, so we must craft Net::Packet::IPv4 and Net::Packet::TCP headers.

   use Net::Packet::Frame;
   my $ip = Net::Packet::IPv4->new(
      dst => $desc->ipDst,
   );
   my $tcp = Net::Packet::TCP->new(
      dst => 22,
   );

You do not need to set the source IP, since it will be taken from the package variable $Net::Packet::Ip. Also, reasonable defaults are set for other fields in those two layers. See Net::Packet::IPv4 and Net::Packet::TCP for more. If you need to change default interface and/or IP, you can always overwrite it at the beginning of your program by manually setting $Net::Packet::Dev and/or $Net::Packet::Ip.

You have your layers 3 and 4, you can pack all into a frame:

   my $frame = Net::Packet::Frame->new(l3 => $ip, l4 => $tcp);

This step also automatically creates the descriptor that will be used to send frames over the network. That is, since you create a frame starting at layer 3, a Net::Packet::DescL3 object will be automatically created. The global $Net::Packet::Desc will be set to point to it. If you do not want to have an auto-creation of descriptor, you can always create it manually before calling Net::Packet::Frame->new, it will not be overwritten. See Net::Packet::Desc.

Also, a Net::Packet::Dump object is created (that is a tcpdump-like process), but not started for now. The $Net::Packet::Dump global is also written to point to it. If you do not want it to be auto-created, you can create one manually before calling Net::Packet::Frame->new for the first time. See Net::Packet::Dump.

Then, your frame is ok, you can send it over the network in order to receive your response:

   $frame->send;

When the first frame is sent using this method, the Net::Packet::Dump process is started, and ready to receive replies, unless it is already started.

You can sleep a few seconds, and then analyze for the response (if any):

   sleep(3);

   $Net::Pkt::Dump->analyze; # Analyze what have been captured by tcpdump, and
                             # unpack all frames into Net::Packet::Frame format

   my $reply = $frame->recv; # Get the Net::Packet::Frame corresponding to 
                             # the Net::Packet::Frame request from captured 
                             # frames stored in $Net::Packet::Dump->frames

   # Print response content, if any
   if ($reply) {
      $reply->ipPrint;
      $reply->tcpPrint;
   }


An alternative way is to use the global $Net::Packet::Timeout, which is set to 1 if no frame at all have been received from a certain amount of time. Be sure to create a Net::Packet::Dump object with a good pcap filter, because even if the packet read from the network is not destinated to your request, it resets the timeout. See Net::Packet::Dump.

   until ($Net::Packet::Timeout) {
      if ($Net::Packet::Dump->next && $frame->recv) {
         print "\nReply:\n";
         $frame->reply->ipPrint;
         $frame->reply->tcpPrint;
         last;
      }
   }

The method next only analyze for the next captured frame, but the analyze method is more a one shot since it analyzes all captured frames. See Net::Packet::Dump.

For more examples, see the examples directory in the source tarball.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES  

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut

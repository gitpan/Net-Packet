use Test;
BEGIN { plan(tests => 1) }

skip(! $ENV{NP_DO_TEST} ? 'Skip since env variable NP_DO_TEST=0' : '', sub {
   my $ok;
   use Net::Packet qw($Env);
   use Net::Packet::Consts qw(:icmpv4 :ipv4);

   $Env->dev($ENV{NP_LO_DEV});
   $Env->ip ($ENV{NP_LO_IP});
   $Env->debug(3) if $ENV{NP_DEBUG};

   require Net::Packet::IPv4;
   require Net::Packet::ICMPv4;
   require Net::Packet::Frame;

   my $l3 = Net::Packet::IPv4->new(
      dst      => $ENV{NP_LO_TARGET_IP},
      protocol => NP_IPv4_PROTOCOL_ICMPv4,
   );

   my $l4 = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_ECHO_REQUEST,
      data => "test",
   );

   my $frame = Net::Packet::Frame->new(l3 => $l3, l4 => $l4);
   $frame->send;

   until ($Env->dump->timeout) {
      if ($frame->recv) {
         $ok++;
         last;
      }
   }

   $ok;
});

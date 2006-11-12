use Test;
BEGIN { plan(tests => 1) }

use Net::Packet::Frame;
use Net::Packet::ARP;
use Net::Packet::ETH;
use Net::Packet::ICMPv4;
use Net::Packet::IPv4;
use Net::Packet::IPv6;
use Net::Packet::NULL;
use Net::Packet::RAW;
use Net::Packet::SLL;
use Net::Packet::TCP;
use Net::Packet::UDP;
use Net::Packet::VLAN;

my $f = Net::Packet::Frame->new;
$f->pack;

my $a = Net::Packet::ARP->new;
$a->pack;

my $e = Net::Packet::ETH->new;
$e->pack;

my $i = Net::Packet::ICMPv4->new;
$i->pack;

my $i2 = Net::Packet::IPv4->new;
$i2->pack;

my $i3 = Net::Packet::IPv6->new;
$i3->pack;

my $n = Net::Packet::NULL->new;
$n->pack;

my $r = Net::Packet::RAW->new;
$r->pack;

my $s = Net::Packet::SLL->new;
$s->pack;

my $t = Net::Packet::TCP->new;
$t->pack;

my $u = Net::Packet::UDP->new;
$u->pack;

my $v = Net::Packet::VLAN->new;
$v->pack;

my $p1 = Net::Packet::PPPoE->new;
$p1->pack;

my $p2 = Net::Packet::PPP->new;
$p2->pack;

my $p3 = Net::Packet::PPPLCP->new;
$p3->pack;

my $llc = Net::Packet::LLC->new;
$llc->pack;

my $cdp = Net::Packet::CDP->new;
$cdp->pack;

my $cdpType1 = Net::Packet::CDP::TypeDeviceId->new;
$cdpType1->pack;

ok(1);

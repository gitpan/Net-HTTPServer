use lib "t/lib";
use Test::More tests=>3;

BEGIN{ use_ok( "Net::HTTPServer" ); }

my $server = new Net::HTTPServer();
ok( defined($server), "new()");
isa_ok( $server, "Net::HTTPServer");


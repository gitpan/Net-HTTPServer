#!/usr/bin/perl -w

use strict;
use lib "../blib/lib";
use Net::HTTPServer;

my $server = new Net::HTTPServer();

$server->RegisterURL("/foo/bar.pl",\&test);

$server->Start();

$server->Process();

sub test
{
    my $env = shift;  # hash reference

    my $res;
    $res  = "<html>\n";
    $res .= "  <head>\n";
    $res .= "    <title>This is a test</title>\n";
    $res .= "  </head>\n";
    $res .= "  <body>\n";
    $res .= "    <pre>\n";

    foreach my $var (keys(%{$env}))
    {
        $res .= "$var -> ".$env->{$var}."\n";
    }
    
    $res .= "    </pre>\n";
    $res .= "  </body>\n";
    $res .= "</html>\n";
    
    return ["200",   # HTTP Response code (200 = Ok)
            {},      # Headers to send back
            $res     # Whatever you are sending back
           ];
}


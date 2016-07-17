#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Utils qw(get_resolver
                            domain_to_parent
                            sign_update);

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers
                                  unsign_zone);

use Test::More tests => 2;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{"port"};

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile("testing/config-client.yml")}
    );
    my $domain = "us.example.com";
    my $rr = eval { $client->generate_token("no.parent.example.com"); };
    ok($@, "Died on unhandled domain name");
    like($@, qr/Unhandled domain name/,
        "Got correct error message");
}

END {
    stop_test_servers($pids);
}

1;

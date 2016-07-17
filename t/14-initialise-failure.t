#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::Util qw(first);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 5;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{"port"};

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile("testing/config-client.yml")}
    );
    my $domain = "us.example.com";
    my $rr = $client->generate_token($domain);
    my $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    $res = $client->post_cds($domain);
    ok($res, "Posted CDS records successfully");
    sleep(1);
    eval { $client->post_cds($domain); };
    ok($@, "Unable to repost relying on same token");
    like($@, qr/Bad Request/, "Got correct response code");
}

END {
    stop_test_servers($pids);
}

1;

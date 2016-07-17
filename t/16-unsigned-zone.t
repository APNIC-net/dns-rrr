#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Utils qw(get_resolver
                            domain_to_parent
                            sign_update);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers
                                  unsign_zone);

use Test::More tests => 4;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{'port'};

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile('testing/config-client.yml')}
    );
    my $domain = 'us.example.com';
    my $rr = $client->generate_token($domain);
    my $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    
    unsign_zone($domain);
    $res = eval { $client->post_cds($domain); };
    ok((not $res), 'Failed to post CDS records');
    like($@, qr/The zone is unsigned/,
        'Got correct error message');
}

END {
    stop_test_servers($pids);
}

1;

#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Utils qw(get_resolver
                            domain_to_parent);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 7;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{'port'};

    my $ua = LWP::UserAgent->new();
    my $res = $ua->get("http://localhost:$port/asdf");
    is($res->code(), HTTP_NOT_FOUND, 'Get request not found');

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile('testing/config-client.yml')}
    );
    my $domain = 'us.example.com';
    my $rr = $client->generate_token($domain);
    $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    $res = $client->post_cds($domain);
    ok($res, "Posted CDS records successfully");
    sleep(1);

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($client, $parent);
    my @ds_rrs = rr($parent_resolver, $domain, 'DS');
    ok(@ds_rrs, 'DS records are present at parent');

    $res = eval { $client->delete_cds($domain); };
    diag $@ if $@;
    ok($res, "Deleted CDS records successfully");
    sleep(1);

    @ds_rrs = rr($parent_resolver, $domain, 'DS');
    ok((not @ds_rrs), 'DS records are not present at parent');
}

END {
    stop_test_servers($pids);
}

1;

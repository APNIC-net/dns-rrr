#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Utils qw(is_sep);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::Util qw(first);
use List::MoreUtils qw(uniq);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 9;

my $pids;

{
    my $data = start_test_servers('testing/config-server-cdnskey.yml');
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
    is($rr->type(), 'TXT', 'RR is a TXT record');
    is($rr->name(), $domain, 'RR has correct name');

    $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    $res = $client->post_cds($domain);
    ok($res, "Posted CDS records successfully");
    sleep(1);
    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $parent_resolver = $client->get_resolver($parent);
    my @ds = rr($parent_resolver, $domain, 'DS');
    is(@ds, 3, 'Three DS records at parent');
    my @algorithms =
        sort map { Net::DNS::RR::DS->digtype($_->digtype()) }
            @ds;
    is_deeply(\@algorithms, [qw(SHA-1 SHA-256 SHA-384)],
                'Correct algorithms used for DS records');

    my $resolver = $client->get_resolver($domain);
    my @cds = rr($resolver, $domain, 'CDS');
    my @cds_algorithms = 
        map { Net::DNS::RR::DS->digtype($_->digtype()) }
            @cds;
    my @unique_cds_algorithms = sort(uniq(@cds_algorithms));
    is_deeply(\@unique_cds_algorithms, [qw(SHA-1 SHA-256)],
                'Different algorithms used for CDS records');
}

END {
    stop_test_servers($pids);
}

1;

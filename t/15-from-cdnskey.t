#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Utils qw(is_sep
                            domain_to_parent);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::Util qw(first);
use List::MoreUtils qw(uniq);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 6;

my $pids;

{
    my $data = start_test_servers("testing/config-server-cdnskey.yml");
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{"port"};

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile("testing/config-client.yml")}
    );
    $client->{"keep_cds"} = 1;
    $client->{"keep_cdnskey"} = 1;
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
    my $parent = domain_to_parent($domain);
    my $parent_resolver = $client->get_resolver($parent);
    my @ds_rrs = rr($parent_resolver, $domain, "DS");
    is(@ds_rrs, 3, "Three DS records at parent");
    my @algorithms =
        sort map { Net::DNS::RR::DS->digtype($_->digtype()) }
            @ds_rrs;
    is_deeply(\@algorithms, [qw(SHA-1 SHA-256 SHA-384)],
                "Correct algorithms used for DS records");

    my $resolver = $client->get_resolver($domain);
    my @cds_rrs = rr($resolver, $domain, "CDS");
    my @cds_algorithms = 
        map { Net::DNS::RR::DS->digtype($_->digtype()) }
            @cds_rrs;
    my @unique_cds_algorithms = sort(uniq(@cds_algorithms));
    is_deeply(\@unique_cds_algorithms, [qw(SHA-1 SHA-256)],
                "Different algorithms used for CDS records");
}

END {
    stop_test_servers($pids);
}

1;

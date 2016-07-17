#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Utils qw(get_resolver
                            domain_to_parent
                            is_sep
                            ds_to_matching_dnskeys);

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::MoreUtils qw(uniq);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 24;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $port = $data->[1]->[0]->{"port"};
 
    my $ua = LWP::UserAgent->new();
    my $res = $ua->get("http://localhost:$port/asdf");
    is($res->code(), HTTP_NOT_FOUND, "Get request not found");

    my $client = APNIC::DNSRRR::Client->new(
        %{YAML::LoadFile("testing/config-client.yml")}
    );
    my $domain = "us.example.com";
    my $rr = $client->generate_token($domain);
    is($rr->type(), "TXT", "RR is a TXT record");
    is($rr->name(), "_delegate.$domain", "RR has correct name");

    $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    sleep(1);
    my $resolver = get_resolver($client, $domain);
    my @rrs = rr($resolver, "_delegate.$domain", "TXT");
    is(@rrs, 1, "One TXT record retrieved for domain");
    is($rrs[0]->type(), "TXT", "Retrieved RR is a TXT record");
    is($rrs[0]->name(), "_delegate.$domain", "Retrieved RR has correct name");

    my @c_rrs = map { rr($resolver, $domain, $_) } qw(CDS CDNSKEY);
    is(@c_rrs, 0, "No CDS/CDNSKEY records present for domain");
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    my @cdnskey_rrs = rr($resolver, $domain, "CDNSKEY");
    is(@cdnskey_rrs, 2, "Two CDNSKEYs present in domain");
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");
    is(@dnskey_rrs, 2, "Two DNSKEYs present in domain");

    my @cdnskey_strings = sort map { $_->string() } @cdnskey_rrs;
    my @dnskey_strings  = sort map { $_->string() } @dnskey_rrs;
    @cdnskey_strings = map { s/CDNSKEY/DNSKEY/; $_ } @cdnskey_strings;
    is_deeply(\@cdnskey_strings, \@dnskey_strings,
        "CDNSKEYs match DNSKEYs");

    my @cds_rrs = rr($resolver, $domain, "CDS");
    is(@cds_rrs, 4, "Four CDS records present in domain");
    for my $cds_rr (@cds_rrs) {
        my @matching_rrs = ds_to_matching_dnskeys($cds_rr, \@dnskey_rrs);
        my $tag = $cds_rr->keytag();
        is(@matching_rrs, 1, "Found DNSKEY for CDS record ($tag)");
    }

    $res = $client->post_cds($domain);
    ok($res, "Posted CDS records successfully");
    sleep(1);

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($client, $parent);
    sleep(1);
    my @ds_rrs = rr($parent_resolver, $domain, "DS");
    is(@ds_rrs, 2, "Two DS records present in parent domain");

    my @tags;
    for my $ds_rr (@ds_rrs) {
        my @matching_rrs = ds_to_matching_dnskeys($ds_rr, \@dnskey_rrs);
        my $tag = $ds_rr->keytag();
        push @tags, $tag;
        is(@matching_rrs, 1, "Found DNSKEY for DS record ($tag)");
        ok(is_sep($matching_rrs[0]), "DNSKEY has the SEP flag");
    }
    @tags = uniq @tags;

    my @sep_tags =
        uniq
        map  { $_->keytag() }
        grep { is_sep($_) }
            @dnskey_rrs;
    is_deeply(\@tags, \@sep_tags, "DS records exist for all SEP keys");
}

END {
    stop_test_servers($pids);
}

1;

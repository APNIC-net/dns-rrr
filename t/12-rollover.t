#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Utils qw(is_sep
                            domain_to_parent
                            ds_to_matching_dnskeys);

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::MoreUtils qw(uniq);
use List::Util qw(first);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers
                                  generate_new_ksk
                                  roll_ksk);

use Test::More tests => 20;

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

    my $resolver = $client->get_resolver($domain);
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");
    is(@dnskey_rrs, 2, "Got existing DNSKEYs from domain");
    my %dnskey_rrs_by_tag = map { $_->keytag() => $_ } @dnskey_rrs;

    generate_new_ksk($domain);
    sleep(1);
    my @new_dnskey_rrs = rr($resolver, $domain, "DNSKEY");
    is(@new_dnskey_rrs, 3, "New DNSKEY added to domain");
    @new_dnskey_rrs =
        grep { not $dnskey_rrs_by_tag{$_->keytag()} }
            @new_dnskey_rrs;
    is(@new_dnskey_rrs, 1, "Confirmed new DNSKEY added to domain");
    ok(is_sep($new_dnskey_rrs[0]), "New DNSKEY is KSK");

    $res = $client->create_cds($domain);
    ok($res, "Recreated CDS records successfully");
    sleep(1);
    $res = $client->put_cds($domain);
    ok($res, "Put CDS records successfully");
    sleep(1);

    my $parent = domain_to_parent($domain);
    my $parent_resolver = $client->get_resolver($parent);
    my @ds_rrs = rr($parent_resolver, $domain, "DS");
    is(@ds_rrs, 4, "Four DS records at parent");

    my $old_ksk = first { is_sep($_) } @dnskey_rrs;
    my $old_tag = $old_ksk->keytag();
    roll_ksk($domain, $old_tag);
    sleep(1);

    @dnskey_rrs = rr($resolver, $domain, "DNSKEY");
    is(@dnskey_rrs, 2, "Old DNSKEY removed from zone");
    %dnskey_rrs_by_tag = map { $_->keytag() => $_ } @dnskey_rrs;
    ok((not $dnskey_rrs_by_tag{$old_tag}),
        "Confirmed old DNSKEY removed from zone");

    $res = $client->create_cds($domain);
    ok($res, "Recreated CDS records successfully");
    sleep(1);
    $res = $client->put_cds($domain);
    ok($res, "Put CDS records successfully");
    sleep(1);

    @ds_rrs = rr($parent_resolver, $domain, "DS");
    is(@ds_rrs, 2, "Two DS records at parent");

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

#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
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

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 24;

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
    is($rr->type(), 'TXT', 'RR is a TXT record');
    is($rr->name(), $domain, 'RR has correct name');

    $res = $client->add_token($domain, $rr);
    ok($res, "Added token successfully");
    sleep(1);
    my $resolver = get_resolver($client, $domain);
    my @rrs = rr($resolver, $domain, 'TXT');
    is(@rrs, 1, 'One TXT record retrieved for domain');
    is($rrs[0]->type(), 'TXT', 'Retrieved RR is a TXT record');
    is($rrs[0]->name(), $domain, 'Retrieved RR has correct name');

    my @cs = map { rr($resolver, $domain, $_) } qw(CDS CDNSKEY);
    is(@cs, 0, 'No CDS/CDNSKEY records present for domain');
    $res = $client->create_cds($domain);
    ok($res, "Created CDS records successfully");
    sleep(1);
    my @cdnskeys = rr($resolver, $domain, 'CDNSKEY');
    is(@cdnskeys, 2, 'Two CDNSKEYs present in domain');
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');
    is(@dnskeys, 2, 'Two DNSKEYs present in domain');

    my @cdata = sort map { $_->string() } @cdnskeys;
    my @data  = sort map { $_->string() } @dnskeys;
    @cdata = map { s/CDNSKEY/DNSKEY/; $_ } @cdata;
    is_deeply(\@cdata, \@data, 'CDNSKEYs match DNSKEYs');

    my @cds_rrs = rr($resolver, $domain, 'CDS');
    is(@cds_rrs, 4, 'Four CDS records present in domain');
    for my $cds_rr (@cds_rrs) {
        my @matching = ds_to_matching_dnskeys($cds_rr, \@dnskeys);
        my $tag = $cds_rr->keytag();
        is(@matching, 1, "Found DNSKEY for CDS record ($tag)");
    }

    sleep(1);
    $res = $client->post_cds($domain);
    ok($res, "Posted CDS records successfully");

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($client, $parent);
    sleep(1);
    my @ds_rrs = rr($parent_resolver, $domain, 'DS');
    is(@ds_rrs, 2, 'Two DS records present in parent domain');

    my @tags;
    for my $ds_rr (@ds_rrs) {
        my @matching = ds_to_matching_dnskeys($ds_rr, \@dnskeys);
        my $tag = $ds_rr->keytag();
        push @tags, $tag;
        is(@matching, 1, "Found DNSKEY for DS record ($tag)");
        ok(is_sep($matching[0]), "DNSKEY has the SEP flag");
    }
    @tags = uniq @tags;

    my @ctags =
        uniq
        map  { $_->keytag() }
        grep { is_sep($_) }
            @dnskeys;
    is_deeply(\@tags, \@ctags, 'DS records exist for all SEP keys');
}

END {
    stop_test_servers($pids);
}

1;

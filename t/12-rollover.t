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
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers
                                  generate_new_ksk
                                  roll_ksk);

use Test::More tests => 16;

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

    my $resolver = $client->get_resolver($domain);
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');
    is(@dnskeys, 2, 'Got existing DNSKEYs from domain');
    my %dnskeys_by_tag = map { $_->keytag() => $_ } @dnskeys;

    generate_new_ksk($domain);
    sleep(1);
    my @new_dnskeys = rr($resolver, $domain, 'DNSKEY');
    is(@new_dnskeys, 3, 'New DNSKEY added to domain');
    @new_dnskeys =
        grep { not $dnskeys_by_tag{$_->keytag()} }
            @new_dnskeys;
    is(@new_dnskeys, 1, 'Confirmed new DNSKEY added to domain');
    ok(is_sep($new_dnskeys[0]), "New DNSKEY is KSK");

    $res = $client->create_cds($domain);
    ok($res, "Recreated CDS records successfully");
    sleep(1);
    $res = $client->put_cds($domain);
    ok($res, "Put CDS records successfully");
    sleep(1);

    my $parent = domain_to_parent($domain);
    my $parent_resolver = $client->get_resolver($parent);
    my @ds = rr($parent_resolver, $domain, 'DS');
    is(@ds, 4, 'Four DS records at parent');

    my $old_ksk = first { is_sep($_) } @dnskeys;
    my $old_tag = $old_ksk->keytag();
    roll_ksk($domain, $old_tag);
    sleep(1);

    @dnskeys = rr($resolver, $domain, 'DNSKEY');
    is(@dnskeys, 2, 'Old DNSKEY removed from zone');
    %dnskeys_by_tag = map { $_->keytag() => $_ } @dnskeys;
    ok((not $dnskeys_by_tag{$old_tag}),
        'Confirmed old DNSKEY removed from zone');

    $res = $client->create_cds($domain);
    ok($res, "Recreated CDS records successfully");
    sleep(1);
    $res = $client->put_cds($domain);
    ok($res, "Put CDS records successfully");
    sleep(1);

    @ds = rr($parent_resolver, $domain, 'DS');
    is(@ds, 2, 'Two DS records at parent');
}

END {
    stop_test_servers($pids);
}

1;

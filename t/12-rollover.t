#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Utils qw(is_sep);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use List::Util qw(first);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib './t/lib';
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers);

use Test::More tests => 18;

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

    my ($id) = `docker ps | grep bind_child | cut -f 1 -d' '`;
    chomp $id;
    my ($json) = `docker inspect -f '{{json .Mounts }}' $id`;
    $data = decode_json($json);
    my $path = $data->[0]->{'Source'};
    my $keydir = "$path/bind/etc/keys";
    my (@keygen_content) = `dnssec-keygen -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE us.example.com. 2>/dev/null`;
    my $keypath = $keygen_content[$#keygen_content];
    chomp $keypath;
    system("mv $keypath* $keydir");
    system("rndc -c ./testing/01_child/rndc.config loadkeys us.example.com.");
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

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $parent_resolver = $client->get_resolver($parent);
    my @ds = rr($parent_resolver, $domain, 'DS');
    is(@ds, 2, 'Two DS records at parent');

    my $old_ksk = first { is_sep($_) } @dnskeys;
    my $old_tag = $old_ksk->keytag();
    my @old_paths = map { chomp; $_ } `ls $keydir/*$old_tag*`;
    my $key_path = first { /\.key$/ } @old_paths;

    system("rndc -c ./testing/01_child/rndc.config sign us.example.com.");
    sleep(1);
    my @rndc_keys = 
        map { chomp; $_ }
            `rndc -c ./testing/01_child/rndc.config signing -list us.example.com.`;
    my $to_remove = first { /$old_tag/ } @rndc_keys;
    $to_remove =~ s/.* key //;

    system("dnssec-settime -I +0 -D +0 $key_path >/dev/null 2>&1");
    system("rndc -c ./testing/01_child/rndc.config signing -clear $to_remove us.example.com. >/dev/null 2>&1");
    system("rndc -c ./testing/01_child/rndc.config loadkeys us.example.com.");
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
    is(@ds, 1, 'One DS record at parent');
}

END {
    stop_test_servers($pids);
}

1;

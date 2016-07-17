#!/usr/bin/perl

use warnings;
use strict;

use APNIC::DNSRRR::Client;
use APNIC::DNSRRR::Server;
use APNIC::DNSRRR::Utils qw(get_resolver
                            domain_to_parent
                            sign_update);

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);
use LWP::UserAgent;
use Net::DNS;
use YAML;

use lib "./t/lib";
use APNIC::DNSRRR::Test::Utils qw(start_test_servers
                                  stop_test_servers
                                  unsign_zone);

use Test::More tests => 4;

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

    my $resolver = get_resolver($client, $domain);
    my $update = Net::DNS::Update->new($domain, "IN");
    my $invalid_cds = "us.example.com. 5 IN CDS 30909 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CF C41A5766";
    $update->push(update => rr_add($invalid_cds));
    sign_update($client, $domain, $update);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        die "Unable to create invalid CDS record: ".Dumper($reply);
    }
    sleep(1);
    
    $res = eval { $client->post_cds($domain); };
    ok((not $res), "Failed to post CDS records");
    like($@, qr/no matching DNSKEY record/,
        "Got correct error message");
}

END {
    stop_test_servers($pids);
}

1;

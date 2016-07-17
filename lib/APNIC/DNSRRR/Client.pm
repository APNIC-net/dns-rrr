package APNIC::DNSRRR::Client;

use warnings;
use strict;

use APNIC::DNSRRR::DS;
use APNIC::DNSRRR::Utils qw(get_resolver
                            sign_update
                            rrsets_are_equal);

use Data::Dumper;
use JSON::XS qw(decode_json);
use LWP::UserAgent;
use Net::DNS;
use Time::HiRes qw(sleep);

our $VERSION = "0.1";

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;

    if (not defined $self->{"cds_digest_types"}) {
        $self->{"cds_digest_types"} = [qw(SHA-1 SHA-256)];
    }
    for my $digest (@{$self->{"cds_digest_types"}}) {
        my $res = Net::DNS::RR::DS->digtype($digest);
        if (not $res) {
            die "Digest type '$digest' is invalid";
        }
    }

    my $ua = LWP::UserAgent->new();
    $self->{"ua"} = $ua;
    bless $self, $class;
    return $self;
}

sub wait_for_records
{
    my ($self, $domain, $name, $rr_type, $expected_rrs) = @_;

    my $resolver = get_resolver($self, $domain);
    my $timeout = 300;
    while ($timeout > 0) {
        my @rrs = rr($resolver, $name, $rr_type);
        if (rrsets_are_equal(\@rrs, $expected_rrs, 1)) {
            return 1;
        }
        $timeout--;
        sleep(0.1);
    }

    die "Expected records were not found (timed out)";
}

sub send_request
{
    my ($self, $method, $domain, $path) = @_;

    my $details = $self->{"domains"}->{$domain} || {};
    my $dnsrrr_server = $details->{"dns-rrr-server"};
    if (not $dnsrrr_server) {
        die "No dns-rrr-server configured for domain '$domain'";
    }
    my $ua = $self->{"ua"};
    my $res = $ua->$method("$dnsrrr_server/domains/$domain$path");
    return $res;
}

sub generate_token
{
    my ($self, $domain) = @_;

    my $res = $self->send_request("post", $domain, "/token");
    if (not $res->is_success()) {
        die "Unable to generate token: ".Dumper($res);
    }
    my $record = decode_json($res->content())->{"record"};
    my $rr = Net::DNS::RR->new($record);
    return $rr;
}

sub add_token
{
    my ($self, $domain, $rr) = @_;

    my $update = Net::DNS::Update->new($domain, "IN");
    $update->push(update => rr_add($rr->string()));
    sign_update($self, $domain, $update);
    my $resolver = get_resolver($self, $domain);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        die "Unable to add token to server: ".Dumper($reply);
    }

    return 1;
}

sub remove_required_records
{
    my ($self, $domain) = @_;

    for my $type (qw(cds cdnskey)) {
        if ($self->{"keep_".$type}) {
            next;
        }
        my $rr_type = uc $type;
        my $resolver = get_resolver($self, $domain);
        my $update = Net::DNS::Update->new($domain, "IN");
        $update->push(update => rr_del("$domain $rr_type"));
        sign_update($self, $domain, $update);
        my $reply = $resolver->send($update);
        if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
            warn "Unable to remove $rr_type records: ".Dumper($reply);
        }
    }

    return 1;
}

sub create_cds
{
    my ($self, $domain) = @_;

    my $update = Net::DNS::Update->new($domain, "IN");
    $update->push(update => rr_del("$domain CDS"));
    $update->push(update => rr_del("$domain CDNSKEY"));

    my $resolver = get_resolver($self, $domain);
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");
    my @cds_rrs;
    my @cdnskey_rrs;
    for my $dnskey_rr (@dnskey_rrs) {
        my $string = $dnskey_rr->string();
        $string =~ s/DNSKEY/CDNSKEY/;
        push @cdnskey_rrs, Net::DNS::RR::CDNSKEY->new($string);
        for my $digtype (@{$self->{"cds_digest_types"}}) {
            my $cds_rr =
                Net::DNS::RR::CDS->create($dnskey_rr,
                                          digtype => $digtype);
            push @cds_rrs, $cds_rr;
        }
    }
    for my $update_rr (@cdnskey_rrs, @cds_rrs) {
        $update->push(update => rr_add($update_rr->string()));
    }

    sign_update($self, $domain, $update);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        die "Unable to create CDS records: ".Dumper($reply);
    }

    $self->wait_for_records($domain, $domain, 'CDNSKEY', \@cdnskey_rrs);
    $self->wait_for_records($domain, $domain, 'CDS',     \@cds_rrs);

    return 1;
}

sub post_cds
{
    my ($self, $domain) = @_;

    my $res = $self->send_request("post", $domain, "/cds");
    if (not $res->is_success()) {
        die "Unable to post CDS records: ".Dumper($res);
    }
    $self->remove_required_records($domain);

    return 1;
}

sub remove_token
{
    my ($self, $domain, $rr) = @_;

    my $update = Net::DNS::Update->new($domain, "IN");
    $update->push(update => rr_del($rr->string()));
    sign_update($self, $domain, $update);
    my $resolver = get_resolver($self, $domain);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        die "Unable to remove token from server: ".Dumper($reply);
    }

    return 1;
}

sub delete_cds
{
    my ($self, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my $update = Net::DNS::Update->new($domain, "IN");
    $update->push(update => rr_del("$domain CDS"));
    $update->push(update => rr_del("$domain CDNSKEY"));
    my $cds_string = "$domain CDS 1 0 1 1";
    $update->push(update => rr_add($cds_string));
    sign_update($self, $domain, $update);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        die "Unable to create zero-algorithm CDS record: ".Dumper($reply);
    }
    $self->wait_for_records($domain, $domain, 'CDS',
                            [ Net::DNS::RR->new($cds_string) ]);

    my $res = $self->send_request("delete", $domain, "/cds");
    if (not $res->is_success()) {
        die "Unable to delete CDS records: ".Dumper($res);
    }
    $self->remove_required_records($domain);

    return 1;
}

sub put_cds
{
    my ($self, $domain) = @_;

    my $res = $self->send_request("put", $domain, "/cds");
    if (not $res->is_success()) {
        die "Unable to update CDS records: ".Dumper($res);
    }
    $self->remove_required_records($domain);

    return 1;
}

1;

package APNIC::DNSRRR::Server;

use warnings;
use strict;

use Bytes::Random::Secure;
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(encode_json);
use List::Util qw(first);
use Net::DNS;

use APNIC::DNSRRR::DS;
use APNIC::DNSRRR::Utils qw(get_resolver
                            sign_update
                            is_sep);

use constant TOKEN_EXPIRY_SECONDS => 300;

our $VERSION = '0.1';

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;
    if (not defined $self->{'port'}) {
        $self->{'port'} = 8080;
    }
    my $d = HTTP::Daemon->new(
        LocalPort => $self->{'port'},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    $self->{'port'} = $d->sockport();
    $self->{'d'} = $d;
    bless $self, $class;
    return $self;
}

sub error
{
    my ($self, $c, $code, $title, $detail) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($title) {
        my $data = encode_json({ title  => $title,
                                 ($detail) ? (detail => $detail) : () });
        $response->content($data);
        $response->header('Content-Type' => 'application/problem+json');
    }
    return $c->send_response($response);
}

sub success
{
    my ($self, $c, $code, $data) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($data) {
        $response->content(encode_json($data));
        $response->header('Content-Type' => 'application/json');
    }
    return $c->send_response($response);
}

sub post_token
{
    my ($self, $c, $r, $domain) = @_;

    my $current = $self->{'tokens'}->{$domain};
    my $now = time();
    if ($current) {
        my $timestamp = $current->[1];
        if (($timestamp + TOKEN_EXPIRY_SECONDS) > $now) {
            return $self->error($c, HTTP_BAD_REQUEST,
                                'Unexpired token',
                                'The token for this domain has not '.
                                'yet expired.');
        }
    }
    my $brs = Bytes::Random::Secure->new(Bits => 512, NonBlocking => 1);
    my $token = $brs->bytes_hex(32);
    my $timestamp = time();
    $self->{'tokens'}->{$domain} = [ $token, $timestamp ];

    return $self->success($c, HTTP_OK,
                          { record => "$domain IN TXT \"$token\"" });
}

sub post_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @rrs = rr($resolver, $domain, "TXT");
    if (not @rrs) {
        return $self->error($c, HTTP_FORBIDDEN,
                            'No token record',
                            'No TXT token record was found.');
    }
    my $token = $self->{'tokens'}->{$domain}->[0];
    if (not $token) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No token',
                            'No token has been generated for this domain.');
    }
    my $matching_rr = first { $_->rdstring() eq $token } @rrs;
    if (not $matching_rr) {
        return $self->error($c, HTTP_FORBIDDEN,
                            'No matching token record',
                            'No matching TXT token record was found.');
    }
    my @cds_rrs = rr($resolver, $domain, "CDS");
    if (not @cds_rrs) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDS records',
                            'No CDS records were found.');
    }
    my @cdnskeys = rr($resolver, $domain, "CDNSKEY");
    if (not @cdnskeys) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDNSKEY records',
                            'No CDNSKEY records were found.');
    }

    my %sep_keys_by_tag =
        map  { $_->keytag() => $_ }
        grep { is_sep($_) }
            @cdnskeys;
    @cds_rrs = grep { $sep_keys_by_tag{$_->keytag()} } @cds_rrs;
    if (not @cds_rrs) {
        return $self->error($c, HTTP_BAD_REQUEST);
    }

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $parent_resolver = get_resolver($self, $parent);
    my $update = Net::DNS::Update->new($parent, 'IN');

    $update->push(update => rr_del("$domain DS"));
    my @ds_rrs =
        map { my $data = $_->string();
              $data =~ s/CDS/DS/;
              Net::DNS::RR->new($data) }
            @cds_rrs;
    for my $ds_rr (@ds_rrs) {
        $update->push(update => rr_add($ds_rr->string()));
    }

    sign_update($self, $parent, $update);

    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne 'NOERROR')) {
        warn("Unable to set DS records against server: ".Dumper($reply));
        return $self->error($c, HTTP_INTERNAL_SERVER_ERROR,
                            'Internal error',
                            'Unable to add DS records to server.');
    }

    delete $self->{'tokens'}->{$domain};

    return $self->success($c, HTTP_CREATED);
}

sub post
{
    my ($self, $c, $r) = @_;

    my $path = $r->uri()->path();
    if ($path =~ /^\/domains\/(.*?)\/token$/) {
        return $self->post_token($c, $r, $1);
    } elsif ($path =~ /^\/domains\/(.*?)\/cds$/) {
        return $self->post_cds($c, $r, $1);
    }

    return $self->error($c, HTTP_NOT_FOUND);
}

sub get_dnskeys
{
    my ($self, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');
    my @rrsigs =
        grep { $_->typecovered() eq 'DNSKEY' }
            rr($resolver, $domain, 'RRSIG');

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $parent_resolver = get_resolver($self, $parent);

    my %ds_rrs =
        map { $_->keytag() => $_ }
            rr($parent_resolver, $domain, 'DS');
    my @ds_compare_rrs =
        map { Net::DNS::RR::DS->create($_, digtype => 'SHA-256') }
            @dnskeys;
    my @ds_keep_rrs =
        grep { my $key = $_;
               my $ds = Net::DNS::RR::DS->create($key, digtype => 'SHA-256');
               my $ds_rr = $ds_rrs{$key->keytag()};
               $ds_rr and ($ds_rr->string() eq $ds->string()) }
            @dnskeys;

    for my $rrsig (@rrsigs) {
        if ($rrsig->verify(\@dnskeys, \@ds_keep_rrs)) {
            return @dnskeys;
        }
    }

    return;
}

sub validate_signatures
{
    my ($self, $domain, $record_type) = @_;

    my $resolver = get_resolver($self, $domain);
    my @records = rr($resolver, $domain, $record_type);
    my @rrsigs = 
        grep { $_->typecovered() eq $record_type }
            rr($resolver, $domain, 'RRSIG');

    my @keys = $self->get_dnskeys($domain);
    if (not @keys) {
        return;
    }
    for my $rrsig (@rrsigs) {
        if ($rrsig->verify(\@records, \@keys)) {
            return @records;
        }
    }

    return;
}

sub delete_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @cdss = $self->validate_signatures($domain, "CDS");
    if (not @cdss) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDS records',
                            'No CDS records were found.');
    }
    if (@cdss > 1) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Multiple CDS records',
                            'Multiple CDS records were found.');
    }
    my $cds = $cdss[0];
    if ($cds->algorithm() != 0) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Invalid CDS record',
                            'CDS record must have an algorithm of 0.');
    }

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $update = Net::DNS::Update->new($parent, 'IN');
    my $parent_resolver = get_resolver($self, $parent);

    $update->push(update => rr_del("$domain DS"));
    sign_update($self, $parent, $update);
    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne 'NOERROR')) {
        return $self->error($c, HTTP_INTERNAL_SERVER_ERROR,
                            'Internal error',
                            'Unable to delete DS records from server.');
    }

    return $self->success($c ,HTTP_OK);
}

sub delete
{
    my ($self, $c, $r) = @_;

    my $path = $r->uri()->path();
    if ($path =~ /^\/domains\/(.*?)\/cds$/) {
        return $self->delete_cds($c, $r, $1);
    }

    return $self->error($c, HTTP_NOT_FOUND);
}

sub put_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @cdss = $self->validate_signatures($domain, "CDS");
    if (not @cdss) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDS records',
                            'No CDS records were found.');
    }
    my @cdnskeys = $self->validate_signatures($domain, "CDNSKEY");
    if (not @cdnskeys) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDNSKEY records',
                            'No CDNSKEY records were found.');
    }

    my %sep_keys_by_tag =
        map  { $_->keytag() => $_ }
        grep { is_sep($_) }
            @cdnskeys;
    @cdss = grep { $sep_keys_by_tag{$_->keytag()} } @cdss;
    if (not @cdss) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No known CDNSKEY records',
                            'No known CDNSKEY records were found.');
    }

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);
    my $update = Net::DNS::Update->new($parent, 'IN');
    my $parent_resolver = get_resolver($self, $parent);

    $update->push(update => rr_del("$domain DS"));
    my @ds_rrs =
        map { my $data = $_->string();
              $data =~ s/CDS/DS/;
              Net::DNS::RR->new($data) }
            @cdss;
    for my $ds_rr (@ds_rrs) {
        $update->push(update => rr_add($ds_rr->string()));
    }

    sign_update($self, $parent, $update);
    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne 'NOERROR')) {
        return $self->error($c, HTTP_INTERNAL_SERVER_ERROR,
                            'Internal error',
                            'Unable to update DS records on server.');
    }

    return $self->success($c, HTTP_OK);
}

sub put
{
    my ($self, $c, $r) = @_;

    my $path = $r->uri()->path();
    if ($path =~ /^\/domains\/(.*?)\/cds$/) {
        return $self->put_cds($c, $r, $1);
    }

    return $self->error($c, HTTP_NOT_FOUND);
}

sub run
{
    my ($self) = @_;

    my $d = $self->{'d'};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            if ($method eq 'POST') {
                $self->post($c, $r);
            } elsif ($method eq 'DELETE') {
                $self->delete($c, $r);
            } elsif ($method eq 'PUT') {
                $self->put($c, $r);
            } else {
                $self->error($c, HTTP_NOT_FOUND);
            }
        }
        $c->close();
        undef $c;
    }
}

1;

package APNIC::DNSRRR::Server;

use warnings;
use strict;

use Bytes::Random::Secure;
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(encode_json);
use List::MoreUtils qw(uniq);
use List::Util qw(first);
use Net::DNS;

use APNIC::DNSRRR::DS;
use APNIC::DNSRRR::Utils qw(get_resolver
                            sign_update
                            is_sep
                            domain_to_parent
                            ds_to_matching_dnskeys);

use constant TOKEN_EXPIRY_SECONDS => 300;
use constant DS_FROM => (qw(CDS CDNSKEY));

our $VERSION = '0.1';

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;
    if (not defined $self->{'port'}) {
        $self->{'port'} = 8080;
    }
    if (not defined $self->{'ds_from'}) {
        $self->{'ds_from'} = 'CDS';
    }
    if (not first { $_ eq $self->{'ds_from'} } DS_FROM()) {
        die "'ds_from' must be either 'CDS' or 'CDNSKEY'";
    }
    if (not defined $self->{'ds_digests'}) {
        $self->{'ds_digests'} = [qw(SHA-1 SHA-256)];
    }
    for my $digest (@{$self->{'ds_digests'}}) {
        my $res = Net::DNS::RR::DS->digtype($digest);
        if (not $res) {
            die "Digest type '$digest' is invalid";
        }
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
    return $response;
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
    return $response;
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

    my $record = "_delegate.$domain IN TXT \"$token\"";
    return $self->success($c, HTTP_OK, { record => $record });
}

sub generate_ds_records
{
    my ($self, $cds_rrs, $cdnskey_rrs) = @_;

    my %sep_keys_by_tag =
        map  { $_->keytag() => $_ }
        grep { is_sep($_) }
            @{$cdnskey_rrs};
    my @ds_rrs;

    if ($self->{'ds_from'} eq 'CDS') {
        my @sep_cds_rrs =
            grep { $sep_keys_by_tag{$_->keytag()} }
                @{$cds_rrs};
        @ds_rrs =
            map { my $data = $_->string();
                  $data =~ s/CDS/DS/;
                  Net::DNS::RR->new($data) }
                @sep_cds_rrs;
    } else {
        for my $cdnskey (values %sep_keys_by_tag) {
            for my $digest_type (@{$self->{'ds_digests'}}) {
                my $ds = eval {
                    Net::DNS::RR::DS->create($cdnskey,
                                             digtype => $digest_type)
                };
                if (my $error = $@) {
                    warn "Unable to create digest of type ".
                         "'$digest_type': $error";
                } else {
                    push @ds_rrs, $ds;
                }
            }
        }
    }

    return @ds_rrs;
}

sub get_dnskeys
{
    my ($self, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');

    my @rrsigs =
        grep { $_->typecovered() eq 'DNSKEY' }
            rr($resolver, $domain, 'RRSIG');

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($self, $parent);
    my @ds_rrs = rr($parent_resolver, $domain, 'DS');

    my @dnskey_to_use_rrs =
        map { ds_to_matching_dnskeys($_, \@dnskeys) }
            @ds_rrs;

    for my $rrsig (@rrsigs) {
        if ($rrsig->verify(\@dnskeys, \@dnskey_to_use_rrs)) {
            return @dnskeys;
        }
    }

    return;
}

sub validate_signatures
{
    my ($self, $domain, $record_type, $dnskeys) = @_;

    my $resolver = get_resolver($self, $domain);
    my @records = rr($resolver, $domain, $record_type);
    my @rrsigs =
        grep { $_->typecovered() eq $record_type }
            rr($resolver, $domain, 'RRSIG');

    for my $rrsig (@rrsigs) {
        if ($rrsig->verify(\@records, $dnskeys)) {
            return @records;
        }
    }

    return;
}

sub is_signed
{
    my ($self, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');

    for my $rr_type (qw(DNSKEY SOA)) {
        my @valid_records =
            $self->validate_signatures(
                $domain, $rr_type, \@dnskeys
            );
        if (not @valid_records) {
            return;
        }
    }

    return 1;
}

sub has_matching_dnskeys
{
    my ($self, $domain, $cds_rrs, $cdnskeys) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskeys = rr($resolver, $domain, 'DNSKEY');

    for my $cds_rr (@{$cds_rrs}) {
        my @matching = ds_to_matching_dnskeys($cds_rr, \@dnskeys);
        if (not @matching) {
            return;
        }
    }

    for my $cdnskey_rr (@{$cdnskeys}) {
        my $cstring = $cdnskey_rr->string();
        $cstring =~ s/CDNSKEY/DNSKEY/;
        my $found = 0;
        for my $dnskey (@dnskeys) {
            my $string = $dnskey->string();
            if ($cstring eq $string) {
                $found = 1;
                last;
            }
        }
        if (not $found) {
            return;
        }
    }

    return 1;
}

sub rrsets_are_equal
{
    my ($set_one, $set_two) = @_;

    if (@{$set_one} != @{$set_two}) {
        return;
    }

    my @strings_one = sort map { $_->string() } @{$set_one};
    my @strings_two = sort map { $_->string() } @{$set_two};

    for (my $i = 0; $i < @strings_one; $i++) {
        if ($strings_one[$i] ne $strings_two[$i]) {
            return;
        }
    }

    return 1;
}

sub nameservers_agree
{
    my ($self, $domain, $cds_rrs, $cdnskey_rrs) = @_;

    my $resolver = get_resolver($self, $domain);
    my @soa_rrs = rr($resolver, $domain, 'SOA');
    my @ns_rrs = rr($resolver, $domain, 'NS');
    my @nameservers =
        uniq((map { $_->nsdname() } @ns_rrs),
             (map { $_->mname()   } @soa_rrs));
    if (not @nameservers) {
        return 1;
    }

    my @final_nameservers =
        map { my $nameserver = $_;
              my @address_rrs =
                  map { rr($resolver, $nameserver, $_) }
                      qw(A AAAA);
              (@address_rrs)
                  ? (map { $_->address() } @address_rrs)
                  : $nameserver }
            @nameservers;

    for my $nameserver (@final_nameservers) {
        my $ns_resolver = Net::DNS::Resolver->new();
        $ns_resolver->nameserver($nameserver);
        my ($n_cds_rrs, $n_cdnskey_rrs) =
            map { [ rr($ns_resolver, $domain, $_) ] }
                qw(CDS CDNSKEY);
        if (not rrsets_are_equal($cds_rrs, $n_cds_rrs)) {
            return;
        }
        if (not rrsets_are_equal($cdnskey_rrs, $n_cdnskey_rrs)) {
            return;
        }
    }

    return 1;
}

sub post_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @rrs = rr($resolver, "_delegate.$domain", "TXT");
    if (not @rrs) {
        return $self->error($c, HTTP_FORBIDDEN,
                            'No token record',
                            'No _delegate TXT token record was found.');
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
    my $res = $self->is_signed($domain);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Zone validation failed',
                            'The zone is unsigned or invalidly signed.');
    }
    $res = $self->has_matching_dnskeys($domain, \@cds_rrs, \@cdnskeys);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Missing DNSKEYs for CDS/CDNSKEYs',
                            'One or more CDS/CDNSKEY records has no '.
                            'matching DNSKEY record.');
    }
    $res = $self->nameservers_agree($domain, \@cds_rrs, \@cdnskeys);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Nameserver inconsistency',
                            'The nameservers for this domain have '.
                            'inconsistent CDS/CDNSKEY RR sets.');
    }

    my @ds_rrs = $self->generate_ds_records(\@cds_rrs, \@cdnskeys);
    if (not @ds_rrs) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No usable DS input',
                            'None of the CDS/CDNSKEY records could '.
                            'be used to generate DS records.');
    }

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($self, $parent);
    my $update = Net::DNS::Update->new($parent, 'IN');
    $update->push(update => rr_del("$domain DS"));
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

sub delete_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @keys = $self->get_dnskeys($domain);
    my @cdss = $self->validate_signatures($domain, "CDS", \@keys);
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

    my $parent = domain_to_parent($domain);
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
    my @keys = $self->get_dnskeys($domain);
    my @cdss = $self->validate_signatures($domain, "CDS", \@keys);
    if (not @cdss) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDS records',
                            'No CDS records were found.');
    }
    my @cdnskeys = $self->validate_signatures($domain, "CDNSKEY", \@keys);
    if (not @cdnskeys) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No CDNSKEY records',
                            'No CDNSKEY records were found.');
    }
    my $res = $self->is_signed($domain);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Zone validation failed',
                            'The zone is unsigned or invalidly signed.');
    }
    $res = $self->has_matching_dnskeys($domain, \@cdss, \@cdnskeys);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Missing DNSKEYs for CDS/CDNSKEYs',
                            'One or more CDS/CDNSKEY records has no '.
                            'matching DNSKEY record.');
    }
    $res = $self->nameservers_agree($domain, \@cdss, \@cdnskeys);
    if (not $res) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'Nameserver inconsistency',
                            'The nameservers for this domain have '.
                            'inconsistent CDS/CDNSKEY RR sets.');
    }

    my @ds_rrs = $self->generate_ds_records(\@cdss, \@cdnskeys);
    if (not @ds_rrs) {
        return $self->error($c, HTTP_BAD_REQUEST,
                            'No usable DS input',
                            'None of the CDS/CDNSKEY records could '.
                            'be used to generate DS records.');
    }

    my $parent = domain_to_parent($domain);
    my $update = Net::DNS::Update->new($parent, 'IN');
    my $parent_resolver = get_resolver($self, $parent);
    $update->push(update => rr_del("$domain DS"));
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
            my $path = $r->uri()->path();
            print STDERR "$method $path\n";
            my $res = eval {
                ($method eq 'POST')   ? $self->post($c, $r)
              : ($method eq 'DELETE') ? $self->delete($c, $r)
              : ($method eq 'PUT')    ? $self->put($c, $r)
                                      : $self->error($c, HTTP_NOT_FOUND);
            };
            if (my $error = $@) {
                print STDERR "Unable to process request: $error\n";
                $c->send_response($self->error(HTTP_INTERNAL_SERVER_ERROR));
            } else {
                my $res_str = $res->as_string();
                $res_str =~ s/\n/\\n/g;
                $res_str =~ s/\r/\\r/g;
                print STDERR "$res_str\n";
                $c->send_response($res);
            }
        }
        $c->close();
        undef $c;
    }
}

1;

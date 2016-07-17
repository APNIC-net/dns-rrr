package APNIC::DNSRRR::Server;

use warnings;
use strict;

use APNIC::DNSRRR::DS;
use APNIC::DNSRRR::Utils qw(get_resolver
                            sign_update
                            is_sep
                            domain_to_parent
                            ds_to_matching_dnskeys
                            rrsets_are_equal);

use Bytes::Random::Secure;
use Data::Dumper;
use Data::Validate::Domain qw(is_domain);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(encode_json);
use List::MoreUtils qw(uniq);
use List::Util qw(first);
use Net::DNS;

use constant TOKEN_EXPIRY_SECONDS => 300;
use constant DS_FROM => (qw(CDS CDNSKEY));

our $VERSION = "0.1";

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;
    if (not defined $self->{"port"}) {
        $self->{"port"} = 8080;
    }
    if (not defined $self->{"ds_from"}) {
        $self->{"ds_from"} = "CDS";
    }
    if (not first { $_ eq $self->{"ds_from"} } DS_FROM()) {
        die "'ds_from' must be either 'CDS' or 'CDNSKEY'";
    }
    if (not defined $self->{"ds_digest_types"}) {
        $self->{"ds_digest_types"} = [qw(SHA-1 SHA-256)];
    }
    for my $digest (@{$self->{"ds_digest_types"}}) {
        my $res = Net::DNS::RR::DS->digtype($digest);
        if (not $res) {
            die "Digest type '$digest' is invalid";
        }
    }

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    $self->{"port"} = $d->sockport();
    $self->{"d"} = $d;
    bless $self, $class;
    return $self;
}

sub error
{
    my ($self, $code, $title, $detail) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($title) {
        my $data = encode_json({ title  => $title,
                                 ($detail) ? (detail => $detail) : () });
        $response->content($data);
        $response->header("Content-Type" => "application/problem+json");
    }
    return $response;
}

sub success
{
    my ($self, $code, $data) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($data) {
        $response->content(encode_json($data));
        $response->header("Content-Type" => "application/json");
    }
    return $response;
}

sub post_token
{
    my ($self, $c, $r, $domain) = @_;

    my $current = $self->{"tokens"}->{$domain};
    my $now = time();
    if ($current) {
        my $timestamp = $current->[1];
        if (($timestamp + TOKEN_EXPIRY_SECONDS) > $now) {
            return $self->error(HTTP_BAD_REQUEST,
                                "Unexpired token",
                                "The token for this domain has not ".
                                "yet expired.");
        }
    }
    my $brs = Bytes::Random::Secure->new(Bits => 512, NonBlocking => 1);
    my $token = $brs->bytes_hex(32);
    my $timestamp = time();
    $self->{"tokens"}->{$domain} = [ $token, $timestamp ];

    my $record = "_delegate.$domain IN TXT \"$token\"";
    return $self->success(HTTP_OK, { record => $record });
}

sub generate_ds_records
{
    my ($self, $cds_rrs, $cdnskey_rrs) = @_;

    my @sep_cdnskey_rrs = grep { is_sep($_) } @{$cdnskey_rrs};

    my @ds_rrs;
    if ($self->{"ds_from"} eq "CDS") {
        my @sep_cds_rrs =
            grep { my @matching_rrs =
                       ds_to_matching_dnskeys($_, \@sep_cdnskey_rrs);
                   (@matching_rrs ? 1 : 0) }
                @{$cds_rrs};
        @ds_rrs =
            map { my $data = $_->string();
                  $data =~ s/CDS/DS/;
                  Net::DNS::RR->new($data) }
                @sep_cds_rrs;
    } else {
        for my $cdnskey_rr (@sep_cdnskey_rrs) {
            for my $digest_type (@{$self->{"ds_digest_types"}}) {
                my $ds_rr = eval {
                    Net::DNS::RR::DS->create($cdnskey_rr,
                                             digtype => $digest_type)
                };
                if (my $error = $@) {
                    warn "Unable to create digest of type ".
                         "'$digest_type': $error";
                } else {
                    push @ds_rrs, $ds_rr;
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
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");

    my @rrsig_rrs =
        grep { $_->typecovered() eq "DNSKEY" }
            rr($resolver, $domain, "RRSIG");

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($self, $parent);
    my @ds_rrs = rr($parent_resolver, $domain, "DS");

    my @matching_dnskey_rrs =
        map { ds_to_matching_dnskeys($_, \@dnskey_rrs) }
            @ds_rrs;

    for my $rrsig_rr (@rrsig_rrs) {
        if ($rrsig_rr->verify(\@dnskey_rrs, \@matching_dnskey_rrs)) {
            return @dnskey_rrs;
        }
    }

    return;
}

sub validate_signatures
{
    my ($self, $domain, $rr_type, $dnskey_rrs) = @_;

    my $resolver = get_resolver($self, $domain);
    my @rrs = rr($resolver, $domain, $rr_type);
    my @rrsig_rrs =
        grep { $_->typecovered() eq $rr_type }
            rr($resolver, $domain, "RRSIG");

    for my $rrsig_rr (@rrsig_rrs) {
        if ($rrsig_rr->verify(\@rrs, $dnskey_rrs)) {
            return @rrs;
        }
    }

    return;
}

sub is_signed
{
    my ($self, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");

    for my $rr_type (qw(DNSKEY SOA)) {
        my @valid_rrs =
            $self->validate_signatures(
                $domain, $rr_type, \@dnskey_rrs
            );
        if (not @valid_rrs) {
            return;
        }
    }

    return 1;
}

sub has_matching_dnskeys
{
    my ($self, $domain, $cds_rrs, $cdnskey_rrs) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskey_rrs = rr($resolver, $domain, "DNSKEY");

    for my $cds_rr (@{$cds_rrs}) {
        my @matching_rrs = ds_to_matching_dnskeys($cds_rr, \@dnskey_rrs);
        if (not @matching_rrs) {
            return;
        }
    }

    for my $cdnskey_rr (@{$cdnskey_rrs}) {
        my $cdnskey_string = $cdnskey_rr->string();
        $cdnskey_string =~ s/CDNSKEY/DNSKEY/;
        my $match =
            first { $_->string() eq $cdnskey_string }
                @dnskey_rrs;
        if (not $match) {
            return;
        }
    }

    return 1;
}

sub nameservers_agree
{
    my ($self, $domain, $cds_rrs, $cdnskey_rrs) = @_;

    my $resolver = get_resolver($self, $domain);
    my @soa_rrs = rr($resolver, $domain, "SOA");
    my @ns_rrs = rr($resolver, $domain, "NS");
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
        my ($ns_cds_rrs, $ns_cdnskey_rrs) =
            map { [ rr($ns_resolver, $domain, $_) ] }
                qw(CDS CDNSKEY);
        if (not rrsets_are_equal($cds_rrs, $ns_cds_rrs)) {
            return;
        }
        if (not rrsets_are_equal($cdnskey_rrs, $ns_cdnskey_rrs)) {
            return;
        }
    }

    return 1;
}

sub post_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @txt_rrs = rr($resolver, "_delegate.$domain", "TXT");
    if (not @txt_rrs) {
        return $self->error(HTTP_FORBIDDEN,
                            "No token record",
                            "No _delegate TXT token record was found.");
    }
    my $token = $self->{"tokens"}->{$domain}->[0];
    if (not $token) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No token",
                            "No token has been generated for this domain.");
    }
    my $matching_rr = first { $_->rdstring() eq $token } @txt_rrs;
    if (not $matching_rr) {
        return $self->error(HTTP_FORBIDDEN,
                            "No matching token record",
                            "No matching TXT token record was found.");
    }
    my @cds_rrs = rr($resolver, $domain, "CDS");
    if (not @cds_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No CDS records",
                            "No CDS records were found.");
    }
    my @cdnskey_rrs = rr($resolver, $domain, "CDNSKEY");
    if (not @cdnskey_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No CDNSKEY records",
                            "No CDNSKEY records were found.");
    }
    my $res = $self->is_signed($domain);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Zone validation failed",
                            "The zone is unsigned or invalidly signed.");
    }
    $res = $self->has_matching_dnskeys($domain, \@cds_rrs, \@cdnskey_rrs);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Missing DNSKEYs for CDS/CDNSKEYs",
                            "One or more CDS/CDNSKEY records has no ".
                            "matching DNSKEY record.");
    }
    $res = $self->nameservers_agree($domain, \@cds_rrs, \@cdnskey_rrs);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Nameserver inconsistency",
                            "The nameservers for this domain have ".
                            "inconsistent CDS/CDNSKEY RR sets.");
    }

    my @ds_rrs = $self->generate_ds_records(\@cds_rrs, \@cdnskey_rrs);
    if (not @ds_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No usable DS input",
                            "None of the CDS/CDNSKEY records could ".
                            "be used to generate DS records.");
    }

    my $parent = domain_to_parent($domain);
    my $parent_resolver = get_resolver($self, $parent);
    my $update = Net::DNS::Update->new($parent, "IN");
    $update->push(update => rr_del("$domain DS"));
    for my $ds_rr (@ds_rrs) {
        $update->push(update => rr_add($ds_rr->string()));
    }
    sign_update($self, $parent, $update);
    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        warn("Unable to set DS records against server: ".Dumper($reply));
        return $self->error(HTTP_INTERNAL_SERVER_ERROR,
                            "Internal error",
                            "Unable to add DS records to server.");
    }

    delete $self->{"tokens"}->{$domain};

    return $self->success(HTTP_CREATED);
}

sub post
{
    my ($self, $c, $r, $domain, $rest) = @_;

    if ($rest eq "token") {
        return $self->post_token($c, $r, $domain);
    } elsif ($rest eq "cds") {
        return $self->post_cds($c, $r, $domain);
    }

    return $self->error(HTTP_NOT_FOUND);
}

sub delete_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskey_rrs = $self->get_dnskeys($domain);
    my @cds_rrs = $self->validate_signatures($domain, "CDS", \@dnskey_rrs);
    if (not @cds_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No CDS records",
                            "No CDS records were found.");
    }
    if (@cds_rrs > 1) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Multiple CDS records",
                            "Multiple CDS records were found.");
    }
    my $cds_rr = $cds_rrs[0];
    if ($cds_rr->algorithm() != 0) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Invalid CDS record",
                            "CDS record must have an algorithm of 0.");
    }

    my $parent = domain_to_parent($domain);
    my $update = Net::DNS::Update->new($parent, "IN");
    my $parent_resolver = get_resolver($self, $parent);
    $update->push(update => rr_del("$domain DS"));
    sign_update($self, $parent, $update);
    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        warn("Unable to delete DS records from server: ".Dumper($reply));
        return $self->error(HTTP_INTERNAL_SERVER_ERROR,
                            "Internal error",
                            "Unable to delete DS records from server.");
    }

    return $self->success(HTTP_OK);
}

sub delete
{
    my ($self, $c, $r, $domain, $rest) = @_;

    if ($rest eq "cds") {
        return $self->delete_cds($c, $r, $domain);
    }

    return $self->error(HTTP_NOT_FOUND);
}

sub put_cds
{
    my ($self, $c, $r, $domain) = @_;

    my $resolver = get_resolver($self, $domain);
    my @dnskey_rrs = $self->get_dnskeys($domain);
    my @cds_rrs =
        $self->validate_signatures($domain, "CDS", \@dnskey_rrs);
    if (not @cds_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No CDS records",
                            "No CDS records were found.");
    }
    my @cdnskey_rrs =
        $self->validate_signatures($domain, "CDNSKEY", \@dnskey_rrs);
    if (not @cdnskey_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No CDNSKEY records",
                            "No CDNSKEY records were found.");
    }
    my $res = $self->is_signed($domain);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Zone validation failed",
                            "The zone is unsigned or invalidly signed.");
    }
    $res = $self->has_matching_dnskeys($domain, \@cds_rrs, \@cdnskey_rrs);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Missing DNSKEYs for CDS/CDNSKEYs",
                            "One or more CDS/CDNSKEY records has no ".
                            "matching DNSKEY record.");
    }
    $res = $self->nameservers_agree($domain, \@cds_rrs, \@cdnskey_rrs);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST,
                            "Nameserver inconsistency",
                            "The nameservers for this domain have ".
                            "inconsistent CDS/CDNSKEY RR sets.");
    }

    my @ds_rrs = $self->generate_ds_records(\@cds_rrs, \@cdnskey_rrs);
    if (not @ds_rrs) {
        return $self->error(HTTP_BAD_REQUEST,
                            "No usable DS input",
                            "None of the CDS/CDNSKEY records could ".
                            "be used to generate DS records.");
    }

    my $parent = domain_to_parent($domain);
    my $update = Net::DNS::Update->new($parent, "IN");
    my $parent_resolver = get_resolver($self, $parent);
    $update->push(update => rr_del("$domain DS"));
    for my $ds_rr (@ds_rrs) {
        $update->push(update => rr_add($ds_rr->string()));
    }
    sign_update($self, $parent, $update);
    my $reply = $parent_resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        return $self->error(HTTP_INTERNAL_SERVER_ERROR,
                            "Internal error",
                            "Unable to update DS records on server.");
    }

    return $self->success(HTTP_OK);
}

sub put
{
    my ($self, $c, $r, $domain, $rest) = @_;

    if ($rest eq "cds") {
        return $self->put_cds($c, $r, $domain);
    }

    return $self->error(HTTP_NOT_FOUND);
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            print STDERR "$method $path\n";

            my ($domain, $rest) = ($path =~ /^\/domains\/(.*?)\/(.*)$/);
            if ((not $domain) or (not $rest)) {
                print STDERR "Unable to process request: invalid path\n";
                $c->send_response($self->error(HTTP_NOT_FOUND));
                next;
            }
            if (not is_domain($domain)) {
                print STDERR "Unable to process request: invalid domain\n";
                $c->send_response($self->error(HTTP_BAD_REQUEST,
                                               "Invalid domain name"));
                next;
            }
            my $parent = domain_to_parent($domain);
            my $details = $self->{'domains'}->{$parent};
            if (not $details) {
                print STDERR "Unable to process request: unhandled domain\n";
                $c->send_response($self->error(HTTP_BAD_REQUEST,
                                               "Unhandled domain name"));
                next;
            }

            my @args = ($c, $r, $domain, $rest);
            my $res = eval {
                ($method eq "POST")   ? $self->post(@args)
              : ($method eq "DELETE") ? $self->delete(@args)
              : ($method eq "PUT")    ? $self->put(@args)
                                      : $self->error(HTTP_NOT_FOUND);
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

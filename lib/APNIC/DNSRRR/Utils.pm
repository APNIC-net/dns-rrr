package APNIC::DNSRRR::Utils;

use warnings;
use strict;

use Net::DNS;
use Scalar::Util qw(blessed);

our @EXPORT_OK = qw(get_resolver
                    sign_update
                    is_sep
                    domain_to_parent
                    ds_to_matching_dnskeys
                    rrsets_are_equal);

use base qw(Exporter);

sub get_resolver
{
    my ($object, $domain) = @_;

    my $details = $object->{"domains"}->{$domain};
    my $resolver = Net::DNS::Resolver->new();

    my $server = $details->{"server"}
              || $object->{"default_server"};
    if ($server) {
        my ($port) = ($server =~ /.*:(.*)/);
        $server =~ s/:.*//;
        if ($server !~ /\./) {
            my @data = gethostbyname($server);
            my $addr = join '.', unpack('C4', $data[4]);
            $resolver->nameservers($addr);
        } else {
            $resolver->nameservers($server);
        }
        if ($port) {
            $resolver->port($port);
        }
    } else {
        my ($soa) = rr($resolver, $domain, "SOA");
        if (not $soa) {
            die "Unable to get SOA record for $domain";
        }
        $resolver->nameservers($soa->mname());
    }

    return $resolver;
}

sub sign_update
{
    my ($object, $domain, $update) = @_;

    my $details = $object->{"domains"}->{$domain};
    if ($details->{"tsig"}) {
        $update->sign_tsig($domain, $details->{"tsig"});
    }

    return 1;
}

sub is_sep
{
    my ($rr) = @_;

    return ($rr->can("is_sep")) ? $rr->is_sep() : $rr->sep();
}

sub domain_to_parent
{
    my ($domain) = @_;

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);

    return $parent;
}

sub ds_to_matching_dnskeys
{
    my ($ds_rr, $dnskey_rrs) = @_;

    my $pkg = blessed($ds_rr);
    my @matching_dnskey_rrs =
        grep { my $ds_rr_cmp =
                   $pkg->create(
                       $_,
                       digtype => $ds_rr->digtype()
                   );
               $ds_rr_cmp->string() eq $ds_rr->string() }
            @{$dnskey_rrs};

    return @matching_dnskey_rrs;
}

sub rrsets_are_equal
{
    my ($set_one, $set_two, $ignore_ttl) = @_;

    if (@{$set_one} != @{$set_two}) {
        return;
    }

    if ($ignore_ttl) {
        for my $obj (@{$set_one}, @{$set_two}) {
            $obj->ttl(0);
        }
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

1;

package APNIC::DNSRRR::Utils;

use warnings;
use strict;

use Scalar::Util qw(blessed);

our @EXPORT_OK = qw(get_resolver
                    sign_update
                    is_sep
                    domain_to_parent
                    ds_to_matching_dnskeys);

use base qw(Exporter);

sub get_resolver
{
    my ($object, $domain) = @_;

    my $details = $object->{'domains'}->{$domain};
    my $resolver = Net::DNS::Resolver->new();
    if ($details->{'server'}) {
        $resolver->nameservers($details->{'server'});
    }
    return $resolver;
}

sub sign_update
{
    my ($object, $domain, $update) = @_;

    my $details = $object->{'domains'}->{$domain};
    if ($details->{'tsig'}) {
        $update->sign_tsig($domain, $details->{'tsig'});
    }

    return 1;
}

sub is_sep
{
    my ($rr) = @_;

    return ($rr->can('is_sep')) ? $rr->is_sep() : $rr->sep();
}

sub domain_to_parent
{
    my ($domain) = @_;

    my ($parent) = ($domain =~ /^[^\.].*?\.(.*)$/);

    return $parent;
}

sub ds_to_matching_dnskeys
{
    my ($ds, $dnskeys) = @_;

    my $pkg = blessed($ds);
    my @matching_dnskeys =
        grep { my $ds_cmp =
                   $pkg->create(
                       $_,
                       digtype => $ds->digtype()
                   );
               $ds_cmp->string() eq $ds->string() }
            @{$dnskeys};

    return @matching_dnskeys;
}

1;

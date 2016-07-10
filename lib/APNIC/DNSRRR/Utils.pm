package APNIC::DNSRRR::Utils;

use warnings;
use strict;

our @EXPORT_OK = qw(get_resolver
		    sign_update
                    is_sep);

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

1;

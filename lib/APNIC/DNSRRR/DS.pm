package APNIC::DNSRRR::DS;

use warnings;
use strict;

use Net::DNS::RR::DS;
use Carp qw(croak);

# This package adds 0 (UNDEFINED) as a 'valid' DNSSEC algorithm, to
# support removal of DS records.  See section 4 of
# draft-ietf-dnsop-maintain-ds.

package Net::DNS::RR::DS;

my @algbyname = (               ## Reserved     => 0,   # [RFC4034][RFC4398]
        'UNDEFINED'          => 0,
        'RSAMD5'             => 1,                      # [RFC3110][RFC4034]
        'DH'                 => 2,                      # [RFC2539]
        'DSA'                => 3,                      # [RFC3755][RFC2536]
                                ## Reserved     => 4,   # [RFC6725]
        'RSASHA1'            => 5,                      # [RFC3110][RFC4034]
        'DSA-NSEC3-SHA1'     => 6,                      # [RFC5155]
        'RSASHA1-NSEC3-SHA1' => 7,                      # [RFC5155]
        'RSASHA256'          => 8,                      # [RFC5702]
                                ## Reserved     => 9,   # [RFC6725]
        'RSASHA512'          => 10,                     # [RFC5702]
                                ## Reserved     => 11,  # [RFC6725]
        'ECC-GOST'           => 12,                     # [RFC5933]
        'ECDSAP256SHA256'    => 13,                     # [RFC6605]
        'ECDSAP384SHA384'    => 14,                     # [RFC6605]

        'INDIRECT'   => 252,                            # [RFC4034]
        'PRIVATEDNS' => 253,                            # [RFC4034]
        'PRIVATEOID' => 254,                            # [RFC4034]
                                ## Reserved     => 255, # [RFC4034]
        );

my %algbyval = reverse @algbyname;

my $map = sub {
        my $arg = shift;
        return $arg if $arg =~ /^\d/;
        $arg =~ s/[^A-Za-z0-9]//g;                      # strip non-alphanumerics
        uc($arg);
};

my @pairedval = sort ( 0 .. 254, 0 .. 254 );            # also accept number
my %algbyname = map &$map($_), @algbyname, @pairedval;

no warnings;

sub _algbyname {
        my $name = shift;
        my $key  = uc $name;                            # synthetic key
        $key =~ s/[^A-Z0-9]//g;                         # strip non-alphanumerics
        (defined $algbyname{$key}) || croak "unknown algorithm $name";
        $algbyname{$key};
}

sub _algbyval {
        my $value = shift;
        $algbyval{$value} || return $value;
}

1;

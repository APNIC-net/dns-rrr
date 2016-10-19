use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::DNSRRR::Server',
    AUTHOR         => 'Tom Harrison <tomh@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/DNSRRR/Server.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/dns-rrr'
        }
    },
    EXE_FILES      => [ qw(bin/dns-rrr-client bin/dns-rrr-server) ],
    PREREQ_PM      => { 'Test::More'            => 0,
                        'HTTP::Daemon'          => 0,
                        'Net::DNS'              => 0,
                        'Net::DNS::SEC'         => 0,
                        'YAML'                  => 0,
                        'Bytes::Random::Secure' => 0,
                        'JSON::XS'              => 0,
                        'LWP::UserAgent'        => 0,
                        'List::MoreUtils'       => 0, }
);

1;

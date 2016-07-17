#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 2;

BEGIN {
    use_ok("APNIC::DNSRRR::Server");
    use_ok("APNIC::DNSRRR::Client");
}

1;

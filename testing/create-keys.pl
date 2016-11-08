#!/usr/bin/perl

use warnings;
use strict;

use File::Slurp qw(read_file);

sub run
{
    my ($cmd) = @_;
    my $res = system($cmd);
    if ($res != 0) {
        die "$cmd failed";
    }
    return $res;
}

my $zone = $ARGV[0];
my $content = read_file($zone);
my ($fqdn) = ($content =~ /^\$ORIGIN (.*)$/m);
run("../../testing/create-zsk.sh $fqdn");
run("../../testing/create-ksk.sh $fqdn");

#!/usr/bin/perl

use warnings;
use strict;

my ($in, $out) = @ARGV;
open my $fh,  '<', $in or die $!;
open my $fho, '>', $out or die $!;
while (defined (my $line = <$fh>)) {
    my ($dir) = ($line =~ /^include "(.*)"/);
    if ($dir) {
        my @paths = glob($dir);
        for my $path (@paths) {
            print $fho 'include "'.$path.'"'.";\n";
        }
    } else {
        print $fho $line;
    }
} 

1;

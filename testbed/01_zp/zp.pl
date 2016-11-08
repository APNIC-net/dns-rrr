#!/usr/bin/perl

use warnings;
use strict;

use HTTP::Daemon;
use HTTP::Response;
use JSON::XS qw(encode_json);

my $DNSSEC_PARTS = <<EOF;
    key-directory "/etc/bind/keys";
    auto-dnssec maintain;
    inline-signing yes;
EOF

my $count = 0;

sub generate_zone
{
    my ($auto_dnssec) = @_;

    my $fh;

    # Generate a new zone name.
    my $zone_name = "sd$count.example.com.";
    my $zone_name_np = $zone_name;
    $zone_name_np =~ s/\.$//;
    $count++;

    # Generate a key for the zone.
    my $path = `dnssec-keygen -r /dev/urandom -a HMAC-MD5 -b 128 -n HOST $zone_name`;
    chomp $path;
    open $fh, '<', $path.".private" or die $!;
    my $key;
    while (defined (my $line = <$fh>)) {
        ($key) = ($line =~ /^Key: (.*)$/);
        if ($key) {
            last;
        }
    }
    if (not $key) {
        die "Unable to generate/retrieve key";
    }
    close $fh;
    system("rm $path.*");

    # Write a new zonefile.
    open $fh, '>', "/etc/bind/zones.$zone_name_np" or die $!;
    print $fh <<EOF;
\$TTL    86400 ; 24 hours could have been written as 24h or 1d
; \$TTL used for all RRs without explicit TTL value
\$ORIGIN $zone_name
@  1D  IN  SOA ns1.$zone_name hostmaster.$zone_name (
                              2002022401 ; serial
                              3H ; refresh
                              15 ; retry
                              1w ; expire
                              3h ; nxdomain ttl
                             )
       IN  NS     ns1.$zone_name ; in the domain
; server host definitions
ns1    IN  A      127.0.0.4  ;name server definition
www    IN  A      127.0.0.4  ;web server definition
EOF
    close $fh;

    # Write a configuration file for the zonefile.
    my $extra;
    if ($auto_dnssec) {
        $extra = $DNSSEC_PARTS;
	my $path1 = `dnssec-keygen -r /dev/urandom -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $zone_name`;
        chomp $path1;
        system("mv $path1.* /etc/bind/keys/");
        my $path2 = `dnssec-keygen -r /dev/urandom -a NSEC3RSASHA1 -b 2048 -n ZONE $zone_name`;
        chomp $path2;
        system("mv $path2.* /etc/bind/keys/");
        system("chmod 777 /etc/bind/keys/*");
    }
    open $fh, '>', "/etc/bind/named.conf.d/$zone_name_np" or die $!;
    print $fh <<EOF;
key $zone_name_np {
    algorithm hmac-md5;
    secret "$key";
};

zone $zone_name_np {
    type master;
    file "/etc/bind/zones.$zone_name_np";
    allow-update { key $zone_name_np; };
    $extra
};
EOF
    close $fh;

    # Refresh bind's configuration.
    system("perl /etc/bind/process-named-conf.pl /etc/bind/named.conf.local.template /etc/bind/named.conf.local");

    # Reload bind's configuration.
    system("rndc -c /root/rndc.config reconfig");

    return ($zone_name, $key);
}

sub handle_request
{
    my ($c, $r) = @_;

    my %args = $r->uri()->query_form();
    my ($zone_name, $key) = generate_zone($args{'auto-dnssec'});

    my $res = HTTP::Response->new();
    $res->code(200);
    $res->header('Content-Type' => 'application/json');
    $res->content(encode_json({ name => $zone_name,
                                key  => $key }));
    $c->send_response($res);

    return 1;
}

sub main
{
    my $d = HTTP::Daemon->new(LocalPort => 8080) or die $!;
    while (my $c = $d->accept) {
	if (my $r = $c->get_request) {
	    if ($r->method eq 'POST' and $r->uri->path eq "/provision") {
                handle_request($c, $r);
	    } else {
		$c->send_error(404);
	    }
	}
	$c->close;
	undef($c);
    }
}

main();

1;

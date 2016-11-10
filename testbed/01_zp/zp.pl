#!/usr/bin/perl

use warnings;
use strict;

use Bytes::Random::Secure;
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Response;
use JSON::XS qw(encode_json);
use List::Util qw(first);
use Net::DNS;

my $DNSSEC_PARTS = <<EOF;
    key-directory "/etc/bind/keys";
    auto-dnssec maintain;
    inline-signing yes;
EOF

my $PORT = 8082;

my $tsig;
my $nameserver;

sub generate_zone
{
    my ($auto_dnssec) = @_;

    my $fh;

    my $resolver = Net::DNS::Resolver->new();
    $resolver->nameservers($nameserver);

    # Generate a new zone name.
    my $brs = Bytes::Random::Secure->new(Bits => 512, NonBlocking => 1);
    my $token;
    do {
        $token = $brs->bytes_hex(4);
    } while ($resolver->query("$token.example.com", "NS"));

    my $zone_name = "$token.example.com.";
    my $zone_name_np = $zone_name;
    $zone_name_np =~ s/\.$//;

    # Add an NS record to the parent.
    my $update = Net::DNS::Update->new("example.com", "IN");
    $update->push(update => rr_add("$zone_name NS ns1.$zone_name_np"));
    $update->sign_tsig("example.com", $tsig);
    my $reply = $resolver->send($update);
    if ((not $reply) or ($reply->header()->rcode() ne "NOERROR")) {
        warn "Unable to add NS record to parent: ".
             Dumper($reply, $nameserver, $tsig, $update);
        return;
    }

    # Generate a key for the zone.
    my ($path) = `dnssec-keygen -r /dev/urandom -a HMAC-MD5 -b 128 -n HOST $zone_name`;
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
        warn "Unable to generate/retrieve key";
        return;
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
	my ($path1) = `dnssec-keygen -r /dev/urandom -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $zone_name`;
        chomp $path1;
        system("mv $path1.* /etc/bind/keys/");
        my ($path2) = `dnssec-keygen -r /dev/urandom -a NSEC3RSASHA1 -b 2048 -n ZONE $zone_name`;
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
    my $result = system("perl /etc/bind/process-named-conf.pl /etc/bind/named.conf.local.template /etc/bind/named.conf.local");
    if ($result != 0) {
        warn "Unable to refresh bind's configuration";
        return;
    }

    # Reload bind's configuration.
    $result = system("rndc -c /root/rndc.config reconfig");
    if ($result != 0) {
        warn "Unable to reload bind's configuration";
        return;
    }

    return ($zone_name, $key);
}

sub handle_generate_key_request
{
    my ($c, $r, $zone) = @_;

    my $res = HTTP::Response->new();

    my ($keypath) =
        `dnssec-keygen -r /dev/urandom -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $zone. 2>/dev/null`;
    chomp $keypath;
    system("chmod 777 $keypath*");
    system("mv $keypath* /etc/bind/keys/");
    my $result = system("rndc -c /root/rndc.config loadkeys $zone.");
    if ($result != 0) {
        warn "Unable to load keys into zone";
        $res->code(500);
        $c->send_response($res);
        return;
    }

    $res->code(200);
    $c->send_response($res);

    return 1;
}

sub handle_remove_key_request
{
    my ($c, $r, $zone) = @_;

    my $res = HTTP::Response->new();

    my %args = $r->uri()->query_form();
    my $tag = $args{'tag'};
    if (not $tag) {
        warn "No tag for $zone key removal request";
        $res->code(400);
        $c->send_response($res);
    }

    my ($previous_path) =
	map { chomp; $_ }
            `ls /etc/bind/keys/K$zone.*$tag.key`;

    system("rndc -c /root/rndc.config sign $zone.");
    sleep(1);
    my @rndc_keys =
        map { chomp; $_ }
            `rndc -c /root/rndc.config signing -list $zone.`;
    my $to_remove = first { /$tag/ } @rndc_keys;
    $to_remove =~ s/.* key //;

    my $result =
        system("dnssec-settime -I +0 -D +0 $previous_path");
    if ($result != 0) {
        warn "Unable to set time to zero for key $tag for $zone";
        $res->code(500);
        $c->send_response($res);
        return;
    }
    system("chmod 777 /etc/bind/keys/*");

    $result = system("rndc -c /root/rndc.config signing -clear ".
                     "$to_remove $zone.");
    if ($result != 0) {
        warn "Unable to clear signing for key $tag for $zone";
        $res->code(500);
        $c->send_response($res);
        return;
    }
    $result = system("rndc -c /root/rndc.config loadkeys $zone.");
    if ($result != 0) {
        warn "Unable to load keys for $zone";
        $res->code(500);
        $c->send_response($res);
        return;
    }

    $res->code(200);
    $c->send_response($res);

    return 1;
}

sub handle_provision_request
{
    my ($c, $r) = @_;

    my $res = HTTP::Response->new();

    my %args = $r->uri()->query_form();
    my ($zone_name, $key) = generate_zone($args{'auto-dnssec'});

    if (not $zone_name) {
        $res->code(500);
        $c->send_response($res);
    } else {
        $res->code(200);
        $res->header('Content-Type' => 'application/json');
        $res->content(encode_json({ name => $zone_name,
                                    key  => $key }));
        $c->send_response($res);
    }

    return 1;
}

sub zone_to_tsig
{
    my ($zone_name) = @_;

    open my $fh, '<', "/etc/bind/named.conf.d/$zone_name" or die $!;
    my $key;
    while (defined (my $line = <$fh>)) {
        chomp $line;
        ($key) = ($line =~ /secret "(.*)";/);
        if ($key) {
            last;
        }
    }
    return $key;
}

sub main
{
    print "Starting ZP\n";

    open my $fh, '<', '/root/rndc.config' or die $!;
    my @data = <$fh>;
    close $fh;

    ($tsig) = first { /secret/ } @data;
    chomp $tsig;
    $tsig =~ s/.*"(.+)".*/$1/;
    ($nameserver) = first { /default-server/ } @data;
    chomp $nameserver;
    $nameserver =~ s/.*default-server\s*(.+);/$1/;
    my @ipdata = gethostbyname($nameserver);
    $nameserver = join '.', unpack('C4', $ipdata[4]);

    print "TSIG is '$tsig', nameserver is '$nameserver'\n";

    print "Binding to $PORT\n";
    my $d = HTTP::Daemon->new(LocalPort => $PORT,
			      ReuseAddr => 1,
			      ReusePort => 1) or die $!;
    print "Bound to $PORT, waiting for connections\n";
    while (my $c = $d->accept) {
        eval {
            print "Accepted connection\n";
            my $r = $c->get_request();
            if (not $r) {
                die "No request";
            }
            my $m = $r->method();
            my $p = $r->uri->path();
            print "$m $p\n";
            if ($m eq 'POST') {
                if ($p eq "/provision") {
                    handle_provision_request($c, $r);
                } else {
                    my ($zone, $action) = ($p =~ m!/(.*.example.com)/(.*)$!);
                    my $tsig = zone_to_tsig($zone);
                    my ($arg_tsig) =
                        ($r->header("Authorization") =~ /^Bearer (.+)$/);
                    if ((not $arg_tsig) or ($arg_tsig ne $tsig)) {
                        $c->send_error(401);
                    } elsif ($action eq "generate-key") {
                        handle_generate_key_request($c, $r, $zone);
                    } elsif ($action eq "remove-key") {
                        handle_remove_key_request($c, $r, $zone);
                    } else {
                        $c->send_error(404);
                    }
                }
            } else {
                $c->send_error(404);
            }
        };
        if (my $error = $@) {
            print "Error: $error\n";
            $c->send_error(500);
        }
        print "Finished with connection\n";
	$c->close;
	undef($c);
    }
}

main();

1;

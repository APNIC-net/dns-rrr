package APNIC::DNSRRR::Test::Utils;

use warnings;
use strict;

use APNIC::DNSRRR::Server;

use JSON::XS qw(decode_json);
use List::Util qw(first);

our @EXPORT_OK = qw(start_test_servers
                    stop_test_servers
                    generate_new_ksk
                    roll_ksk
                    unsign_zone);

use base qw(Exporter);

sub start_test_servers
{
    my ($config_path) = @_;

    if (not $config_path) {
        $config_path = "testing/config-server.yml";
    }

    my @pids;
    my @servers;

    my $server = APNIC::DNSRRR::Server->new(
        %{YAML::LoadFile($config_path)}
    );
    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $server;
    } else {
        if (not $ENV{"DNSRRR_DEBUG"}) {
            close STDERR;
        }
        $server->run();
        exit();
    }

    system("./testing/start.sh >/dev/null");
    # todo: check that the servers are actually up.
    sleep(5);

    return [ \@pids, \@servers ];
}

sub stop_test_servers
{
    my ($pids) = @_;

    for my $pid (@{$pids}) {
        kill 9, $pid;
        waitpid $pid, 0;
    }

    system("./testing/stop.sh >/dev/null");
}

sub get_keydir
{
    my ($domain) = @_;

    my $container_name =
        ($domain eq "example.com")
            ? "bind_parent"
            : "bind_child";

    my ($id) = `docker ps | grep $container_name | cut -f 1 -d" "`;
    chomp $id;
    my ($json) = `docker inspect -f "{{json .Mounts }}" $id`;
    my $data = decode_json($json);
    my $path = $data->[0]->{"Source"};
    my $keydir = "$path/bind/etc/keys";

    return $keydir;
}

sub generate_new_ksk
{
    my ($domain) = @_;

    my $keydir = get_keydir($domain);
    my (@keygen_content) =
        `dnssec-keygen -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $domain. 2>/dev/null`;
    my $keypath = $keygen_content[$#keygen_content];
    chomp $keypath;
    system("mv $keypath* $keydir");
    system("rndc -c ./testing/01_child/rndc.config loadkeys us.example.com.");

    return 1;
}

sub get_config_path
{
    my ($domain) = @_;

    my $config_dir =
        ($domain eq "example.com")
            ? "00_parent"
            : "01_child";
    my $config_path = "./testing/$config_dir/rndc.config";

    return $config_path;
}

sub roll_ksk
{
    my ($domain, $previous_ksk_tag) = @_;

    my $keydir = get_keydir($domain);
    my @previous_paths = map { chomp; $_ } `ls $keydir/*$previous_ksk_tag*`;
    my $previous_path = first { /\.key$/ } @previous_paths;

    my $config_path = get_config_path($domain);
    system("rndc -c $config_path sign $domain.");
    sleep(1);
    my @rndc_keys =
        map { chomp; $_ }
            `rndc -c $config_path signing -list $domain.`;
    my $to_remove = first { /$previous_ksk_tag/ } @rndc_keys;
    $to_remove =~ s/.* key //;

    system("dnssec-settime -I +0 -D +0 $previous_path >/dev/null 2>&1");
    system("rndc -c $config_path signing -clear $to_remove $domain. ".
           ">/dev/null 2>&1");
    system("rndc -c $config_path loadkeys $domain.");

    return 1;
}

sub unsign_zone
{
    my ($domain) = @_;

    my $keydir = get_keydir($domain);
    my @key_paths = grep { /\.key$/ } map { chomp; $_ } `ls $keydir/*`;
    for my $key_path (@key_paths) {
        system("dnssec-settime -I +0 -D +0 $key_path >/dev/null 2>&1");
    }

    my $config_path = get_config_path($domain);
    my @rndc_keys =
        map { s/.* key //; $_ }
        map { chomp; $_ }
            `rndc -c $config_path signing -list $domain.`;
    for my $rndc_key (@rndc_keys) {
        system("rndc -c $config_path signing -clear $rndc_key $domain. ".
               ">/dev/null 2>&1");
    }
    system("rndc -c $config_path loadkeys $domain.");

    return 1;
}

1;

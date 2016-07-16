package APNIC::DNSRRR::Test::Utils;

use warnings;
use strict;

use APNIC::DNSRRR::Server;

our @EXPORT_OK = qw(start_test_servers
                    stop_test_servers);

use base qw(Exporter);

sub start_test_servers
{
    my ($config_path) = @_;

    if (not $config_path) {
        $config_path = 'testing/config-server.yml';
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
        $server->run();
        exit();
    }

    system("./testing/start.sh >/dev/null");

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

1;

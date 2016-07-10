package APNIC::DNSRRR::Test::Utils;

use warnings;
use strict;

use APNIC::DNSRRR::Server;

our @EXPORT_OK = qw(start_test_servers
                    stop_test_servers);

use base qw(Exporter);

sub start_test_servers
{
    my @pids;
    my @servers;

    my $server = APNIC::DNSRRR::Server->new(
        %{YAML::LoadFile('testing/config-server.yml')}
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

# dns-rrr

Client and server implementations of [draft-ietf-regext-dnsoperator-to-rrr-protocol](https://tools.ietf.org/html/draft-ietf-regext-dnsoperator-to-rrr-protocol).

## Dependencies

Perl dependencies are listed in `Makefile.PL`.  To run the tests,
Docker (>= 1.8.3) and bind (>= 9.10) are required as well.

## Installation

    perl Makefile.PL
    make
    cd testing
    ./build.sh
    cd ..
    make test
    sudo make install

## Configuration

Configuration is in YAML format.  Server configuration is like so:

    port: {port}
    domains:
      {domain-name}:
        server: {dns-server-for-domain}
        tsig: {key-for-dns-update}
      ...
    ds_from: {CDS|CDNSKEY}
    ds_digest_types: [{SHA-1|SHA-256|SHA-384|GOST}, ...]

`port` is the port on which the server will run.  `domains` contains
information about DNS servers and update keys for specific domains.
`ds_from` is the type of record that should be used to generate DS
records (defaults to CDS).  `ds_digest_types` is the set of digest
algorithms for which DS records should be generated (only relevant
when `ds_from` is CDNSKEY, and defaults to SHA-1 and SHA-256).

Client configuration is like so:

    domains:
      {domain-name}:
        server: {dns-server-for-domain}
        tsig: {key-for-dns-update}
        dns-rrr-server: {dns-rrr-server-url}
      ...
    cds_digest_types: [{SHA-1|SHA-256|SHA-384|GOST}, ...]
    keep_cds: {1|0}
    keep_cdnskey: {1|0}

`domains` is the same as for server configuration, except that each
domain for which updates will be sent must be present, and each domain
must have an additional `dns-rrr-server` entry pointing to the server
providing this protocol for that domain.  `cds_digest_types` is the
set of digest algorithms for which CDS records should be generated
(defaults to SHA-1 and SHA-256).  `keep_cds` and `keep_cdnskey`
indicate whether records of those types should not be deleted after
use (defaults to false for both).

## Example usage

    $ ./testing/start.sh
    322169d3c33808a4766610458a87266b2fc666175965776f33bfda37b8a4be8f
    d91f3505cece3f3279cd3cd0f2259a03fd0ca1994db4a7d57a7c3bbb63c62eef

This will start two Docker containers, each running bind with DNSSEC
enabled, one for `example.com` (127.0.0.2) and one for
`us.example.com` (127.0.0.3).

    $ dns-rrr-server testing/config-server.yml &
    Running on port 34517...
    $ dig @127.0.0.3 +short DS us.example.com
    $ dns-rrr-client testing/config-client.yml us.example.com --initialise
    $ dig @127.0.0.2 +short DS us.example.com
    16023 7 1 59913E4E49AA288EA3D54D3855C5FDC3494D2F56
    16023 7 2 BD13E33A85F3C547CB8C6E213CA709315382140438CD4FD9CF39CE46 C9791870
    $ dns-rrr-client testing/config-client.yml us.example.com --delete
    $ dig @127.0.0.2 +short DS us.example.com

The other client command is `--update`, which recreates the CDS and
CDNSKEY records and executes a PUT against the server, requesting that
it refresh its DS records accordingly.  For testing key rollover and
other scenarios: use `docker inspect -f {{ .Mounts }} $id` to find the
base bind configuration directory, and see `testing/00_parent` and
`testing/01_child` for RNDC configuration files.

## License

See [LICENSE.txt](LICENSE.txt).

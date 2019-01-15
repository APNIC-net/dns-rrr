## Public testbed

The public testbed comprises a dummy instance of bind, a dns-rrr
service, and a zone provisioning service.  The bind instance is
self-contained, and does not interact with any other DNS server.  Each
service runs on rrr.ideas.apnic.net.

To provision a zone for testing, send a POST request to the zone
provisioning service:

    $ curl -X POST http://rrr.ideas.apnic.net:8082/provision?auto-dnssec=1
    {"key":"W5QimCOOAwBveXxRLCB8+w==","name":"b15c6ace.example.com."}

The response contains the name of the new zone, as well as a TSIG key
that can be used to perform dynamic DNS updates against that zone via
the dummy instance of bind.  The `auto-dnssec` argument is optional:
if set, DNSSEC keys will be generated for the zone and any updates
made to the zone will cause new RRSIGs to be generated automatically.

To test with the dns-rrr client, write a configuration file:

    $ cat config.yml
    domains:
      b15c6ace.example.com:
        server: rrr.ideas.apnic.net
        tsig: "W5QimCOOAwBveXxRLCB8+w=="
        dns-rrr-server: http://rrr.ideas.apnic.net:8081

and then initialise DNSSEC:

    $ dns-rrr-client config.yml b15c6ace.example.com --initialise

at which point it should be possible to see the created DS records:

    $ dig +tcp @rrr.ideas.apnic.net +short DS b15c6ace.example.com | sort
    46524 7 1 D097B8E9E4372B0CA0E76A4FF83D893C039DC2BB
    46524 7 2 7AC4AD23C7653ADE032C1EFFF5F9E91C24640984D3A86C53A13C29C7 12CE98B9
    46524 7 4 5CAF943D6135B46B0F60C874E21A6A82B555CE4D5370B2D7F859B47C E328C3F38A9B61E25863A2CE6412E1A23EC29E82

To create a new KSK, send a request to the zone provisioning service:

    $ curl -i -X POST -H "Authorization: Bearer W5QimCOOAwBveXxRLCB8+w==" http://rrr.ideas.apnic.net:8082/b15c6ace.example.com/generate-key
    HTTP/1.1 200 OK
    ...

To update the DS records accordingly:

    $ dns-rrr-client config.yml b15c6ace.example.com --update
    $ dig +tcp @rrr.ideas.apnic.net +short DS b15c6ace.example.com | sort
    11295 7 1 EAA6A596154F0C045BB3874137864DB014D29BCA
    11295 7 2 B95F66C61788F6060EB5BF6DC5F20A1F4F03BADCD8F1108BD3FE1D2B 564E8CBF
    11295 7 4 CBA2BAE0C5411DDED0D5CCD77AECC6BF5ECDFC15699A593F6F3F70F6 FE5CA5187EBDB0E85DCBC70ABD3427C6E93A4637
    46524 7 1 D097B8E9E4372B0CA0E76A4FF83D893C039DC2BB
    46524 7 2 7AC4AD23C7653ADE032C1EFFF5F9E91C24640984D3A86C53A13C29C7 12CE98B9
    46524 7 4 5CAF943D6135B46B0F60C874E21A6A82B555CE4D5370B2D7F859B47C E328C3F38A9B61E25863A2CE6412E1A23EC29E82

To remove an existing KSK:

    $ curl -i -X POST -H "Authorization: Bearer W5QimCOOAwBveXxRLCB8+w==" http://rrr.ideas.apnic.net:8082/b15c6ace.example.com/remove-key?tag=46524
    HTTP/1.1 200 OK
    ...
    $ dns-rrr-client config.yml b15c6ace.example.com --update
    $ dig +tcp @rrr.ideas.apnic.net +short DS b15c6ace.example.com | sort
    11295 7 1 EAA6A596154F0C045BB3874137864DB014D29BCA
    11295 7 2 B95F66C61788F6060EB5BF6DC5F20A1F4F03BADCD8F1108BD3FE1D2B 564E8CBF
    11295 7 4 CBA2BAE0C5411DDED0D5CCD77AECC6BF5ECDFC15699A593F6F3F70F6 FE5CA5187EBDB0E85DCBC70ABD3427C6E93A4637

To disable DNSSEC:

    $ dns-rrr-client config.yml b15c6ace.example.com --delete
    $ dig +tcp @rrr.ideas.apnic.net +short DS b15c6ace.example.com | sort
    $

If you run into any problems with the testbed/dns-rrr-client, or have
any feedback/suggestions, please contact tomh@apnic.net or
helpdesk@apnic.net.

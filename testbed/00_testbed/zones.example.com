$TTL	86400 ; 24 hours could have been written as 24h or 1d
; $TTL used for all RRs without explicit TTL value
$ORIGIN example.com.
@  1D  IN  SOA ns1.example.com. hostmaster.example.com. (
			      2002022401 ; serial
			      3H ; refresh
			      15 ; retry
			      1w ; expire
			      3h ; nxdomain ttl
			     )
       IN  NS     ns1.example.com. ; in the domain
; server host definitions
ns1    IN  A      127.0.0.4  ;name server definition     
www    IN  A      127.0.0.4  ;web server definition

$ORIGIN sd0
@       IN  NS  ns1
ns1     IN  A   127.0.0.4

$ORIGIN sd1
@       IN  NS  ns1
ns1     IN  A   127.0.0.4

$ORIGIN sd2
@       IN  NS  ns1
ns1     IN  A   127.0.0.4

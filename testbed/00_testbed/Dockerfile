FROM sameersbn/bind:9d576d697e3e

RUN usermod -u 1000 bind
COPY zones.example.com /etc/bind/
COPY named.conf.local.template /etc/bind
COPY process-named-conf.pl /etc/bind
RUN mkdir /etc/bind/named.conf.d
COPY ./named.conf.d/named.conf.local /etc/bind/named.conf.d
COPY ./named.conf.d/named.conf.options /etc/bind/named.conf.d
COPY empty /etc/bind/named.conf.options
RUN mkdir /etc/bind/keys
COPY K* /etc/bind/keys/
RUN chown -R bind:bind /etc/bind
RUN chown -R bind:bind /var/cache/bind
RUN perl /etc/bind/process-named-conf.pl /etc/bind/named.conf.local.template /etc/bind/named.conf.local

ENTRYPOINT ["/sbin/entrypoint.sh"]
CMD ["/usr/sbin/named"]

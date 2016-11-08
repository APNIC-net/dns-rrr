FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y \
    libhttp-daemon-perl \
    libjson-xs-perl \
    libyaml-perl \
    libbytes-random-secure-perl \
    libdata-validate-domain-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    cpanminus \
    libssl-dev \
    make \
    dnsutils
RUN cpanm Net::DNS && cpanm Net::DNS::SEC
ADD dns-rrr /root/dns-rrr
ADD config-server.yml /root/dns-rrr/config-server.yml
RUN cd /root/dns-rrr/ && perl Makefile.PL && make && make install
CMD ["perl", "-MCarp::Always", "/root/dns-rrr/bin/dns-rrr-server", "/root/dns-rrr/config-server.yml"]

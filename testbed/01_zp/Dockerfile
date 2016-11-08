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
    tree \
    bind9utils \
    dnsutils
RUN cpanm Net::DNS && cpanm Net::DNS::SEC
COPY zp.pl /root/
COPY rndc.config /root/
RUN ln -s /data/bind/etc /etc/bind
CMD ["perl", "/root/zp.pl"]

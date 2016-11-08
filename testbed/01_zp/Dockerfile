FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y tree
RUN apt-get install -y bind9utils
RUN apt-get install -y libhttp-daemon-perl
RUN apt-get install -y libjson-xs-perl
COPY zp.pl /root/
COPY rndc.config /root/
RUN ln -s /data/bind/etc /etc/bind
CMD ["perl", "/root/zp.pl"]

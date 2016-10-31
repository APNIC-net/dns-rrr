#!/bin/sh
dnssec-keygen -r /dev/urandom -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $1

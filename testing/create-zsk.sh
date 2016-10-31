#!/bin/sh
dnssec-keygen -r /dev/urandom -a NSEC3RSASHA1 -b 2048 -n ZONE $1

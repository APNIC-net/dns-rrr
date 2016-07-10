#!/bin/sh
dnssec-keygen -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE $1

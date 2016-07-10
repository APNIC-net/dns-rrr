#!/bin/sh
dnssec-keygen -a NSEC3RSASHA1 -b 2048 -n ZONE $1

#!/bin/sh
set -e
rm -rf dns-rrr
mkdir dns-rrr
cd ../../
cp -r `ls | grep -v "testbed"` ./testbed/02_rrr/dns-rrr/
cd testbed/02_rrr
docker build -t bind_rrr .
rm -rf dns-rrr

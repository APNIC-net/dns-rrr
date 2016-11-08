#!/bin/sh
rm -f K*
rm -f dsset-example.com.
../../testing/create-keys.pl zones.example.com
cp Dockerfile.template Dockerfile
uid=$(id -u)
sed -i -e "s/\${USER_ID}/$uid/" Dockerfile
touch empty
docker build -t bind_testbed .
rm empty

#!/bin/sh
rm -f K*
rm -f dsset-example.com.
../create-keys.pl zones.parent
cp Dockerfile.template Dockerfile
uid=$(id -u)
sed -i -e "s/\${USER_ID}/$uid/" Dockerfile
docker build -t bind_parent .

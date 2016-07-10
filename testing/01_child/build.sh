#!/bin/sh
rm -f K*
rm -f dsset-us.example.com.
../create-keys.pl zones.child
cp Dockerfile.template Dockerfile
uid=$(id -u)
sed -i -e "s/\${USER_ID}/$uid/" Dockerfile
docker build -t bind_child .

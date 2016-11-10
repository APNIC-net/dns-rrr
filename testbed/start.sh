#!/bin/sh
if [ $# -eq 0 ]
    then
        dir1=`mktemp -d`
    else
        dir1=$1
fi
echo $dir1
docker run --name bind_testbed -d --restart=always \
  --publish 127.0.0.4:53:53/tcp \
  --publish 127.0.0.4:53:53/udp \
  --publish 127.0.0.4:953:953/tcp \
  --publish 127.0.0.4:10000:10000/tcp \
  --volume $dir1:/data \
  bind_testbed
docker run --name bind_zp -d --restart=always \
  --publish 127.0.0.4:8082:8082/tcp \
  --volume $dir1:/data \
  --link bind_testbed:bind_testbed \
  bind_zp
docker run --name bind_rrr -d --restart=always \
  --publish 127.0.0.4:8081:8081/tcp \
  --link bind_testbed:bind_testbed \
  bind_rrr

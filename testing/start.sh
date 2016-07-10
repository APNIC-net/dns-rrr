#!/bin/sh
dir1=`mktemp -d`
dir2=`mktemp -d`
docker run --name bind_parent -d --restart=always \
  --publish 127.0.0.2:53:53/tcp \
  --publish 127.0.0.2:53:53/udp \
  --publish 127.0.0.2:953:953/tcp \
  --publish 127.0.0.2:10000:10000/tcp \
  --volume $dir1:/data \
  bind_parent
docker run --name bind_child -d --restart=always \
  --publish 127.0.0.3:53:53/tcp \
  --publish 127.0.0.3:53:53/udp \
  --publish 127.0.0.3:953:953/tcp \
  --publish 127.0.0.3:10000:10000/tcp \
  --volume $dir2:/data \
  bind_child

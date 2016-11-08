#!/bin/sh
docker ps | grep bind_parent | cut -f 1 -d' ' | xargs docker stop | xargs docker rm
docker ps | grep bind_child  | cut -f 1 -d' ' | xargs docker stop | xargs docker rm

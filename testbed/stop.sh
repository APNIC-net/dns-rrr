#!/bin/sh
docker ps | grep bind_testbed | cut -f 1 -d' ' | xargs docker stop | xargs docker rm
docker ps | grep bind_zp      | cut -f 1 -d' ' | xargs docker stop | xargs docker rm
docker ps | grep bind_rrr     | cut -f 1 -d' ' | xargs docker stop | xargs docker rm

#!/bin/sh
set -e;
for dir in `ls | sort`; do
    if [ -d "$dir" ]; then
        echo $dir;
        cd $dir;
        ./build.sh;
        cd ..;
    fi;
done;

#!/usr/bin/env sh
work_dir=$1
docker run -e TERM --privileged --security-opt seccomp:unconfined -v $work_dir:/mnt/files --name=re3 -it bruce30262/re3 /bin/bash

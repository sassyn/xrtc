#!/bin/bash

export GOPATH="/gopath"

[ -e "/gobuild" ] && cd "/gobuild"

if [ -f "/tmp/etc/routes.yml" ]; then
    host_ip=$(cat /etc/hosts | grep "host_ip" | awk '{print $1}')
    if [ "###$host_ip" != "###" ]; then
        sed -i "s#host_ip#$host_ip#" /tmp/etc/routes.yml
    fi
fi

exec "$@"

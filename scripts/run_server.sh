#!/usr/bin/env bash

make
bin=/local/repository/cmd/hotstuffserver/hotstuffserver
$bin --self-id $1 --privkey /local/repository/keys/$2 "$@" > $1.out &
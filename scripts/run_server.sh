#!/usr/bin/env bash

bin=/local/hotstuff/cmd/hotstuffserver/hotstuffserver
$bin --self-id $1 --privkey /local/hotstuff/keys/$2 "$@" > $1.out &
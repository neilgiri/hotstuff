#!/usr/bin/env bash

sudo tar -C /usr/local -xvzf go1.15.7.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
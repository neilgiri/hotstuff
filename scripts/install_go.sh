#!/usr/bin/env bash

sudo tar -C /usr/local -xvzf /local/go1.15.7.linux-amd64.tar.gz
export PATH=$PATH:/local/go/bin
sudo echo "export PATH=$PATH:/local/go/bin" >> ~/.profile
source ~/.profile
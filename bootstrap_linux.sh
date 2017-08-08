#!/usr/bin/env bash
set -o errexit
set -o nounset

# Install dependencies.
UBUNTU_NAME=$(lsb_release -s -c)
LLDB_VERSION="4.0"

# We need lldb version 4.0 so we add llvm's custom apt repos.
wget -O - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-add-repository "deb http://apt.llvm.org/$UBUNTU_NAME/ llvm-toolchain-$UBUNTU_NAME-$LLDB_VERSION main"

# Update and install dependencies.
sudo apt-get update
sudo apt-get install build-essential git cmake python-setuptools \
    python-dev libboost-python-dev libglib2.0-dev pkg-config \
    llvm clang python-pyparsing liblldb-$LLDB_VERSION -y

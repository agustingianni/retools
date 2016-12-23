#!/usr/bin/env bash

# Create a symbolic link to the project.
if [ ! -L retools ]; then
    ln -s /vagrant retools
fi

# Install dependencies.
apt-get update
apt-get install build-essential git cmake python-setuptools \
    python-dev libboost-python-dev libglib2.0-dev pkg-config \
    llvm clang -y

# Create a temporary directory.
DEPS_DIR=$(mktemp -d)

# Change to the temporary directory.
pushd $DEPS_DIR

if [ ! -f /usr/lib/libcapstone.a ]; then
    echo "Could not find Capstone Engine, installing it from sources."
    # Install capstone + python bindings.
    git clone https://github.com/aquynh/capstone.git
    pushd capstone
        ./make.sh
        sudo ./make.sh install
        pushd bindings/python
            make
            sudo make install
        popd
    popd
fi

if [ ! -f /usr/lib/libunicorn.a ]; then
    echo "Could not find Unicorn Engine, installing it from sources."
    # Install unicorn + python bindings.
    git clone https://github.com/unicorn-engine/unicorn.git
    pushd unicorn
        ./make.sh
        sudo ./make.sh install
        pushd bindings/python
            make
            sudo make install
        popd
    popd
fi

if [ ! -f /usr/lib/libdarm.a ]; then
    echo "Could not find DARM, installing it from sources."
    # Install darm.
    git clone https://github.com/jbremer/darm.git
    pushd darm
        make
        sudo cp libdarm.a /usr/lib
        sudo cp libdarm.so /usr/lib
        sudo mkdir -p /usr/include/darm
        sudo cp *.h /usr/include/darm/
    popd
fi

if [ ! -f /usr/local/bin/afl-fuzz ]; then
    echo "Could not find afl-fuzz, installing it from sources."
    wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
    tar xzf afl-latest.tgz
    cd afl*
    make
    cd llvm_mode
    make
    sudo make install
popd

rm -rf $DEPS_DIR
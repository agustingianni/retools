#!/usr/bin/env bash
set -o errexit
set -o nounset

# Create a symbolic link to the project.
if [ ! -L retools ]; then
    ln -s /vagrant retools
fi

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

# Create a temporary directory.
DEPS_DIR=$(mktemp -d)

# Change to the temporary directory.
pushd $DEPS_DIR

if [ ! -f /usr/lib/libcapstone.a ]; then
    echo "Could not find Capstone Engine, installing it from sources."
    # Install capstone + python bindings.
    git clone https://github.com/aquynh/capstone.git
    pushd capstone
        CAPSTONE_ARCHS=arm ./make.sh
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
        MACOS_UNIVERSAL=yes UNICORN_ARCHS=arm UNICORN_DEBUG=yes ./make.sh
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
    AFL_DIRNAME=$(tar tzf afl-latest.tgz | sed -e 's@/.*@@' | uniq)
    tar xzf afl-latest.tgz
    cd $AFL_DIRNAME
    make
    cd llvm_mode
    make
    cd ..
    sudo make install
fi

popd

rm -rf $DEPS_DIR
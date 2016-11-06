#!/usr/bin/env bash

# Create a symbolic link to the project.
ln -s /vagrant retools

# Install dependencies.
apt-get update
apt-get install build-essential git cmake python-setuptools \
    python-dev libboost-python-dev libglib2.0-dev pkg-config -y

# Create a temporary directory.
DEPS_DIR=$(mktemp -d)

# Change to the temporary directory.
pushd $DEPS_DIR

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

# Install unicorn + python bindings.
git clone https://github.com/unicorn-engine/unicorn.git
pushd unicorn
./make.sh
sudo ./make.sh install
pushd bindings/python
make
sudo make install
popd

# Install darm.
git clone https://github.com/jbremer/darm.git
pushd darm
make
sudo cp libdarm.a /usr/lib
sudo cp libdarm.so /usr/lib
sudo mkdir /usr/include/darm
sudo cp *.h /usr/include/darm/
popd

popd

rm -rf $DEPS_DIR
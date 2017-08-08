#!/usr/bin/env bash
BINARY_DIR=$1
INSTALL_DIR=$2

pushd $BINARY_DIR > /dev/null
cp libdarm.a $INSTALL_DIR/usr/local/lib
cp libdarm.so $INSTALL_DIR/usr/local/lib

# Darm's makefile sucks.
if [ "$(uname)" == "Darwin" ] ; then
    mv $INSTALL_DIR/usr/local/lib/libdarm.so $INSTALL_DIR/usr/local/lib/libdarm.dylib
fi

cp *.h $INSTALL_DIR/usr/local/include
popd > /dev/null

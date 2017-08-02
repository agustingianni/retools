#!/usr/bin/env bash
set -o errexit
set -o nounset

UNAME=$(uname)
if [ "$UNAME" == "Linux" ] ; then
	echo "Building retools on Linux"
    source bootstrap_linux.sh
elif [ "$UNAME" == "Darwin" ] ; then
	echo "Building retools on macOS"
    source bootstrap_macos.sh
fi

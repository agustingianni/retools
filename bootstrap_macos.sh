#!/usr/bin/env bash
set -o errexit
set -o nounset

# Check that the user has 'brew' installed.
if ! type "brew" &> /dev/null; then
    echo "Brew is not installed. Please install and re run this script."
    exit 1
fi

# Install dependencies.
echo "Installing dependencies using brew"
brew install boost-python
#!/usr/bin/env bash
set -o errexit
set -o nounset

# Location of our sources.
export RETOOLS=$HOME/retools

# Samples collected for fuzzing.
export SAMPLES_DIR=$RETOOLS/tests/libbinary/macho/coverage

# Place all the moving parts inside a ramdisk.
export AFL_RAMDISK_DIR=$HOME/afl-ramdisk
export AFL_FINDINGS_DIR=$AFL_RAMDISK_DIR/afl_findings
export AFL_TESTCASES_DIR=$AFL_RAMDISK_DIR/afl_testcases
export AFL_BUILD_DIR=$AFL_RAMDISK_DIR/afl_build
export AFL_CRASHES_DIR=$AFL_RAMDISK_DIR/afl_findings/crashes

# Binary to be fuzzed.
export AFL_HARNESS=$AFL_BUILD_DIR/src/tools/harness_libbinary/harness_libbinary

# Create a fuzzing build inside a ramdisk.
mkdir $AFL_RAMDISK_DIR && chmod 777 $AFL_RAMDISK_DIR
sudo mount -t tmpfs -o size=1G tmpfs $AFL_RAMDISK_DIR

# Build.
mkdir $AFL_BUILD_DIR
pushd $AFL_BUILD_DIR
    CC=afl-gcc CXX=afl-g++ cmake -DBUILD_TYPE=FUZZING $RETOOLS
    AFL_ASAN=1 make
popd

# Copy only the files that optimize coverage.
afl-cmin -i $SAMPLES_DIR -o $AFL_TESTCASES_DIR -- $AFL_HARNESS @@
rm $SAMPLES_DIR/*
cp -r $AFL_TESTCASES_DIR $SAMPLES_DIR

# Run afl-fuzz.
sudo bash -c "echo core >/proc/sys/kernel/core_pattern"
afl-fuzz -i $AFL_TESTCASES_DIR -o $AFL_FINDINGS_DIR $AFL_HARNESS @@
afl-fuzz -M fuzzer00 -m 200 -i $AFL_TESTCASES_DIR -o $AFL_FINDINGS_DIR $AFL_HARNESS @@
afl-fuzz -S fuzzer01 -m 200 -i $AFL_TESTCASES_DIR -o $AFL_FINDINGS_DIR $AFL_HARNESS @@

###############################################################################
# Rename all files to its sha1 hash.
###############################################################################
for file in ./id*; do
    if [ -f "$file" ]
    then
        new_filename=$(openssl sha1 $file | awk '{print $2}')
        mv $file $new_filename
    fi
done

###############################################################################
# Iterate all crashes and remove the ones that do not actually crash.
###############################################################################
export TEST_BINARY=/Users/anon/workspace/retools/build/src/tools/binary_info/binary_info
for crash in id:*; do
    $TEST_BINARY $crash
    if [ $? -eq 0 ]
    then
        rm $crash
    fi
done

# Code coverage.
export TEST_BINARY=/Users/anon/workspace/retools/coverage_build/src/tools/binary_info/binary_info
for crash in coverage/*; do
    $TEST_BINARY $crash > /dev/null 2>&1
done

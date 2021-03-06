# retools: a reverse engineering toolkit for normies

Collection of tools (disassembler, emulator, binary parser) aimed at reverse enginering tasks, more specifically, bug finding related. Currently we target ARMv7 and Mach-O though in the future more architectures and formats are planned.

`retools` is somewhat unique in that most of the semantics for relevant instructions are parsed out of the specification PDFs as opposed to being generated by hand. Currently the disassembler, emulator, and binary parsers are partially done, with a symbolic execution engine and instrumentation/hooking framework to come as I get more time.

[![Build Status](https://travis-ci.org/agustingianni/retools.svg?branch=master)](https://travis-ci.org/agustingianni/retools)

# About the framework
`retools` has been designed to be modular, that is, we have divided each major subsystem in a separate library that can be used in most of the cases independently of other parts of the framework.

## libdisassembly
Multi architecture decoding/disassembling library. It supports, for now, the `ARMv7` (and below) architecture.
The decoding/disasembling procedures for the `ARMv7` architecture are generated automatically from the architecture manual.

## libemulation
Emulation library that allows its clients to emulate instructions. The emulation code has been automatically generated in the same fashion as `libdisassembly`.

## libbinary
Library that allows its clients to read/write/parse binary executables in a generic way that is independent of the underliying file format of the binary.
As of now we only support `mach-o` binaries, both `fat` and `slim` binaries.

### Example
In this example we will use the `binary_info` tool to inspect some generic details about a macho binary. `binary_info` is meant to be an example of how to use `libbinary`.

```
$ ./build/src/tools/binary_info/binary_info /bin/ps

Current binary:
  Linker: /usr/lib/dyld

  Version: 168.0.0.0.0

  UID: 55137f9f2fd933e6b9f39d4c7c65681c

  Entry points:
    entry: 0x51ac
    ...

  Libraries:
    lib: /usr/lib/libSystem.B.dylib

  Strings:
    val: no valid keywords; valid keywords:
    val:        ps [-L]
    ...

  Symbols:
    sym: __mh_execute_header @ 0x100000000
    ...
  Segment:
    address : 0x0
    size    : 0x100000000
    perm    : ---
  Segment:
    address : 0x100000000
    size    : 0x6000
    perm    : r-x
  Segment:
    address : 0x100006000
    size    : 0x3000
    perm    : rw-
  Segment:
    address : 0x100009000
    size    : 0x4000
    perm    : r--
```

## libsymbolic
The main idea of `libsymbolic` is to have an accurate and complete representation of the working architecture (say, ARM, x86, etc.) in a way that can be queried and used in the construction of reverse engineering tools.

As of now, `libsymbolic` is a *placeholder* for the automaticaly generated formal specification of the architecture.

## libinstrumentation
*Placeholder* for an instrumentation library.

# Installation
There are two recommended ways you can install this framework, we recommend using `vagrant` if you are just curious about testing the tools and having a look at the code. Otherwise compiling the code should not be difficult on a semi-modern linux system.

## Requirements

`retools` is supported and has been tested on `macOS` and `Linux`. A `Windows` build may be possible if you don't mind not building the `libdebug` part of the framework because as of now, it depends on `lldb` being present.

Software dependencies:

- `pyparsing`
- `capstone`
- `unicorn`
- `darm`
- `cmake`
- `Boost.Python`
- `lldb`

All the dependencies should be handled by the `bootstrap.sh` script.

### Vagrant
Use vagrant with the provided `Vagrant` file. It will automatically create an Ubuntu VM and will run `bootstrap.sh` to install all the required files for compilation. Once the VM is created, you will find `retools` code at `$HOME/retools`. Move to that directory and then follow the *compilation* instructions that follow.

### Compilation

```
# Clone the repository.
$ git clone https://github.com/agustingianni/retools.git

# Move to the cloned directory.
$ cd retools/

# Bootstrap installation (skip if using vagrant).
$ bash bootstrap.sh

# Compile sources.
$ mkdir build
$ cd build/
$ cmake ..
$ make -j8
```

# Documentation / Presentations
- ARM Disassembling with a twist / Ekoparty 2016 [PDF](https://drive.google.com/file/d/0B0l-Qo3D3sAoMEhkcFBFVzRiNEk/view)
- ARM Disassembling with a twist / Ekoparty 2016 [VID](https://vimeo.com/147629533)
- ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition
 [PDF](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0406c/index.html)

# Licensing
See [LICENSE](LICENSE)

# Contact
Feel free to contact via e-mail to agustin.gianni@gmail.com or twitter @agustingianni.
# retools: a reverse engineering toolkit for normies

Collection of tools aimed at reverse engineering tasks, more specifically, bug finding related.
Most of the tools are generated, or at at least partially generated, in an automatic way.

#### libdisassembly
Multi architecture decoding/disassembling library. It supports, for now, the `ARMv7` (and below) architecture.
The decoding/disasembling procedures for the `ARMv7` architecture are generated automatically from the architecture manual.

#### libemulation
Emulation library that allows its clients to emulate instructions. The emulation code has been automatically generated in the same fashion as `libdisassembly`.

#### libbinary
Library that allows its clients to read/write/parse binary executables in a generic way that is independent of the underliying file format of the binary.
As of now we only support `mach-o` binaries.

#### libsymbolic
The main idea of `libsymbolic` is to have an accurate and complete representation of the working architecture (say, ARM, x86, etc.) in a way that can be queried and used in the construction of reverse engineering tools.

As of now, `libsymbolic` is a *placeholder* for the automaticaly generated formal specification of the architecture.

#### libinstrumentation
*Placeholder* for an instrumentation library.

# Instalation
There are two recommended ways you can install this framework, we recommend using `vagrant` if you are just curious about testing the tools and having a look at the code. Otherwise compiling the code should not be difficult on a semi-modern linux system.

### Vagrant
Use vagrant with the provided `Vagrant` file. It will automatically create an Ubuntu VM and will run `bootstrap.sh` to install all the required files for compilation. Once the VM is created, you will find `retools` code at `$HOME/retools`. Move to that directory and then follow the *compilation* instructions that follow.

### Compilation

```
# Bootstrap installation (skip if using vagrant).
$ sudo bash bootstrap.sh

# Move to the cloned directory.
$ cd retools/

# Run code generators.
$ pushd src/libdisassembly/arm/scripts
$ python disgen.py --gen_decoder --gen_to_str
$ python emugen.py -g
$ popd

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
BSD License

# Contact
Feel free to contact via e-mail to agustin.gianni@gmail.com or twitter @agustingianni.
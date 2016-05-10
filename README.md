# OP-TEE Linux Driver - \*\*DEPRECATED\*\*

# 2016-04-17: Driver has been deprecated
Since the release of [OP-TEE 2.0.0](https://github.com/OP-TEE/optee_os/blob/master/CHANGELOG.md#op-tee---version-200),
we are no longer using this OP-TEE Linux kernel driver, but we
will keep it here for reference in case anyone needs it for one
or another reason. Also, this version of the OP-TEE driver is
not compatible with OP-TEE 2.0.0 and later. I.e, you cannot use
this with latest on the other OP-TEE gits like optee_os, optee_client,
optee_test etc.

The new driver we are using is located here:
[linaro-swg/linux/tree/optee](https://github.com/linaro-swg/linux/tree/optee).
Hopefully we will get this driver mainlined at some point in time,
but for the time being that will be our default OP-TEE driver for
OP-TEE >= v2.0.0.

Besides that we have also backported the 2.0.0 driver to [LSK 3.18](https://git.linaro.org/kernel/linux-linaro-stable.git/shortlog/refs/heads/v3.18/topic/optee)
and [LSK 4.4](https://git.linaro.org/kernel/linux-linaro-stable.git/shortlog/refs/heads/v4.4/topic/optee)
for those that would like to use an older kernel.

Another important patch that has been mainlined and is needed on older kernels
is the ARM SMCCC patch that could be found here: [14457459f9ca2ff8521686168ea179edc3a56a44] (https://github.com/torvalds/linux/commit/14457459f9ca2ff8521686168ea179edc3a56a44)

# Description
The optee_linuxdriver git, containing the source code for the TEE driver 
module in Linux.
It is distributed under the GPLv2 open-source license. For a general
overview of OP-TEE, please see the [Notice.md](Notice.md) file.

In this git, the module to build is optee.ko.
It allows communication between the Rich OS Client Application (unsecure
world), the Trusted OS (secure world) and the tee-supplicant (unsecure
world) which is a daemon serving the Trusted OS in secure world with
miscellaneous features, such as file system access.

## License
The software is provided under the
[GPL-2.0](http://opensource.org/licenses/GPL-2.0) license.

## Platforms supported
This software has hardware dependencies.
The software has been tested using:

- STMicroelectronics b2020-h416 (orly-2) hardware (32-bits)
- Some initial testing has been done using
[Foundation FVP](http://www.arm.com/fvp), which can be downloaded free of
charge.

## Get and build the software
### Get the compiler
We will strive to use the latest available compiler from Linaro. Start by
downloading and unpacking the compiler. Then export the PATH to the bin folder.

	$ cd $HOME
	$ mkdir toolchains
	$ cd toolchains
	$ wget http://releases.linaro.org/14.05/components/toolchain/binaries/gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux.tar.xz
	$ tar xvf gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux.tar.xz
	$ export PATH=$HOME/toolchains/gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux/bin:$PATH

### Get the Linux kernel (from www.kernel.org)
	$ cd $HOME
	$ mkdir devel
	$ cd devel
	$ tar xf linux-3.10.32.tar.xz
	$ mv linux-3.10.32 linux

### Download the source code
	$ cd $HOME
	$ cd devel
	$ git clone https://github.com/OP-TEE/optee_linuxdriver.git

### Build
	$ cd $HOME/devel/linux
	$ make -j3 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- mrproper
	$ make -j3 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- defconfig
	$ make -j3 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- all
	$ make -j3 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- M=$HOME/devel/optee_linuxdriver modules

#### Compiler flags
To be able to see the full command when building you could build using following
flag:

`$ make V=1`

## Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/CodingStyle)). We achieve this by running
[checkpatch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl) from Linux kernel.
However there are a few exceptions that we had to make since the code also
follows GlobalPlatform standards. The exceptions are as follows:

- CamelCase for GlobalPlatform types are allowed.
- And we also exclude checking third party code that we might use in this
  project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
  those are also part of the complete TEE solution). The reason for excluding
  and not fixing third party code is because we would probably deviate too much
  from upstream and therefore it would be hard to rebase against those projects
  later on (and we don't expect that it is easy to convince other software
  projects to change coding style).

### checkpatch
Since checkpatch is licensed under the terms of GNU GPL License Version 2, we
cannot include this script directly into this project. Therefore we have
written the Makefile so you need to explicitly point to the script by exporting
an environment variable, namely CHECKPATCH. So, suppose that the source code for
the Linux kernel is at `$HOME/devel/linux`, then you have to export like follows:

	$ export CHECKPATCH=$HOME/devel/linux/scripts/checkpatch.pl
thereafter it should be possible to use one of the different checkpatch targets
in the [Makefile](Makefile). There are targets for checking all files, checking
against latest commit, against a certain base-commit etc. For the details, read
the [Makefile](Makefile).

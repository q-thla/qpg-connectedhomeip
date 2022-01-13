# QPG6105 SDK for Matter

Using [Matter](https://github.com/project-chip/connectedhomeip) on the Qorvo QPG6105.

---

- [QPG6105 SDK for Matter](#qpg6105-sdk-for-matter)
  - [Introduction](#introduction)
  - [Building](#building)
    - [Preparation](#preparation)
    - [Compilation](#compilation)
  - [Programming the QPG6105](#programming-the-qpg6105)
  - [Viewing Logging Output](#viewing-logging-output)

---

## Introduction

![QPG6105 DK board](../../qpg6105/doc/qpg6105.png)

Several example applications are provided to to demonstrate a Matter
device with Thread connectivity, using Bluetooth Low Energy to perform Matter
provisioning on the Qorvo QPG6105 SDK. More information about each application
can be found in the `APPLICATION.md` file found in the `example/<app>` directories.

Currently supported example applications

- [lighting-app](../../examples/lighting-app/APPLICATION.md)
- [lock-app](../../examples/lock-app/APPLICATION.md)

## Building

### Preparation

Download and install a suitable ARM gcc tool chain:
[GNU Arm Embedded Toolchain 9-2019-q4-update](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads)
(Direct download link:
[Linux](https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/9-2019q4/gcc-arm-none-eabi-9-2019-q4-major-x86_64-linux.tar.bz2) |
[Mac OS X](https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/9-2019q4/gcc-arm-none-eabi-9-2019-q4-major-mac.tar.bz2))
we will assume the installation ends up in `~/tools/gcc-arm-none-eabi-9-2019-q4-major`

Install additional tools used by the Matter build:

On Linux

    sudo apt-get install git make libtool ccache ninja-build

On Mac OS X

    brew install libtool ccache ninja

Below we assume we work from `${HOME}`

Clone the [Matter](https://github.com/project-chip/connectedhomeip) repo into a local directory

    cd ~
    git clone https://github.com/project-chip/connectedhomeip.git
    cd connectedhomeip
    git submodule update --init --recursive

The submodule command will add the [Qorvo Matter SDK](https://github.com/Qorvo/qpg-connectedhomeip) as submodule to the Matter repository.

Alternatively the SDK can be cloned separately

    cd ~
    git clone https://github.com/Qorvo/qpg-connectedhomeip

and can be used in the Matter repository (instead of the pre-package submodule) by passing `qpg_sdk_root` when running gn:

    gn gen --args="qpg_sdk_root=\"~/qpg-connectedhomeip\""

### Compilation

Set the following environment variables before compilation:

    export ARM_GCC_INSTALL_ROOT=~/tools/gcc-arm-none-eabi-9-2019-q4-major/bin
    export PATH=$PATH:$ARM_GCC_INSTALL_ROOT

All builds are GN/ninja based

    cd ~/connectedhomeip/examples/<app>/qpg
    source third_party/connectedhomeip/scripts/activate.sh
    gn gen out/debug
    ninja -C out/debug

This will result in `.hex` in `out/debug`

## Programming the QPG6105

When inserting the USB cable into your build machine a *DAPLINK* should appear.
Drag and drop the `.hex` output file to the *DAPLINK* drive and wait \~30sec.
The QPG6105 will reprogram itself, unmount and remount itself on your host.
If the programming succeeded, there should be no `FAIL.txt` file on the remounted drive.

Alternative ways, such as using a J-Link to program the QPG6105 are outlined in the documentation package that comes with the QPG6105 Development Kit.

## Viewing Logging Output

The device can be reached over a serial connection (`COMx` on Windows, `/dev/ttyACMx` on Unix) with the following parameters:

> - Speed: 115200
> - Data bits: 8
> - Stop bits: 1
> - Parity: None
> - Flow control: XON/XOFF

At startup you will see

    qvCHIP v0.0.0.0 (CL:155586) running
    [P][-] Init CHIP Stack
    [P][DL] BLEManagerImpl::Init() complete
    [P][-] Starting Platform Manager Event Loop
    [P][-] ==================================
    [P][-] Qorvo [Application Name] Launching
    [P][-] ==================================
    [D][DL] Matter task running

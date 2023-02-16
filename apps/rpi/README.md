<!--
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
-->
# SEDIMENT App on Raspberry Pi Zero W / Linux
This directory contains the SEDIMENT app that is to run on a Ubuntu PC or a Raspberry Pi Zero W. 

## Contents
- [SEDIMENT App on Raspberry Pi Zero W / Linux](#sediment-app-on-raspberry-pi-zero-w--linux)
  - [Contents](#contents)
  - [Dependencies](#dependencies)
  - [Build](#build)
  - [Run](#run)

## Dependencies
See [Third Party Libaries](../../servers/README.md) for third party libraries that are needed to build the app.

## Build
To build SDEIMENT, do the following.

        $ cd $SEDIMENT/apps/rpi
        $ mkdir build
        $ cd build
        $ cmake ..
        $ make

## Run
After successfully built, the app can be started using the following command.

        $ $SEDIMENT/app/rpi/build/sediment

By default, the app is configured to use the config file for device Ubuntu-001 in $SEDIMENT/configs/boards/Ubuntu-001. To change the settings, you can edit and save the file and rerun the app. Alternatively, you can make a copy of the file and make the change in that file. In that case, the command line option -p is necessary for the settings to take effect. For example, if the new settings are in a file named /tmp/new-RPI, use the following command line.

        $ $SEDIMENT/app/rpi/build/sediment -p /tmp/new-RPI

```
$ ./sediment -h
./sediment
  -p/--wdkibe-pub-key <publisher key file>
	Read WKD-IBE publisher key material file. Used only by publishers.
  -h/--help
	This help.
```

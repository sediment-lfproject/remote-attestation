<!--
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
-->
# SEDIMENT on Zephyr-based Devices
This directory contains SEDIMENT on devices implemented on top of Zephyr, which currently includes Silicon Labs Giant Gecko.

## Contents
- [SEDIMENT on Zephyr-based Devices](#sediment-on-zephyr-based-devices)
  - [Contents](#contents)
  - [Prerequisite](#prerequisite)
  - [SEDIMENT Customizations](#sediment-customizations)
  - [Build](#build)
  - [Flashing](#flashing)
  - [Configurations](#configurations)
  - [Monitoring Output](#monitoring-output)
  - [Test](#test)

## Prerequisite
Follow the instructions at [Zephyr](<https://docs.zephyrproject.org/latest/getting_started/index.html>) to set up both Zephyr and its SDK.
The following description refers to zephyrproject/zephyr as $ZEPHYR and the sediment installation directory as $SEDIMENT. 

## SEDIMENT Customizations
Create in zephyr a symbolic link to the root of the sediment repository.

        $ cd $ZEPHYR
        $ ln -s $SEDIMENT .

## Build
To build a SEDIMENT app, do the following.

Change directory to zephyr

        $ cd $ZEPHYR

Set board environment variable, efm32gg_stk3701a for Giant Gecko.

        $ export BOARD=efm32gg_stk3701a

Use the following command to build sediment for Giant Gecko. The --pristine argument can be omitted for subsequent build for the same board and app. If successful, the image will be left in build/zephyr/zephyr.hex or zephyr.bin.

        $ west build sediment/apps/giant --pristine
        
If the BOARD environment variable is not set, add `-b <BOARD>` to the command

        $ west build -b efm32gg_stk3701a sediment/apps/giant --pristine
        
The build will fail because of configuration errors. Copy the correct configurations as follows (replace giant with stm for STM32F767ZI).

        $ cp $SEDIMENT/apps/giant/doc/dot.config build/zephyr/.config

Rebuild without the --pristine option

        $ west build -b efm32gg_stk3701a sediment/apps/giant

## Flashing
To install SEDIMENT on a device, do the following.

1.  Change directory to zephyr

        $ cd $ZEPHYR
        
2. Connect the Giant Gecko to the host computer using USB and run the command below

        $ west flash

Once the flashing is completed, the device will reset and start running. Note that, for Giant Gecko, SEGGER J-Link needs to be installed on the host. If not, download it from [J-Link](https://www.segger.com/downloads/jlink/) and follow the [instructions](https://eclipse-embed-cdt.github.io/debug/jlink/install/) to install. 


## Configurations
As initially built, default board ID, server IP addresses and ports and other settings are included. To provision a device, prepare a configuration file, based on the sample, e.g., in $SEDIMENT/configs/boards/gg-01. Changes the options (IP address, in particular) appropriately.

Connect the board to the host PC.

Open a serial terminal app, e.g. minicom or gtkterm, and connect to the detected deivce, e.g. at /dev/ttyACM0

        $ minicom -D /dev/ttyACM0 

In a separate terminal, run the provisioning script and give the configuration file as an argument as follows.

        $ python $SEDIMENT/utils/provision.py provision $SEDIMENT/configs/boards/gg-01 

This will write, via UART, the configurations into the board's non-volatile memory, from which sediments loads the power-on settings. These settings remain on the boards even after the sediment app is updated or the device is power-cycled. 

## Monitoring Output
Use a serial terminal, e.g. minicom on Linux or putty on Windows, to monitor the messages with the following settings:

        Speed: 115200
        Data: 8 bits
        Parity: None
        Stop bits: 1

On Linux, do the following, assuming the deivce is detected at /dev/ttyACM0.

        $ minicom -D /dev/ttyACM0 

## Test
Review [Test Configuration](../../servers/README.md) to see how to set up the servers and test it together with the device.

<!--
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
-->
# SEDIMENT Servers
This directory contains SEDIMENT servers for Remote Attestation, including a remote attestation server and a firewall to serve as the initial contact point for an IoT device running SEDIMENT (also known as prover). The guide below assumes the servers are being installed on Ubuntu 20.04. Other Linux distributions are expected to have no issues, but have not been tested.

## Contents
- [SEDIMENT Servers](#sediment-servers)
  - [Contents](#contents)
  - [Install Third Party Libraries](#install-third-party-libraries)
  - [Build](#build)
  - [Configuring the Servers](#configuring-the-servers)
  - [Running the Servers](#running-the-servers)
    - [Remote Attestation Server (Verifier)](#remote-attestation-server-verifier)
    - [Firewall](#firewall)
  - [Running On an Ubuntu PC](#running-on-an-ubuntu-pc)
    - [Using A Raspberry Pi Zero W](#using-a-raspberry-pi-zero-w)
    - [Using A Zephyr Device](#using-a-zephyr-device)

## Install Third Party Libraries
A few 3rd party libraries are required for the remote attestation server and the firewall. Run the following command to install the dependent libraries on Ubuntu.

        $ $SEDIMENT/utils/install-libraries.sh

Note that mbedtls 3.1.0 and mqtt C and C++ libraries need to be installed separately.        
Please download and install mbedtls version 3.1.0 from https://github.com/Mbed-TLS/mbedtls.
The latest version may also work, but 3.1.0 is the version tested.
Please also download and install mqtt C++ and C libraries from https://github.com/eclipse/paho.mqtt.cpp and
https://github.com/eclipse/paho.mqtt.c, respectively.

## Build
- Build the remote attestation server as follows.

        $ cd $SEDIMENT/servers/verifier
        $ mkdir build; cd build
        $ cmake ..; make

- Build the firewall as follows.

        $ cd $SEDIMENT/servers/firewall
        $ mkdir build; cd build
        $ cmake ..; make

## Configuring the Servers
By default, the servers are configured using configs/boards/+, which contains settings such as IP address and port, and key materials. 
To change the settings, you can edit and save configs/boards/+ and rerun the corresponding servers. 
The servers are usually run as subscribers. So to use a different config file, use the command line option -s. For example, if the firewall is to use a config file named fw.cfg, do the following,

        $ $SEDIMENT/servers/firewall/build/firewall -s fw.cfg

## Running the Servers
### Remote Attestation Server (Verifier)

        $ cd $SEDIMENT/servers/verifier
        $ ./verifier

You will see output similar to the following.
```
key_dist: JEDI
report_interval: 5
key_change_interval: 30
enc_enabled: true
auth_enabled: true
attest_enabled: true
passport_period: 86400
pass_thru_enabled: true
payload_size: 48
log_level: 8
Component: id: RAP_Server
	incoming: TCP:127.0.0.1:8100
	outgoing: TCP:127.0.0.1:8000
	outgoing2: TCP:127.0.0.1:8101
	aService: TCP:127.0.0.1:8102
```
Incoming is the endpoint where the verifier listens for attestation requests from provers. Outgoing is the endpoint to which attestation alerts are sent (usually to the relying party, or firewall in this case). Verifier also sends attestation results to GUI which listens at the Outgoing2 endpoint and listens for requests from the GUI at the aService endpoint. Note that GUI is not included in the current release. Error messages about failing to connect to the corresponding address will appear in the logs.

### Firewall

        $ cd $SEDIMENT/servers/firewall
        $ ./firewall

You will see output similar to the following.        
```
key_dist: JEDI
report_interval: 5
key_change_interval: 30
enc_enabled: true
auth_enabled: true
attest_enabled: true
passport_period: 86400
pass_thru_enabled: true
payload_size: 48
log_level: 8
Component: id: RA_Manager
	incoming: TCP:127.0.0.1:8000
	outgoing: TCP:127.0.0.1:8001
	outgoing2: 
	aService: 
```
Incoming is the endpoint where the firewall listens for remote attestation requests from IoT devices (provers), while outgoing is the endpoint to which relevant data are forwarded. Note that data forwarding is included in the current release. Error messages about failing to connect to the corresponding address will appear in the logs.

## Running On an Ubuntu PC
To run remote attestation on an Ubuntu 20.04 PC, execute the following commands, each in a separate terminal window.
```
        $ $SEDIMENT/servers/firewall/build/firewall
        $ $SEDIMENT/servers/attestation/build/verifier
        $ $SEDIMENT/apps/rpi/build/sediment
```

The commands assume the servers and device have been built in their respective build/ directory. See [SEDIMENT App on Linux](../apps/rpi/README.md) on how to build a device on Linux.
After the device connects to the servers, there should be messages in the terminal windows, showing messages being exchanged among the servers and the device. 

If a remote attestation fails because of invalid firmware HMAC checksum in the verifier, the firmware record on the server needs to be corrected. Copy the new firmware to the server directory as follows.

```
        $ cp $SEDIMENT/apps/rpi/build/sediment $SEDIMENT/data/testfiles/ubuntu
```
Then update the (default) database $SEDIMENT/data/sediment.db and change the firmware and size columns of the row corresponding to the device. Restart both the verifier and the device. If remote attestation is successful, one should see a log message containing "all evidence verified for device Ubuntu-001" in the verifier terminal. Note that one of the evidence types attested is the OS Version, which is "Ubuntu 20.04.3 LTS" in the database. If you are running on a different version, please update the osVersion column of the database accordingly.

### Using A Raspberry Pi Zero W
Prepare RPi0 as follows.

- Build the executable as described in [SEDIMENT App on RPi0](../apps/rpi/README.md). Assume the executable is located in $SEDIMENT/apps/rpi/build/sediment.
- Copy the executable from RPi0 to the verifier database on the Ubuntu PC (hostname is ubuntu below)
```
    # scp $SEDIMENT/apps/rpi/build/sediment ubuntu:$SEDIMENT/data/testfiles/rpi
```
- On the server PC, update the (default) database $SEDIMENT/data/sediment.db and change the firmware and size columns of the row corresponding to the device .

- On the RPi, edit the config file $SEDIMENT/configs/boards/RPI-001 and change the address field to match the address of the firewall.

On PC
```
        $ $SEDIMENT/servers/firewall/build/firewall
        $ $SEDIMENT/servers/attestation/build/verifier
```

On RPi
```
        $ $SEDIMENT/apps/rpi/build/sediment -p $SEDIMENT/configs/boards/RPI-001
```

### Using A Zephyr Device
Prepare a zephyr device as follows.

- Build and download the firmware and configurations as described in [SEDIMENT App on Zephyr](../apps/zephyr/README.md). 

- Copy the firmware to the Attestastion Server database. For example, 

        $ cp $ZEPHYR/build/zephyr/zephyr.bin $SEDIMENT/data/testfiles/zephyr-GG.bin

- On the server PC, update the (default) database $SEDIMENT/data/sediment.db and change the firmware and size columns of the row corresponding to the device.

On PC
```
        $ $SEDIMENT/servers/firewall/build/firewall
        $ $SEDIMENT/servers/attestation/build/verifier
```
Power on the Giant Gecko.

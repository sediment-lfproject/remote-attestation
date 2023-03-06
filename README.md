<!--
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
-->
# The SEDIMENT Project

Copyright (c) 2023 Peraton Labs

Distribution A: Approved for public release; distribution unlimited. 

This material is based upon work supported by the DARPA OPS-5G program under
contract number HR001120C0156. Any opinions, findings, conclusions, or
recommendations expressed here are those of the authors and do not necessarily
reflect the views of DARPA.

This repository hosts references to SEDIMENT components and scripts to
build SEDIMENT or individual components from source. All files are released 
under the [Apache 2.0](LICENSE) license unless specifically noted otherwise.

SEDIMENTS components include an application server to receive IoT data 
(temperature and humidity sensor readings), a remote attestation server, 
a firewall to serve as the initial contact point for an IoT device running 
SEDIMENT (also known as prover). The guide below assumes the servers are being 
installed on Ubuntu 20.04. Other Linux distributions are expected to 
have no issues, but have not been tested.

- [The SEDIMENT Project](#the-sediment-project)
  - [Install Third Party Libraries](#install-third-party-libraries)
  - [Build](#build)
  - [Configuring the Servers](#configuring-the-servers)
  - [Running the Servers](#running-the-servers)
    - [Remote Attestation Server (Verifier)](#remote-attestation-server-verifier)
    - [Firewall](#firewall)
  - [Test Configuration on Linux](#test-configuration-on-linux)
    - [Using A Raspberry Pi Zero W](#using-a-raspberry-pi-zero-w)
    - [Using A Zephyr Device](#using-a-zephyr-device)

## Install Third Party Libraries
A few 3rd party libraries are required for the remote attestation server and the firewall. 
Run the following command to install the dependent libraries on Ubuntu.

        $ $SEDIMENT/utils/install-libraries.sh

Note that mbedtls 3.1.0 and mqtt C and C++ libraries need to be installed separately.        
Please download and install mbedtls version 3.1.0 from https://github.com/Mbed-TLS/mbedtls.
The latest version may also work, but 3.1.0 is the version tested.
Please also download and install mqtt C++ and C libraries from 
https://github.com/eclipse/paho.mqtt.cpp and
https://github.com/eclipse/paho.mqtt.c, respectively.

## Build
- Build the SEDIMENT executables as follows

        $ cd $SEDIMENT
        $ mkdir build; cd build
        $ cmake ..; make

## Configuring the Servers
By default, the servers are configured using configs/boards/+, 
which contains settings such as IP address and port, and key materials. 
For devices running Zephyr, see [Devices](../apps/zephyr/README.md) 
for flashing configurations to the devices. 

To change the settings, you can edit and save configs/boards/+ 
and rerun the corresponding servers. 
The servers are usually run as subscribers. So to use a different config file, 
use the command line option -s. 
For example, if the firewall is to use a config file named fw.cfg, do the following,

        $ $SEDIMENT/build/firewall -s fw.cfg

## Running the Servers
### Remote Attestation Server (Verifier)

        $ cd $SEDIMENT/build
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
Incoming is the endpoint where the verifier listens for attestation requests from provers. 
Outgoing is the endpoint to which attestation alerts are sent (usually to the relying party). 
Verifier also sends attestation results to GUI which listens at the Outgoing2 endpoint and 
listens for requests from the GUI at the aService endpoint. 

### Firewall

        $ cd $SEDIMENT/build
        $ ./firewall

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
Incoming is the endpoint where the application server listens for encrypted sensor data, 
while outgoing is the endpoint to which the data are forwarded. 

## Test Configuration on Linux
The following is a diagram showing the minimum test configuration where the firewall, 
the application server, the verifier (remote attestation server), 
their GUI's and the device (a virutal one) are all running on the same Ubuntu PC. 

![TestConfig](doc/arch-min.png "Architecture")

To run SEDIMENT on an Ubuntu PC, execute the following commands, each in a separate terminal window.
```
        $ $SEDIMENT/build/firewall
        $ $SEDIMENT/build/verifier
        $ $SEDIMENT/build/prover
```
After the device connects to the servers, there should be messages in the terminals, 
showing messages being exchanged among the servers and the device. 
Sensor data (simulated) from the device should appear on the app server GUI 
and its attestation status and history should show up on the attestation server GUI.

If a remote attestation fails because of invalid firmware HMAC checksum in the verifier, 
the firmware record on the server needs to be corrected. 
Copy the new firmware to the server directory as follows.

```
        $ cp $SEDIMENT/build/prover $SEDIMENT/data/testfiles/ubuntu
```
Then update the (default) database $SEDIMENT/data/sediment.db to change 
the firmware and size columns of the row corresponding to the device. 
Restart both the verifier and the device. If remote attestation is successful, 
one should see a log message containing "all evidence verified for device Ubuntu-001"
in the verifier terminal. Note that one of the evidence types attested is the OS Version, 
which is "Ubuntu 20.04.3 LTS" in the database. If you are running on a different version, 
please update the osVersion column of the database accordingly.

### Using A Raspberry Pi Zero W
Prepare RPi0 as follows.

- Build the executable as described in [SEDIMENT App on RPi0](../apps/rpi/README.md).
- Copy the executable from RPi0 to the Ubuntu PC (hostname is ubuntu below)
```
    # scp $SEDIMENT/build/prover ubuntu:$SEDIMENT/data/testfiles/rpi
```
- On the server PC, update the (default) database $SEDIMENT/data/sediment.db 
  and change the firmware and size columns of the row corresponding to the device, e.g. RPI-001.

- On the RPi, edit the config file, e.g. $SEDIMENT/configs/boards/RPI-001 and 
  change the relyingPartyEndpoint column to match the IP address of the PC.

On PC, run the following, each in a separate terminal
```
        $ $SEDIMENT/build/firewall
        $ $SEDIMENT/build/verifier
```

On RPi
```
        $ $SEDIMENT/build/prover -p $SEDIMENT/configs/boards/RPI-001
```

### Using A Zephyr Device
Prepare a zephyr device as follows.

- Build and download the firmware and configurations as described in 
  [SEDIMENT App on Zephyr](../apps/zephyr/README.md). 

- Copy the firmware to make it visible to the verifier. For example, 

        $ cp $ZEPHYR/build/zephyr/zephyr.bin $SEDIMENT/data/testfiles/zephyr-GG.bin

- On the server PC, update the (default) database $SEDIMENT/data/sediment.db 
  and change the firmware and size columns of the row corresponding to the device, e.g. Giant_Gecko-001.

On PC
```
        $ $SEDIMENT/build/firewall
        $ $SEDIMENT/build/verifier
```
Power on the Giant Gecko.

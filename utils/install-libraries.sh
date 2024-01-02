#! /bin/bash
# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

echo "Enter SEDIMENT installation directory (press Enter for default: ~/sediment): "  
read SEDIMENT
if [ -z $SEDIMENT ]; then
    SEDIMENT=$HOME/sediment
fi    
echo "SEDIMENT is installed at $SEDIMENT"  

#SEDIMENT=$(eval echo $sdm)

sudo apt-get update
sudo apt-get install -y libzmq3-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y libgsl-deva
sudo apt-get install -y python3-pip
sudo apt-get install -y python3.8-venv
sudo apt-get install -y clang-9
sudo apt-get install -y clang++-9
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y mosquitto
sudo apt-get install -y sqlite3
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y libmysqlcppconn-dev

echo "Please download and install mbedtls version 3.1.0 from https://github.com/Mbed-TLS/mbedtls."
echo "The latest version may also work, but 3.1.0 is the version tested."
echo "Please also download and install mqtt C++ and C libraries from https://github.com/eclipse/paho.mqtt.cpp and"
echo "https://github.com/eclipse/paho.mqtt.c, respectively."

pushd /usr/bin
sudo ln -s clang-9 clang
sudo ln -s clang++-9 clang++
popd

sudo apt-get install -y libboost-all-dev
sudo snap install cmake --classic

cd $SEDIMENT
pwd

cd $SEDIMENT/servers/gui
python3 -m venv venv
source venv/bin/activate
python3 -m pip install dash==1.13.3 pandas==1.0.5
pip install pyzmq


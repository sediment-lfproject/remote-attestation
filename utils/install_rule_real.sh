#/bin/bash
# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

if [ "$#" -ne 3 ]; then
    sc=`basename "$0"`
    echo "$sc <device-ID> <ip> <action>"
    exit
fi

DEV=$1
IP=$2
REASON=$3

# clear all old rules
iptables-save | grep $IP |
    while read -r line
    do
        line=$(echo $line | sed -r 's/-A/-D/g')
        iptables $line
        echo $line
    done

# install a new rule

if [ ! "$REASON" = "PASS" ]; then
    iptables -A INPUT -p udp -s $IP --destination-port 5060 -j DROP
fi

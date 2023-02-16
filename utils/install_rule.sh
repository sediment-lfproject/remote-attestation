#/bin/bash
# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0

path=$(dirname "$0")

# acquire the lock first because multiple threads may be active in firewall
#flock -x /tmp/sediment_lock $path/install_rule_real.sh $1 $2 $3
flock -x /tmp/sediment_lock ssh 127.0.0.1 ~/install_rule_real.sh $1 $2 $3

# the following form leads to syntax error when invoked from sediment
# so put REAL script in another file
#(
#    flock -x -w 10 200 
#    REAL    
#) 200>/tmp/sediment_lock

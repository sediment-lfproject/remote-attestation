#!/bin/bash
# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
#

usage_exit() {
  [[ -n "$1" ]] && echo $1
  echo "Usage: $0 [ -kchr ] "
  echo "-c  Clean up"
  echo "-d  Do not build and include SEEC; applies to PROVER only"
  echo "-n  Do not compile RPI"
  echo "-h  Help"
  exit 1
}

handle_opts() {
  local OPTIND
  while getopts "chnd" options; do
    case "${options}" in
      c) CLEAN=1  ;;
      d) DISABLE_SEEC="-DSEEC_ENABLED=OFF"  ;;
      n) NOT_RPI=1  ;;
      h) usage_exit          ;;
      :) usage_exit "Error: -${OPTARG} requires an argument." ;;
      *) usage_exit "" ;;
    esac
  done

  shift $((OPTIND -1))
}

if [ -z "$SEDIMENT" ]; then
    if [ -d ~/sediment ]; then
        SEDIMENT=~/sediment
        echo "Environment variable SEDIMENT not set; set to ~/sediment"
    else
        echo "Please set the environment variable SEDIMENT to the sediment root directory, e.g. ~/sediment"
        exit
    fi
fi

args=("$@")
handle_opts "$@"

cd $SEDIMENT

if [ -z "$CLEAN" ]; then
    cd build; make
else
    rm -rf build
    mkdir build
    cd build
    cmake .. $DISABLE_SEEC
    make
fi

#!/bin/bash
# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
#
# Setup a work space called `work` with two windows
# first window has 3 panes.
# The first pane set at 65%, split horizontally, set to api root and running vim
# pane 2 is split at 25% and running redis-server
# pane 3 is set to api root and bash prompt.
# note: `api` aliased to `cd ~/path/to/work`
#
session="run"

usage_exit() {
  [[ -n "$1" ]] && echo $1
  echo "Usage: $0 [ -kch ] "
  echo "-f  <config file>"
  echo "-v  Run valgrind"
  echo "-l  <log file>"
  echo "-n  Do not run RPI"
  echo "-p  <prover: [none | rpi | gecko]>"
  echo "-z  Run minicom"
  echo "-h  Help"
  exit 1
}

handle_opts() {
  local OPTIND
  while getopts "f:p:lhnvz" options; do
    case "${options}" in
      n) PROVER=none           ;;
      p) PROVER=${OPTARG}      ;;
      v) VALGRIND=valcheck.sh  ;;
      h) usage_exit            ;;
      l) LOGGING=log           ;;
      f) ARG_CONFIG="-f ${OPTARG}"          ;;
      :) usage_exit "Error: -${OPTARG} requires an argument." ;;
      *) usage_exit "" ;;
    esac
  done

  shift $((OPTIND -1))
}

if [ -z "$SEDIMENT" ]; then
    echo "Please set the environment variable SEDIMENT to the sediment root directory, e.g. ~/sediment"
    exit
fi

args=("$@")
handle_opts "$@"

if [ ! -z "$LOGGING" ]; then
    LOG_VERIFIER="| tee verifier.log"
    LOG_FIREWALL="| tee firewall.log"
    LOG_APP_SERVER="| tee app_server.log"
    LOG_PROVER="| tee prover.log"
fi

cd $SEDIMENT/build

# set up tmux
tmux start-server

# create a new tmux session, starting vim from a saved session in the new window
tmux new-session -d -s $session -n verifier #"vim -S ~/.vim/sessions/kittybusiness"

# Select pane 1, set dir to api, run verifier
#tmux selectp -t 1
tmux send-keys "$VALGRIND ./verifier $ARG_CONFIG $LOG_VERIFIER" C-m

# Split pane 1 horizontal by 65%, start app_server
tmux splitw -h -p 50
#tmux send-keys "$VALGRIND ./app_server $ARG_CONFIG $LOG_APP_SERVER" C-m

# Select pane 2
#tmux selectp -t 2
# Split pane 2 vertiacally by 25%
#tmux splitw -v -p 50

# select pane 3, set to firewall
#tmux selectp -t 3
tmux send-keys "$VALGRIND ./firewall $ARG_CONFIG $LOG_FIREWALL" C-m

if [[ -z "$PROVER" || "$PROVER" == "rpi" ]]; then
    tmux selectp -t 0
    tmux splitw -v -p 50
    tmux send-keys "$VALGRIND ./sediment $ARG_CONFIG $LOG_PROVER" C-m
else
    case "${PROVER}" in
       none)
            ;;
      gecko)
            tmux selectp -t 0
            tmux splitw -v -p 50
            tmux send-keys "minicom -D /dev/ttyACM0 -C prover.log" C-m
            ;;
      *) echo "unsupported device"
         exit                      ;;
    esac
fi

# create a new window called scratch
#tmux new-window -t $session:1 -n scratch

# return to main vim window
tmux select-window -t $session:0

# Finished setup, attach to the tmux session!
tmux attach-session -t $session

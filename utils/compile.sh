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
session="cmp"

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
      d) DISABLE_SEEC=1  ;;
      n) NOT_RPI=1  ;;
      h) usage_exit          ;;
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

if [ -z "$CLEAN" ]; then
    CMD="cd build; make"
else
    CMD="rm -rf build; mkdir build; cd build; cmake ..; make"
    NO_SEEC_CMD="rm -rf build; mkdir build; cd build; cmake .. -DSEEC_ENABLED=OFF; make"
fi

VERIFIER_CMD=$CMD
FIREWALL_CMD=$CMD
APP_SERVER_CMD=$CMD
    
if [ -z "$DISABLE_SEEC" ]; then
    PROVER_CMD=$CMD
else
    PROVER_CMD=$NO_SEEC_CMD
fi

# set up tmux
tmux start-server

# create a new tmux session, starting vim from a saved session in the new window
tmux new-session -d -s $session -n verifier #"vim -S ~/.vim/sessions/kittybusiness"

# Select pane 1, set dir to api, run verifier
#tmux selectp -t 1
tmux send-keys "cd $SEDIMENT/servers/verifier/; $VERIFIER_CMD" C-m

# Split pane 1 horizontal by 65%, start app_server
tmux splitw -h -p 50
#tmux send-keys "cd $SEDIMENT/servers/application/; $APP_SERVER_CMD" C-m

# Select pane 2
#tmux selectp -t 2
# Split pane 2 vertiacally by 25%
#tmux splitw -v -p 50

# select pane 3, set to firewall
#tmux selectp -t 3
tmux send-keys "cd $SEDIMENT/servers/firewall/; $FIREWALL_CMD" C-m

if [ -z "$NOT_RPI" ]; then
    # Select pane 1
    tmux selectp -t 0
    tmux splitw -v -p 50
    tmux send-keys "cd $SEDIMENT/apps/rpi/; $PROVER_CMD" C-m
fi

# create a new window called scratch
#tmux new-window -t $session:1 -n scratch

# return to main vim window
tmux select-window -t $session:0

# Finished setup, attach to the tmux session!
tmux attach-session -t $session

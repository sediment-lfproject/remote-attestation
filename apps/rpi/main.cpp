/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>
#include <sstream>
#include <thread>

#include "nv.h"

#include "Prover.hpp"
#include "Config.hpp"
#include "BoardRPI.hpp"
#include "ProverCL.hpp"
#include "Enum.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    ProverCL cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_PROVER);
    config.parseFile(cli.getConfig());

    BoardRPI *board = new BoardRPI(argv[0]);
    board->setConfigFile(cli.getConfig());
    
    Prover prover(config, board);
    prover.setSedimentHome(cli.getSedimentHome());
    board->saveReportInterval(config.getReportInterval());

    if (config.getTransport() == TRANSPORT_MQTT)
        prover.runMqtt();
    else
        prover.run();
}

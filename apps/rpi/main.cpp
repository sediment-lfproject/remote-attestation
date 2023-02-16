/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>
#include <sstream>
#include <thread>

#include "nv.h"

#include "Prover.hpp"
#include "Config.hpp"
#include "BoardRPI.hpp"
#include "CommandLine.hpp"
#include "Enum.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    CommandLine cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_PROVER);
    config.parseFile(cli.getPublisherConfig());

#ifdef SEEC_ENABLED
    Utils::readRsaKey(cli.getRsaPrivateKey(), KeyDistRSA::getPrivateKey());
    Utils::readRsaKey(cli.getRsaPublicKey(), KeyDistRSA::getPublicKey());
#endif

    cout << config.toString() << endl;

    BoardRPI *board = new BoardRPI();
    Prover prover(config, board);

    if (config.getTransport() == TRANSPORT_MQTT)
        prover.runMqtt();
    else
        prover.run();
}

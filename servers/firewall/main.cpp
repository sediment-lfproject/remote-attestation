/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>

#include "Config.hpp"
#include "Device.hpp"
#include "Firewall.hpp"
#include "BoardServer.hpp"
#include "CommandLine.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    CommandLine cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_FIREWALL);
    config.parseFile(cli.getSubscriberConfig());

    Board *board = new BoardServer();
    Firewall firewall(config, board, cli);
#ifdef SEEC_ENABLED
    Utils::readRsaKey(cli.getRsaPrivateKey(), KeyDistRSA::getPrivateKey());
    Utils::readRsaKey(cli.getRsaPublicKey(), KeyDistRSA::getPublicKey());
#endif
    firewall.run();
}

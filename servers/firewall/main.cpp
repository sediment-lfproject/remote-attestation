/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>

#include "Config.hpp"
#include "Device.hpp"
#include "Firewall.hpp"
#include "FirewallCL.hpp"
#include "BoardServer.hpp"
#include "CommandLine.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    FirewallCL cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_FIREWALL);
    config.parseFile(cli.getConfig());

    Board *board = new BoardServer();
    Firewall firewall(config, board, cli);

    firewall.run();
}

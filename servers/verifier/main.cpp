/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>

#include "Config.hpp"
#include "Device.hpp"
#include "Verifier.hpp"
#include "BoardServer.hpp"
#include "CommandLine.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    CommandLine cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_VERIFIER);
    config.parseFile(cli.getSubscriberConfig());

    //    Utils::readRsaKey(cli.getRsaPrivateKey(), KeyDistRSA::getPrivateKey());
    //    Utils::readRsaKey(cli.getRsaPublicKey(), KeyDistRSA::getPublicKey());

    Board *board = new BoardServer();
    Verifier verifier(config, board, cli);

    // control from the GUI or other components
    pthread_t control_thread;
    int ret = pthread_create(&control_thread, NULL, Verifier::serviceControl, &verifier);
    if (ret != 0) {
        printf("control: thread create failed\n");
        exit(1);
    }
    verifier.run();
}

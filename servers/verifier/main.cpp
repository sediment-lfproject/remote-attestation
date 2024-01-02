/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>

#include "Config.hpp"
#include "Device.hpp"
#include "Verifier.hpp"
#include "BoardServer.hpp"
#include "VerifierCL.hpp"
#include "Utils.hpp"

using namespace std;

int main(int argc, char **argv)
{
    VerifierCL cli;

    cli.parseCmdline(argc, argv);

    Config config(NV_VERIFIER);
    config.parseFile(cli.getConfig());

    Board *board = new BoardServer();
    Verifier verifier(config, board, cli);

    // control from the GUI or other components
    pthread_t control_thread;
    int ret = pthread_create(&control_thread, NULL, Verifier::serviceControl, &verifier);
    if (ret != 0) {
        printf("control: thread create failed\n");
        exit(1);
    }

    if (!cli.isNoGUI()) {
        pthread_t gui_thread;
        ret = pthread_create(&gui_thread, NULL, Verifier::guiServiceControl, &verifier);
        if (ret != 0) {
            printf("gui: thread create failed\n");
            exit(1);
        }
    }
    verifier.run();
}
